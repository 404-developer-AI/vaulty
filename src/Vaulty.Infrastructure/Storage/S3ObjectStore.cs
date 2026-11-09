using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Vaulty.Core.Abstractions;
using ByteRange = Vaulty.Core.Abstractions.ByteRange;

namespace Vaulty.Infrastructure.Storage;

/// <summary>Connection settings of one S3 identity on one bucket. The secret key comes from the secrets store.</summary>
public sealed record S3StoreSettings(string ServiceUrl, string Region, string Bucket, string AccessKeyId)
{
    /// <summary>Attempts per operation when the provider asks to slow down (503, 429, 500).</summary>
    public int MaxAttempts { get; init; } = 8;

    /// <summary>Upper bound of one wait, also when Retry-After asks for longer.</summary>
    public TimeSpan MaxBackoff { get; init; } = TimeSpan.FromMinutes(2);
}

/// <summary>
/// <see cref="IObjectStore"/> on an S3-compatible provider with Object Lock (Wasabi). Writes carry the Object Lock
/// retention in compliance mode and Content-MD5, and the returned ETag is compared with the MD5 of the bytes. The SDK's own
/// retries are off: this class retries throttling responses itself and honours Retry-After exactly.
/// </summary>
public sealed class S3ObjectStore : IObjectStore, IDisposable
{
    private readonly AmazonS3Client _client;
    private readonly S3StoreSettings _settings;
    private readonly TimeProvider _clock;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public S3ObjectStore(S3StoreSettings settings, Secret secretAccessKey, TimeProvider? clock = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(secretAccessKey);
        _settings = settings;
        _clock = clock ?? TimeProvider.System;
        _delay = delay ?? ((d, ct) => Task.Delay(d, _clock, ct));
        var config = new AmazonS3Config
        {
            ServiceURL = settings.ServiceUrl,
            AuthenticationRegion = settings.Region,
            ForcePathStyle = true,
            MaxErrorRetry = 0,
            RequestChecksumCalculation = RequestChecksumCalculation.WHEN_REQUIRED,
            ResponseChecksumValidation = ResponseChecksumValidation.WHEN_REQUIRED,
            HttpClientFactory = new RetryAfterHttpClientFactory(),
            Timeout = TimeSpan.FromMinutes(10),
        };
        _client = new AmazonS3Client(new BasicAWSCredentials(settings.AccessKeyId, secretAccessKey.RevealString()), config);
    }

    /// <summary>Throttling responses seen, for the connection test and telemetry.</summary>
    public int ThrottledResponses { get; private set; }

    public Task<ObjectInfo> PutAsync(string key, Stream content, ObjectPutOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(options);
        return RetryAsync("put", key, async () =>
        {
            if (options.FailIfExists && await HeadAsync(key, cancellationToken).ConfigureAwait(false) is not null)
            {
                throw new ObjectAlreadyExistsException(key);
            }

            // Buffer unknown-length or non-seekable streams so Content-MD5 can be computed and the request retried.
            byte[] bytes;
            if (content is MemoryStream ms && ms.TryGetBuffer(out var segment) && ms.Position == 0)
            {
                bytes = segment.Count == segment.Array!.Length ? segment.Array : segment.ToArray();
            }
            else
            {
                if (content.CanSeek) content.Position = 0;
                using var copy = new MemoryStream();
                await content.CopyToAsync(copy, cancellationToken).ConfigureAwait(false);
                bytes = copy.ToArray();
            }
            if (options.ExpectedSha256 is { } sha && !SHA256.HashData(bytes).AsSpan().SequenceEqual(sha))
            {
                throw new ObjectIntegrityException(key, "SHA-256 of the bytes to upload does not match");
            }
            var md5 = MD5.HashData(bytes);
            var request = new PutObjectRequest
            {
                BucketName = _settings.Bucket,
                Key = key,
                InputStream = new MemoryStream(bytes, writable: false),
                MD5Digest = Convert.ToBase64String(md5),
                UseChunkEncoding = false,
                AutoCloseStream = true,
            };
            if (options.LockUntil is { } lockUntil)
            {
                request.ObjectLockMode = ObjectLockMode.Compliance;
                request.ObjectLockRetainUntilDate = lockUntil.UtcDateTime;
            }
            var response = await _client.PutObjectAsync(request, cancellationToken).ConfigureAwait(false);
            var etag = response.ETag?.Trim('"');
            if (!string.Equals(etag, Convert.ToHexStringLower(md5), StringComparison.OrdinalIgnoreCase))
            {
                throw new ObjectIntegrityException(key, "the ETag returned by the provider does not match the MD5 of the bytes");
            }
            return new ObjectInfo(key, bytes.Length, etag, options.LockUntil, _clock.GetUtcNow());
        }, cancellationToken);
    }

    public Task<Stream> GetAsync(string key, ByteRange? range = null, CancellationToken cancellationToken = default) =>
        RetryAsync("get", key, async () =>
        {
            var request = new GetObjectRequest { BucketName = _settings.Bucket, Key = key };
            if (range is { } r) request.ByteRange = new Amazon.S3.Model.ByteRange(r.Offset, r.LastByte);
            var response = await _client.GetObjectAsync(request, cancellationToken).ConfigureAwait(false);
            return (Stream)new ResponseStream(response);
        }, cancellationToken);

    public Task<ObjectInfo?> HeadAsync(string key, CancellationToken cancellationToken = default) =>
        RetryAsync<ObjectInfo?>("head", key, async () =>
        {
            try
            {
                var response = await _client.GetObjectMetadataAsync(_settings.Bucket, key, cancellationToken).ConfigureAwait(false);
                DateTimeOffset? lockUntil = response.ObjectLockRetainUntilDate is { } d && d != default
                    ? new DateTimeOffset(DateTime.SpecifyKind(d, DateTimeKind.Utc))
                    : null;
                return new ObjectInfo(key, response.ContentLength, response.ETag?.Trim('"'), lockUntil,
                    new DateTimeOffset(DateTime.SpecifyKind(response.LastModified ?? DateTime.UtcNow, DateTimeKind.Utc)));
            }
            catch (AmazonS3Exception ex) when (ex.StatusCode == HttpStatusCode.NotFound)
            {
                return null;
            }
        }, cancellationToken);

    public async IAsyncEnumerable<ObjectInfo> ListAsync(string prefix, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        string? token = null;
        do
        {
            var page = await RetryAsync("list", prefix, () => _client.ListObjectsV2Async(new ListObjectsV2Request
            {
                BucketName = _settings.Bucket,
                Prefix = prefix,
                ContinuationToken = token,
            }, cancellationToken), cancellationToken).ConfigureAwait(false);
            foreach (var o in page.S3Objects ?? [])
            {
                yield return new ObjectInfo(o.Key, o.Size ?? 0, o.ETag?.Trim('"'), null,
                    new DateTimeOffset(DateTime.SpecifyKind(o.LastModified ?? DateTime.UtcNow, DateTimeKind.Utc)));
            }
            token = page.IsTruncated == true ? page.NextContinuationToken : null;
        }
        while (token is not null);
    }

    /// <summary>
    /// Deletes every version of the key. With versioning on, a plain delete only adds a delete marker; the garbage collector
    /// must remove the versions themselves, which the provider refuses while their lock holds.
    /// </summary>
    public Task DeleteAsync(string key, CancellationToken cancellationToken = default) =>
        RetryAsync("delete", key, async () =>
        {
            var versions = await _client.ListVersionsAsync(new ListVersionsRequest { BucketName = _settings.Bucket, Prefix = key },
                cancellationToken).ConfigureAwait(false);
            foreach (var version in (versions.Versions ?? []).Where(v => v.Key == key))
            {
                try
                {
                    await _client.DeleteObjectAsync(new DeleteObjectRequest
                    {
                        BucketName = _settings.Bucket,
                        Key = key,
                        VersionId = version.VersionId,
                    }, cancellationToken).ConfigureAwait(false);
                }
                catch (AmazonS3Exception ex) when (ex.StatusCode == HttpStatusCode.Forbidden)
                {
                    var head = await HeadAsync(key, cancellationToken).ConfigureAwait(false);
                    if (head?.LockUntil is { } until && until > _clock.GetUtcNow()) throw new ObjectLockedException(key, until);
                    throw new ObjectStoreAccessDeniedException(key, "delete", ex);
                }
            }
            return true;
        }, cancellationToken);

    private async Task<T> RetryAsync<T>(string operation, string key, Func<Task<T>> action, CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            var holder = new RetryAfterHolder();
            RetryAfterHolder.Current.Value = holder;
            try
            {
                return await action().ConfigureAwait(false);
            }
            catch (AmazonS3Exception ex) when (ex.StatusCode == HttpStatusCode.NotFound && operation == "get")
            {
                throw new ObjectNotFoundException(key);
            }
            catch (AmazonS3Exception ex) when (ex.StatusCode == HttpStatusCode.Forbidden && operation != "delete")
            {
                throw new ObjectStoreAccessDeniedException(key, operation, ex);
            }
            catch (AmazonServiceException ex) when (IsThrottle(ex.StatusCode) && attempt < _settings.MaxAttempts)
            {
                ThrottledResponses++;
                await _delay(Backoff(attempt, holder.RetryAfter), cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                RetryAfterHolder.Current.Value = null;
            }
        }
    }

    /// <summary>Retry-After when the provider sent one (capped), otherwise exponential backoff with full jitter.</summary>
    internal TimeSpan Backoff(int attempt, TimeSpan? retryAfter)
    {
        if (retryAfter is { } wait) return wait > _settings.MaxBackoff ? _settings.MaxBackoff : wait;
        var ceiling = Math.Min(_settings.MaxBackoff.TotalMilliseconds, 200 * Math.Pow(2, attempt));
        return TimeSpan.FromMilliseconds(Random.Shared.NextDouble() * ceiling);
    }

    private static bool IsThrottle(HttpStatusCode code) =>
        code is HttpStatusCode.ServiceUnavailable or HttpStatusCode.TooManyRequests or HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway or HttpStatusCode.GatewayTimeout;

    public void Dispose() => _client.Dispose();

    /// <summary>Keeps the response alive while its body is read.</summary>
    private sealed class ResponseStream(GetObjectResponse response) : Stream
    {
        private readonly Stream _inner = response.ResponseStream;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => response.ContentLength;
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _inner.ReadAsync(buffer, cancellationToken);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            _inner.ReadAsync(buffer, offset, count, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
                response.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}

/// <summary>Carries the Retry-After of the last throttling response from the HTTP handler to the retry loop.</summary>
internal sealed class RetryAfterHolder
{
    public static readonly AsyncLocal<RetryAfterHolder?> Current = new();
    public TimeSpan? RetryAfter { get; set; }
}

internal sealed class RetryAfterHandler : DelegatingHandler
{
    public RetryAfterHandler() : base(new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) })
    {
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (RetryAfterHolder.Current.Value is { } holder && response.Headers.RetryAfter is { } retryAfter)
        {
            holder.RetryAfter = retryAfter.Delta ?? (retryAfter.Date is { } date ? date - DateTimeOffset.UtcNow : null);
            if (holder.RetryAfter < TimeSpan.Zero) holder.RetryAfter = TimeSpan.Zero;
        }
        return response;
    }
}

internal sealed class RetryAfterHttpClientFactory : HttpClientFactory
{
    public override HttpClient CreateHttpClient(IClientConfig clientConfig) =>
        new(new RetryAfterHandler()) { Timeout = Timeout.InfiniteTimeSpan };
}
