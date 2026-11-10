using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Vaulty.Core.Abstractions;
using Vaulty.Infrastructure.Storage;

namespace Vaulty.Recover;

/// <summary>The command line of vaulty-recover.</summary>
public static class RecoverCommand
{
    public const string SecretKeyVariable = "VAULTY_RECOVER_SECRET_ACCESS_KEY";
    public const string MasterKeyVariable = "VAULTY_RECOVER_MASTER_KEY";

    public const string Usage = """
        vaulty-recover: rebuild a tenant from object storage alone, without the Vaulty database.

        Usage:
          vaulty-recover --tenant <id> --out <empty directory> --master-key-file <file> (--store-dir <dir> | S3 options) [options]

        Object storage (read access is enough):
          --store-dir <dir>          a local copy of the backup bucket (for example made with a sync tool)
          --endpoint <url>           S3 endpoint, for example https://s3.eu-central-2.example.com
          --region <region>          S3 region
          --bucket <name>            the backup bucket
          --access-key-id <id>       access key id; the secret key is read from VAULTY_RECOVER_SECRET_ACCESS_KEY

        Keys:
          --master-key-file <file>   the recovery copy of the host master key (base64), or set VAULTY_RECOVER_MASTER_KEY
          --master-key-version <n>   the master key version (default: the newest in the tenant's key files)

        Selection:
          --object <id>              only this protected object (repeatable)
          --snapshot <id>            this snapshot instead of the newest (with one --object)
          --include-versions         also write the older file versions a snapshot keeps

        Every chunk is authenticated and every item's content hash checked. The output has one folder per protected object and
        snapshot with messages as EML, events as ICS, contacts as VCF and files as they are, a manifest.json per snapshot and
        recovery-report.json for the whole run. Exit code 0: everything written; 2: some items failed (see the report); 1: error.
        """;

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error, Func<string, string?> environment,
        Func<RecoverOptions, IObjectStore>? storeFactory = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(environment);
        RecoverOptions options;
        try
        {
            options = RecoverOptions.Parse(args);
        }
        catch (RecoveryException ex)
        {
            await error.WriteLineAsync(ex.Message).ConfigureAwait(false);
            await error.WriteLineAsync().ConfigureAwait(false);
            await error.WriteLineAsync(Usage).ConfigureAwait(false);
            return 1;
        }
        if (options.Help)
        {
            await output.WriteLineAsync(Usage).ConfigureAwait(false);
            return 0;
        }

        byte[]? masterKey = null;
        try
        {
            masterKey = ReadMasterKey(options, environment);
            var store = storeFactory?.Invoke(options) ?? CreateStore(options, environment);
            try
            {
                var report = await TenantRecovery.RunAsync(store, masterKey, new RecoveryRequest(options.TenantId!.Value, options.OutputDirectory!)
                {
                    Objects = options.Objects,
                    Snapshot = options.Snapshot,
                    IncludeVersions = options.IncludeVersions,
                    MasterKeyVersion = options.MasterKeyVersion,
                }, output, cancellationToken).ConfigureAwait(false);
                await output.WriteLineAsync($"Done: {report.Objects.Count} protected objects, {report.Items} items, {report.Failed} failed. "
                                            + $"Report: {Path.Combine(options.OutputDirectory!, "recovery-report.json")}").ConfigureAwait(false);
                return report.Failed > 0 ? 2 : 0;
            }
            finally
            {
                (store as IDisposable)?.Dispose();
            }
        }
        catch (RecoveryException ex)
        {
            await error.WriteLineAsync(ex.Message).ConfigureAwait(false);
            return 1;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or CryptographicException or FormatException
                                   or Amazon.S3.AmazonS3Exception or Amazon.Runtime.AmazonServiceException or HttpRequestException)
        {
            await error.WriteLineAsync($"Recovery stopped: {ex.Message}").ConfigureAwait(false);
            return 1;
        }
        finally
        {
            if (masterKey is not null) CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    private static byte[] ReadMasterKey(RecoverOptions options, Func<string, string?> environment)
    {
        var text = options.MasterKeyFile is { } file ? File.ReadAllText(file) : environment(MasterKeyVariable);
        if (string.IsNullOrWhiteSpace(text)) throw new RecoveryException($"Give the master key with --master-key-file or {MasterKeyVariable}.");
        byte[] key;
        try
        {
            key = Convert.FromBase64String(text.Trim());
        }
        catch (FormatException)
        {
            throw new RecoveryException("The master key is not valid base64. Use the recovery copy from the installation report.");
        }
        if (key.Length != 32)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new RecoveryException($"The master key must be 32 bytes, this one has {key.Length}.");
        }
        return key;
    }

    private static IObjectStore CreateStore(RecoverOptions options, Func<string, string?> environment)
    {
        if (options.StoreDirectory is { } directory) return new DirectoryObjectStore(directory);
        var secret = environment(SecretKeyVariable);
        if (string.IsNullOrEmpty(secret)) throw new RecoveryException($"Set {SecretKeyVariable} to the secret access key.");
        using var secretKey = new Secret("recover.secret-access-key", 1, System.Text.Encoding.UTF8.GetBytes(secret));
        return new S3ObjectStore(new S3StoreSettings(options.Endpoint!, options.Region!, options.Bucket!, options.AccessKeyId!), secretKey);
    }
}

public sealed class RecoverOptions
{
    public Guid? TenantId { get; private set; }
    public string? OutputDirectory { get; private set; }
    public string? StoreDirectory { get; private set; }
    public string? Endpoint { get; private set; }
    public string? Region { get; private set; }
    public string? Bucket { get; private set; }
    public string? AccessKeyId { get; private set; }
    public string? MasterKeyFile { get; private set; }
    public int? MasterKeyVersion { get; private set; }
    public List<Guid> Objects { get; } = [];
    public Guid? Snapshot { get; private set; }
    public bool IncludeVersions { get; private set; }
    public bool Help { get; private set; }

    public static RecoverOptions Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var o = new RecoverOptions();
        for (var i = 0; i < args.Count; i++)
        {
            string Value() => i + 1 < args.Count ? args[++i] : throw new RecoveryException($"{args[i]} needs a value.");
            Guid Id(string what) => Guid.TryParse(Value(), out var g) ? g : throw new RecoveryException($"{what} is not a valid id.");
            switch (args[i])
            {
                case "--help" or "-h": o.Help = true; break;
                case "--tenant": o.TenantId = Id("--tenant"); break;
                case "--out": o.OutputDirectory = Value(); break;
                case "--store-dir": o.StoreDirectory = Value(); break;
                case "--endpoint": o.Endpoint = Value(); break;
                case "--region": o.Region = Value(); break;
                case "--bucket": o.Bucket = Value(); break;
                case "--access-key-id": o.AccessKeyId = Value(); break;
                case "--master-key-file": o.MasterKeyFile = Value(); break;
                case "--master-key-version":
                    o.MasterKeyVersion = int.TryParse(Value(), out var v) && v > 0 ? v : throw new RecoveryException("--master-key-version must be a positive number.");
                    break;
                case "--object": o.Objects.Add(Id("--object")); break;
                case "--snapshot": o.Snapshot = Id("--snapshot"); break;
                case "--include-versions": o.IncludeVersions = true; break;
                default: throw new RecoveryException($"Unknown option {args[i]}.");
            }
        }
        if (o.Help) return o;
        if (o.TenantId is null) throw new RecoveryException("--tenant is required.");
        if (string.IsNullOrEmpty(o.OutputDirectory)) throw new RecoveryException("--out is required.");
        var s3 = o.Endpoint is not null || o.Bucket is not null || o.AccessKeyId is not null || o.Region is not null;
        if (o.StoreDirectory is not null && s3) throw new RecoveryException("Use either --store-dir or the S3 options, not both.");
        if (o.StoreDirectory is null && (o.Endpoint is null || o.Bucket is null || o.AccessKeyId is null || o.Region is null))
        {
            throw new RecoveryException("Give --store-dir, or all of --endpoint, --region, --bucket and --access-key-id.");
        }
        return o;
    }
}

/// <summary>A read-only object store on a local copy of a bucket: object keys are paths below the directory.</summary>
public sealed class DirectoryObjectStore(string root) : IObjectStore
{
    private readonly string _root = Path.GetFullPath(root);

    public Task<ObjectInfo> PutAsync(string key, Stream content, ObjectPutOptions options, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The Recover CLI never writes to object storage.");

    public Task DeleteAsync(string key, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The Recover CLI never deletes from object storage.");

    public Task<Stream> GetAsync(string key, ByteRange? range = null, CancellationToken cancellationToken = default)
    {
        var path = PathOf(key);
        if (!File.Exists(path)) throw new ObjectNotFoundException(key);
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        if (range is not { } r) return Task.FromResult<Stream>(stream);
        stream.Seek(r.Offset, SeekOrigin.Begin);
        return Task.FromResult<Stream>(new BoundedStream(stream, r.Length));
    }

    public Task<ObjectInfo?> HeadAsync(string key, CancellationToken cancellationToken = default)
    {
        var info = new FileInfo(PathOf(key));
        return Task.FromResult(info.Exists ? new ObjectInfo(key, info.Length, null, null, info.LastWriteTimeUtc) : null);
    }

    public async IAsyncEnumerable<ObjectInfo> ListAsync(string prefix, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(prefix);
        if (!Directory.Exists(_root)) yield break;
        var keys = Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(_root, f).Replace(Path.DirectorySeparatorChar, '/'))
            .Where(k => k.StartsWith(prefix, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var info = new FileInfo(PathOf(key));
            yield return new ObjectInfo(key, info.Length, null, null, info.LastWriteTimeUtc);
        }
        await Task.CompletedTask.ConfigureAwait(false);
    }

    private string PathOf(string key)
    {
        var full = Path.GetFullPath(Path.Combine(_root, key.Replace('/', Path.DirectorySeparatorChar)));
        return full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal) ? full : throw new ObjectNotFoundException(key);
    }

    private sealed class BoundedStream(Stream inner, long size) : Stream
    {
        private readonly long _size = size;
        private long _left = size;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _size;
        public override long Position { get => _size - _left; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (_left <= 0) return 0;
            var n = inner.Read(buffer[..(int)Math.Min(buffer.Length, _left)]);
            _left -= n;
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_left <= 0) return 0;
            var n = await inner.ReadAsync(buffer[..(int)Math.Min(buffer.Length, _left)], cancellationToken).ConfigureAwait(false);
            _left -= n;
            return n;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
