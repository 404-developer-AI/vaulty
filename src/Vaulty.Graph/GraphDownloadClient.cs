using System.Net;
using System.Net.Http.Headers;
using Vaulty.Graph.Http;

namespace Vaulty.Graph;

/// <summary>
/// Talks to pre-authenticated URLs: downloads (@microsoft.graph.downloadUrl), upload sessions and mailbox import sessions.
/// It has its own HttpClient without the authentication handler, so no Graph token ever reaches these hosts, and it only
/// talks HTTPS to Microsoft content domains.
/// </summary>
public sealed class GraphDownloadClient
{
    /// <summary>Host suffixes of Microsoft 365 file content.</summary>
    public static readonly IReadOnlyList<string> AllowedHostSuffixes = [".sharepoint.com", ".svc.ms", "outlook.office365.com"];

    private readonly HttpClient _http;
    private readonly IReadOnlyList<string> _allowed;
    private readonly bool _allowHttp;

    public GraphDownloadClient(GraphThrottle throttle, HttpMessageHandler? network = null, IReadOnlyList<string>? allowedHostSuffixes = null,
        bool allowHttpForTests = false)
    {
        var throttling = new ThrottlingHandler(throttle)
        {
            InnerHandler = new DecorationHandler { InnerHandler = network ?? new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) } },
        };
        _http = new HttpClient(new TelemetryHandler { InnerHandler = throttling }) { Timeout = Timeout.InfiniteTimeSpan };
        _allowed = allowedHostSuffixes ?? AllowedHostSuffixes;
        _allowHttp = allowHttpForTests;
    }

    public bool IsAllowed(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (url.Scheme != Uri.UriSchemeHttps && !(_allowHttp && url.Scheme == Uri.UriSchemeHttp)) return false;
        return _allowed.Any(suffix => url.Host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) || url.Host.Equals(suffix.TrimStart('.'), StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Opens the content from <paramref name="offset"/> (Range request for resuming). The caller streams and disposes.</summary>
    public async Task<Stream> OpenAsync(GraphRequestContext context, Uri url, long offset = 0, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (!IsAllowed(url)) throw new GraphException(HttpStatusCode.BadRequest, "downloadHostNotAllowed", $"Download host {url.Host} is not allowed.", null);
        using var request = new HttpRequestMessage(HttpMethod.Get, url).WithContext(context);
        if (offset > 0) request.Headers.Range = new RangeHeaderValue(offset, null);
        var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (offset > 0 && response.StatusCode == HttpStatusCode.OK)
        {
            response.Dispose();
            throw new GraphException(HttpStatusCode.RequestedRangeNotSatisfiable, "rangeIgnored", "The server ignored the Range request.", null);
        }
        if (!response.IsSuccessStatusCode)
        {
            var status = response.StatusCode;
            response.Dispose();
            throw new GraphException(status, "downloadFailed", $"Download returned {(int)status}.", null);
        }
        return new OwningStream(await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false), response);
    }

    /// <summary>
    /// Sends a request to a pre-authenticated URL (an upload session or import session) and returns the response, also when
    /// it is not a success; the caller reads and disposes it. Throttling is handled like every Graph call.
    /// </summary>
    public async Task<HttpResponseMessage> SendAsync(GraphRequestContext context, HttpMethod method, Uri url, HttpContent? content,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (!IsAllowed(url)) throw new GraphException(HttpStatusCode.BadRequest, "hostNotAllowed", $"Host {url.Host} is not allowed.", null);
        using var request = new HttpRequestMessage(method, url) { Content = content }.WithContext(context);
        return await _http.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
    }

    private sealed class OwningStream(Stream inner, IDisposable owner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            inner.ReadAsync(buffer, offset, count, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
                owner.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
