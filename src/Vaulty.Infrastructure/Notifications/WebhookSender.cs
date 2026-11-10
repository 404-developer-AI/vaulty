using System.Net;
using System.Net.Sockets;
using System.Text;
using Vaulty.Core.Notifications;

namespace Vaulty.Infrastructure.Notifications;

public sealed record WebhookOptions
{
    /// <summary>Only for tests and closed networks: allows http and private, loopback and link-local addresses.</summary>
    public bool AllowPrivateTargets { get; init; }
}

public sealed record WebhookResult(bool Delivered, int? Status, string? Error);

public interface IWebhookSender
{
    Task<WebhookResult> SendAsync(Uri url, string eventKind, Guid deliveryId, byte[] body, byte[] secret, TimeSpan timeout, CancellationToken cancellationToken = default);
}

/// <summary>
/// Posts a signed webhook. Only https, and the connection itself is checked: an address in a private, loopback, link-local
/// or multicast range is refused at connect time, so a host name that resolves (or re-resolves) to an internal address
/// cannot be used to reach the platform's own network. Redirects are not followed.
/// </summary>
public sealed class WebhookSender : IWebhookSender, IDisposable
{
    private readonly HttpClient _client;
    private readonly WebhookOptions _options;
    private readonly TimeProvider _clock;

    public WebhookSender(TimeProvider clock, WebhookOptions? options = null)
    {
        _clock = clock;
        _options = options ?? new WebhookOptions();
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectCallback = ConnectAsync,
        };
        _client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        _client.DefaultRequestHeaders.UserAgent.ParseAdd("Vaulty-Webhooks/1");
    }

    public static string? Validate(string url, bool allowPrivate = false)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return "Enter a full URL, for example https://hooks.example.com/vaulty.";
        if (uri.Scheme != Uri.UriSchemeHttps && !(allowPrivate && uri.Scheme == Uri.UriSchemeHttp)) return "Webhooks are sent over https only.";
        if (!string.IsNullOrEmpty(uri.UserInfo)) return "Put credentials in the receiver, not in the URL; Vaulty signs every delivery.";
        if (!allowPrivate && IPAddress.TryParse(uri.Host, out var ip) && IsInternal(ip)) return "Webhooks cannot be sent to a private or local address.";
        return null;
    }

    public async Task<WebhookResult> SendAsync(Uri url, string eventKind, Guid deliveryId, byte[] body, byte[] secret, TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (Validate(url.ToString(), _options.AllowPrivateTargets) is { } problem) return new WebhookResult(false, null, problem);
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new ByteArrayContent(body) };
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        request.Headers.Add(WebhookSignature.EventHeader, eventKind);
        request.Headers.Add(WebhookSignature.DeliveryHeader, deliveryId.ToString());
        request.Headers.Add(WebhookSignature.SignatureHeader, WebhookSignature.Sign(secret, _clock.GetUtcNow().ToUnixTimeSeconds(), body));
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutSource.Token).ConfigureAwait(false);
            var status = (int)response.StatusCode;
            return status is >= 200 and < 300
                ? new WebhookResult(true, status, null)
                : new WebhookResult(false, status, $"The receiver answered {status} {response.ReasonPhrase}.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new WebhookResult(false, null, $"No answer within {timeout.TotalSeconds:F0} seconds.");
        }
        catch (HttpRequestException ex)
        {
            return new WebhookResult(false, null, ex.InnerException is WebhookTargetException target ? target.Message : $"Connection failed: {ex.Message}");
        }
    }

    private async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
        if (!_options.AllowPrivateTargets && addresses.Any(IsInternal))
        {
            throw new WebhookTargetException("Webhooks cannot be sent to a private or local address.");
        }
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(addresses, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);
            if (!_options.AllowPrivateTargets && socket.RemoteEndPoint is IPEndPoint remote && IsInternal(remote.Address))
            {
                throw new WebhookTargetException("Webhooks cannot be sent to a private or local address.");
            }
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public static bool IsInternal(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return true;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast || address.IsIPv6UniqueLocal;
        }
        var b = address.GetAddressBytes();
        return b[0] switch
        {
            0 or 10 or 127 => true,
            100 => b[1] >= 64 && b[1] <= 127,           // carrier-grade NAT
            169 => b[1] == 254,                          // link-local, cloud metadata
            172 => b[1] >= 16 && b[1] <= 31,
            192 => (b[1] == 168) || (b[1] == 0 && b[2] == 0),
            198 => b[1] == 18 || b[1] == 19,             // benchmarking
            >= 224 => true,                              // multicast and reserved
            _ => false,
        };
    }

    public void Dispose() => _client.Dispose();
}

public sealed class WebhookTargetException(string message) : IOException(message);

/// <summary>The JSON body of a delivery: stable field names, no customer content beyond names and counts.</summary>
public static class WebhookBody
{
    public static byte[] Create(Guid eventId, string kind, DateTimeOffset createdAt, Guid? tenantId, Guid? objectId, string payloadJson)
    {
        var json = $"{{\"id\":\"{eventId}\",\"type\":{System.Text.Json.JsonSerializer.Serialize(kind)},\"created_at\":\"{createdAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture)}\","
                   + $"\"tenant_id\":{Id(tenantId)},\"protected_object_id\":{Id(objectId)},\"data\":{payloadJson}}}";
        return Encoding.UTF8.GetBytes(json);
    }

    private static string Id(Guid? id) => id is { } v ? $"\"{v}\"" : "null";
}
