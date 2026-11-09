using System.Text.Json.Serialization;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Vaulty.Core.Abstractions;
using Vaulty.Infrastructure.Storage;

namespace Vaulty.Infrastructure.Platform;

/// <summary>SMTP settings without the password (that is the secret "smtp.password").</summary>
public sealed record SmtpSettings(
    [property: JsonPropertyName("host")] string Host,
    [property: JsonPropertyName("port")] int Port,
    [property: JsonPropertyName("security")] string Security,
    [property: JsonPropertyName("user_name")] string? UserName,
    [property: JsonPropertyName("from_address")] string FromAddress,
    [property: JsonPropertyName("from_name")] string FromName)
{
    public const string SettingKey = "smtp";
    public const string PasswordSecret = "smtp.password";
}

/// <summary>How the web interface shows times, and the defaults for new webhooks.</summary>
public sealed record DisplaySettings(
    [property: JsonPropertyName("time_zone")] string TimeZone,
    [property: JsonPropertyName("webhook_timeout_seconds")] int WebhookTimeoutSeconds,
    [property: JsonPropertyName("webhook_events")] IReadOnlyList<string> WebhookEvents)
{
    public const string SettingKey = "display";

    public static DisplaySettings Default { get; } = new("Europe/Brussels", 10,
        ["backup.failed", "backup.partial", "tenant.consent_lost", "verification.failed", "restore.completed"]);
}

public sealed record MailMessage(string To, string Subject, string Text, string? Html);

public interface IMailSender
{
    Task SendAsync(MailMessage message, CancellationToken cancellationToken = default);
}

/// <summary>Sends mail with MailKit using the SMTP settings and the password from the secrets store. Plain text is always included.</summary>
public sealed class SmtpMailSender(PlatformSettings settings, ISecretStore secrets) : IMailSender
{
    public async Task SendAsync(MailMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        var smtp = await settings.GetAsync<SmtpSettings>(SmtpSettings.SettingKey, cancellationToken).ConfigureAwait(false)
                   ?? throw new InvalidOperationException("SMTP is not configured.");
        var mime = new MimeMessage();
        mime.From.Add(new MailboxAddress(smtp.FromName, smtp.FromAddress));
        mime.To.Add(MailboxAddress.Parse(message.To));
        mime.Subject = message.Subject;
        mime.Body = new BodyBuilder { TextBody = message.Text, HtmlBody = message.Html }.ToMessageBody();

        using var client = new SmtpClient();
        var security = smtp.Security switch
        {
            "ssl" => SecureSocketOptions.SslOnConnect,
            "none" => SecureSocketOptions.None,
            _ => SecureSocketOptions.StartTls,
        };
        await client.ConnectAsync(smtp.Host, smtp.Port, security, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(smtp.UserName))
        {
            using var password = await secrets.GetAsync(SmtpSettings.PasswordSecret, cancellationToken).ConfigureAwait(false);
            await client.AuthenticateAsync(smtp.UserName, password?.RevealString() ?? "", cancellationToken).ConfigureAwait(false);
        }
        await client.SendAsync(mime, cancellationToken).ConfigureAwait(false);
        await client.DisconnectAsync(true, cancellationToken).ConfigureAwait(false);
    }
}
