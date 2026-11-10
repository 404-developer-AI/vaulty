using System.Net;
using System.Text.RegularExpressions;
using Dapper;
using Npgsql;
using Vaulty.Integration.Tests.Database;

namespace Vaulty.Integration.Tests.Web;

/// <summary>
/// The rendered pages: a protected object whose latest snapshot is partial shows an amber chip everywhere it appears
/// (dashboard, tenant page, snapshot list), and its tenant and customer inherit that state instead of showing green.
/// </summary>
public sealed partial class StatusViewTests(WebAppFixture app) : IClassFixture<WebAppFixture>
{
    [PostgresFact]
    public async Task Partial_is_amber_and_never_green_in_every_view()
    {
        var client = await SignedInAdministratorAsync();
        await using var owner = new NpgsqlConnection(app.Database.Migrator);
        var org = await owner.ExecuteScalarAsync<Guid>("SELECT id FROM vaulty.organizations LIMIT 1");
        var (customer, tenant, healthy, partial) = (Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@customer, @org, 'C1', 'Contoso');
            INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name, consent_state, client_id)
                VALUES (@tenant, @org, @customer, @entra, 'Contoso tenant', 'granted', @client);
            INSERT INTO vaulty.protected_objects (id, organization_id, tenant_id, kind, sub_kind, source_id, display_name)
                VALUES (@healthy, @org, @tenant, 'mailbox', 'user', 'm1', 'Sales mailbox'), (@partial, @org, @tenant, 'mailbox', 'user', 'm2', 'Finance mailbox');
            INSERT INTO vaulty.snapshots (id, organization_id, tenant_id, protected_object_id, state, started_at, committed_at, item_counts, exceptions, manifest_root_hash, sequence)
                VALUES (@s1, @org, @tenant, @healthy, 'committed', now() - interval '1 hour', now() - interval '1 hour', '{"items": 120}', '[]', '\x00', 1),
                       (@s2, @org, @tenant, @partial, 'partial', now() - interval '1 hour', now() - interval '1 hour', '{"items": 97}',
                        '[{"error_code":"too_large"},{"error_code":"too_large"},{"error_code":"corrupt"}]', '\x00', 1);
            UPDATE vaulty.protected_objects SET last_snapshot_id = @s1 WHERE id = @healthy;
            UPDATE vaulty.protected_objects SET last_snapshot_id = @s2 WHERE id = @partial;
            """, new { org, customer, tenant, entra = Guid.NewGuid(), client = Guid.NewGuid(), healthy, partial, s1 = Guid.NewGuid(), s2 = Guid.NewGuid() });

        var dashboard = await PageAsync(client, "/");
        Assert.Equal("partial", ChipAfter(dashboard, "Finance mailbox"));
        Assert.Equal("protected", ChipAfter(dashboard, "Sales mailbox"));
        Assert.Equal("partial", ChipBefore(dashboard, "Contoso tenant"));
        Assert.Equal("partial", ChipBefore(dashboard, "C1 · Contoso"));
        Assert.Contains("Partial: 3 missing", dashboard, StringComparison.Ordinal);
        Assert.Contains("1 protected, 1 partial", dashboard, StringComparison.Ordinal);

        var tenantPage = await PageAsync(client, $"/tenants/{tenant}");
        Assert.Equal("partial", ChipAfter(tenantPage, "Finance mailbox"));
        Assert.Equal("protected", ChipAfter(tenantPage, "Sales mailbox"));
        Assert.Equal("partial", ChipAfter(tenantPage, "<td>Status</td>"));

        var snapshots = await PageAsync(client, $"/objects/{partial}");
        Assert.Contains("vy-status partial", snapshots, StringComparison.Ordinal);
        Assert.DoesNotContain("vy-status succeeded", snapshots, StringComparison.Ordinal);
        Assert.DoesNotContain("vy-status protected", snapshots, StringComparison.Ordinal);
    }

    private static async Task<string> PageAsync(HttpClient client, string path)
    {
        var response = await client.GetAsync(path);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{path}: {(int)response.StatusCode} {body[..Math.Min(body.Length, 3000)]}");
        return WebUtility.HtmlDecode(body);
    }

    /// <summary>The class of the first status chip after the text, within the same table row or block.</summary>
    private static string ChipAfter(string html, string text)
    {
        var at = html.IndexOf(text, StringComparison.Ordinal);
        Assert.True(at >= 0, $"'{text}' is not on the page");
        var rest = html[at..];
        var end = rest.IndexOf("</tr>", StringComparison.Ordinal);
        var match = Chip().Match(end > 0 ? rest[..end] : rest);
        Assert.True(match.Success, $"no status chip after '{text}'");
        return match.Groups[1].Value;
    }

    /// <summary>The class of the last status chip before the text (row headers put the chip first).</summary>
    private static string ChipBefore(string html, string text)
    {
        var at = html.IndexOf(text, StringComparison.Ordinal);
        Assert.True(at >= 0, $"'{text}' is not on the page");
        var matches = Chip().Matches(html[..at]);
        Assert.True(matches.Count > 0, $"no status chip before '{text}'");
        return matches[^1].Groups[1].Value;
    }

    [GeneratedRegex("class=\"vy-status (\\w+)\"")]
    private static partial Regex Chip();

    private async Task<HttpClient> SignedInAdministratorAsync()
    {
        var client = app.Client();
        var token = await app.IssueSetupTokenAsync();
        var setupPage = await (await client.GetAsync($"/setup?token={token}")).Content.ReadAsStringAsync();
        await client.PostFormAsync("/setup", Html.FormTokenOf(setupPage), ("token", token), ("organization", "Contoso IT"), ("displayName", "Alex Admin"),
            ("email", "admin@contoso.example"), ("password", "correct horse battery"), ("confirm", "correct horse battery"));
        var mfaPage = await (await client.GetAsync("/account/mfa-setup")).Content.ReadAsStringAsync();
        var enroll = await client.PostFormAsync("/account/mfa/totp", Html.FormTokenOf(mfaPage), ("code", Totp.Code(Html.AuthenticatorKeyOf(mfaPage))));
        Assert.Equal("/account/recovery-codes", enroll.Headers.Location?.OriginalString);
        await client.GetAsync("/account/recovery-codes");
        return client;
    }
}
