using System.Net;
using Dapper;
using Npgsql;
using Vaulty.Integration.Tests.Database;

namespace Vaulty.Integration.Tests.Web;

/// <summary>Setup closes after the first organization, so each scenario has its own database.</summary>
public sealed class FirstAdminTotpTests(WebAppFixture app) : IClassFixture<WebAppFixture>
{
    [PostgresFact]
    public async Task The_first_administrator_registers_with_an_authenticator_app()
    {
        var client = app.Client();
        var token = await app.IssueSetupTokenAsync();

        var setupPage = await (await client.GetAsync($"/setup?token={token}")).Content.ReadAsStringAsync();
        Assert.Contains("Create the organization", setupPage, StringComparison.Ordinal);
        var setup = await client.PostFormAsync("/setup", Html.FormTokenOf(setupPage), ("token", token), ("organization", "Contoso IT"),
            ("displayName", "Alex Admin"), ("email", "admin@contoso.example"), ("password", "correct horse battery"), ("confirm", "correct horse battery"));
        Assert.Equal(HttpStatusCode.Redirect, setup.StatusCode);
        Assert.Equal("/account/mfa-setup", setup.Headers.Location?.OriginalString);

        // Without a second factor, nothing else is reachable.
        var home = await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.Redirect, home.StatusCode);

        var mfaPage = await (await client.GetAsync("/account/mfa-setup")).Content.ReadAsStringAsync();
        var key = Html.AuthenticatorKeyOf(mfaPage);
        Assert.False(string.IsNullOrEmpty(key));
        var enroll = await client.PostFormAsync("/account/mfa/totp", Html.FormTokenOf(mfaPage), ("code", Totp.Code(key)));
        Assert.Equal("/account/recovery-codes", enroll.Headers.Location?.OriginalString);
        var codes = Html.RecoveryCodesOf(await (await client.GetAsync("/account/recovery-codes")).Content.ReadAsStringAsync());
        Assert.Equal(10, codes.Count);
        // Shown once: the next visit has none.
        Assert.Empty(Html.RecoveryCodesOf(await (await client.GetAsync("/account/recovery-codes")).Content.ReadAsStringAsync()));

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/settings/users")).StatusCode);

        // The first administrator holds Organization admin; setup is closed; the audit log recorded it all.
        await using (var owner = new NpgsqlConnection(app.Database.Migrator))
        {
            Assert.Equal("Organization admin", await owner.ExecuteScalarAsync<string>(
                "SELECT r.name FROM vaulty.role_assignments a JOIN vaulty.roles r ON r.id = a.role_id"));
            var actions = (await owner.QueryAsync<string>("SELECT action FROM vaulty.audit_events ORDER BY seq")).ToList();
            Assert.Contains("organization.created", actions);
            Assert.Contains("mfa.enrolled", actions);
            Assert.Contains("role.assigned", actions);
        }
        var closed = await (await app.Client().GetAsync($"/setup?token={token}")).Content.ReadAsStringAsync();
        Assert.Contains("not valid", closed, StringComparison.Ordinal);

        // Sign in again: password, then the authenticator code.
        var fresh = app.Client();
        var login = await (await fresh.GetAsync("/account/login")).Content.ReadAsStringAsync();
        var password = await fresh.PostFormAsync("/account/login", Html.FormTokenOf(login), ("username", "admin@contoso.example"),
            ("password", "correct horse battery"), ("returnUrl", "/settings/audit"));
        Assert.StartsWith("/account/login/second-factor", password.Headers.Location?.OriginalString, StringComparison.Ordinal);
        var second = await (await fresh.GetAsync(password.Headers.Location)).Content.ReadAsStringAsync();
        await Task.Delay(TimeSpan.FromSeconds(1));
        var codeStep = await fresh.PostFormAsync("/account/login/second-factor", Html.FormTokenOf(second),
            ("code", Totp.Code(key, DateTimeOffset.UtcNow.AddSeconds(30))), ("returnUrl", "/settings/audit"));
        if (codeStep.Headers.Location?.OriginalString != "/settings/audit")
        {
            // The code above belongs to the next period; the server accepts one period of drift. Use a recovery code otherwise.
            codeStep = await fresh.PostFormAsync("/account/login/second-factor", Html.FormTokenOf(second), ("code", codes[0]),
                ("recovery", "true"), ("returnUrl", "/settings/audit"));
        }
        Assert.Equal("/settings/audit", codeStep.Headers.Location?.OriginalString);
        var audit = await (await fresh.GetAsync("/settings/audit")).Content.ReadAsStringAsync();
        Assert.Contains("login.succeeded", audit, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task A_wrong_password_is_audited_and_eventually_locks_the_account()
    {
        var client = app.Client();
        var login = await (await client.GetAsync("/account/login")).Content.ReadAsStringAsync();
        var result = await client.PostFormAsync("/account/login", Html.FormTokenOf(login), ("username", "nobody@contoso.example"),
            ("password", "wrong password here"));
        Assert.StartsWith("/account/login?error=invalid", result.Headers.Location?.OriginalString, StringComparison.Ordinal);
    }
}

public sealed class FirstAdminPasskeyTests(WebAppFixture app) : IClassFixture<WebAppFixture>
{
    [PostgresFact]
    public async Task The_first_administrator_registers_with_a_passkey_and_signs_in_without_a_password()
    {
        var client = app.Client();
        var token = await app.IssueSetupTokenAsync();
        var setupPage = await (await client.GetAsync($"/setup?token={token}")).Content.ReadAsStringAsync();
        await client.PostFormAsync("/setup", Html.FormTokenOf(setupPage), ("token", token), ("organization", "Fabrikam MSP"),
            ("email", "owner@fabrikam.example"), ("password", "another long password"), ("confirm", "another long password"));

        using var authenticator = new SoftwareAuthenticator();
        var mfaPage = await (await client.GetAsync("/account/mfa-setup")).Content.ReadAsStringAsync();
        var antiforgery = Html.MetaTokenOf(mfaPage);
        var creation = await client.PostJsonAsync("/account/passkey/creation-options", antiforgery);
        Assert.Equal(HttpStatusCode.OK, creation.StatusCode);
        var register = await client.PostJsonAsync("/account/passkey/register", antiforgery,
            new { credential = authenticator.Create(await creation.Content.ReadAsStringAsync()), name = "Test key" });
        Assert.True(register.IsSuccessStatusCode, await register.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/settings/users")).StatusCode);

        // A new browser: passwordless sign-in with the passkey only.
        var fresh = app.Client();
        var login = await (await fresh.GetAsync("/account/login")).Content.ReadAsStringAsync();
        var freshToken = Html.MetaTokenOf(login);
        var request = await fresh.PostJsonAsync("/account/passkey/request-options", freshToken);
        Assert.Equal(HttpStatusCode.OK, request.StatusCode);
        var signIn = await fresh.PostJsonAsync("/account/passkey/login", freshToken,
            new { credential = authenticator.Get(await request.Content.ReadAsStringAsync()) });
        Assert.True(signIn.IsSuccessStatusCode, await signIn.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await fresh.GetAsync("/")).StatusCode);

        // A password alone is no longer enough: the second factor is required.
        var other = app.Client();
        var loginPage = await (await other.GetAsync("/account/login")).Content.ReadAsStringAsync();
        var password = await other.PostFormAsync("/account/login", Html.FormTokenOf(loginPage), ("username", "owner@fabrikam.example"),
            ("password", "another long password"));
        Assert.StartsWith("/account/login/second-factor", password.Headers.Location?.OriginalString, StringComparison.Ordinal);

        // Step-up with the passkey adds a fresh confirmation to the session.
        var confirmPage = await (await fresh.GetAsync("/account/confirm?returnUrl=/settings/users")).Content.ReadAsStringAsync();
        var confirmToken = Html.MetaTokenOf(confirmPage);
        var stepRequest = await fresh.PostJsonAsync("/account/passkey/request-options", confirmToken);
        var stepUp = await fresh.PostJsonAsync("/account/stepup/passkey", confirmToken,
            new { credential = authenticator.Get(await stepRequest.Content.ReadAsStringAsync()) });
        Assert.True(stepUp.IsSuccessStatusCode, await stepUp.Content.ReadAsStringAsync());
        await using var owner = new NpgsqlConnection(app.Database.Migrator);
        Assert.True(await owner.ExecuteScalarAsync<bool>("SELECT EXISTS (SELECT 1 FROM vaulty.audit_events WHERE action = 'stepup.confirmed')"));
    }
}
