using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Vaulty.Graph.Auth;
using Vaulty.Graph.Http;
using Vaulty.Graph.Onboarding;
using WireMock;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using WireMock.Types;
using WireMock.Util;
using Xunit.Abstractions;

namespace Vaulty.Graph.Tests;

/// <summary>A token provider that hands out a fake JWT with the given roles.</summary>
internal sealed class FakeTokens(params string[] roles) : IGraphTokenProvider
{
    public int Requests { get; private set; }

    public Task<GraphToken> GetTokenAsync(Guid tenantId, bool forceRefresh = false, CancellationToken cancellationToken = default)
    {
        Requests++;
        static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = JsonSerializer.Serialize(new { tid = tenantId, roles });
        return Task.FromResult(new GraphToken($"{B64("{\"alg\":\"none\"}")}.{B64(payload)}.sig", DateTimeOffset.UtcNow.AddHours(1)));
    }
}

public sealed class GraphContractTests(ITestOutputHelper output) : IDisposable
{
    private static readonly Guid Tenant = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private readonly WireMockServer _server = WireMockServer.Start();
    private readonly GraphRequestContext _context = new(Tenant, Workload: "test");

    private Uri Base => new($"{_server.Url}/v1.0/");

    private (GraphClient Client, GraphThrottle Throttle) Create(GraphThrottle? throttle = null, IGraphTokenProvider? tokens = null)
    {
        throttle ??= new GraphThrottle();
        return (new GraphClient(GraphPipeline.Create(tokens ?? new FakeTokens(), throttle), Base), throttle);
    }

    private static string Users(int from, int count, string? next = null) => JsonSerializer.Serialize(new Dictionary<string, object?>
    {
        ["value"] = Enumerable.Range(from, count).Select(i => new { id = $"u{i}", displayName = $"User {i}" }),
        ["@odata.nextLink"] = next,
    });

    [Fact]
    public async Task A_storm_of_100_throttled_requests_slows_down_and_never_fails_the_caller()
    {
        // A storm: Graph answers 429 to everything during the first four seconds, then recovers.
        var stormStart = (DateTime?)null;
        var gate = new object();
        _server.Given(Request.Create().WithPath("/v1.0/users").UsingGet()).RespondWith(Response.Create().WithCallback(_ =>
        {
            lock (gate) stormStart ??= DateTime.UtcNow;
            return DateTime.UtcNow - stormStart < TimeSpan.FromSeconds(4)
                ? new ResponseMessage { StatusCode = 429, Headers = new Dictionary<string, WireMockList<string>> { ["Retry-After"] = new("1") } }
                : new ResponseMessage
                {
                    StatusCode = 200,
                    Headers = new Dictionary<string, WireMockList<string>> { ["Content-Type"] = new("application/json") },
                    BodyData = new BodyData { BodyAsString = Users(0, 1), DetectedBodyType = BodyType.String },
                };
        }));

        var (client, throttle) = Create();
        var initialRate = throttle.CurrentRate(Tenant);
        var started = DateTime.UtcNow;
        var results = await Task.WhenAll(Enumerable.Range(0, 100).Select(_ =>
            client.GetAsync(_context, "users", GraphJson.Default.GraphCollectionGraphUser)));
        var elapsed = DateTime.UtcNow - started;

        Assert.All(results, r => Assert.Single(r.Value));
        Assert.True(throttle.ThrottledResponses(Tenant) >= 4, "the storm throttled requests");
        Assert.Equal(100, throttle.SuccessfulResponses(Tenant));
        Assert.True(throttle.CurrentRate(Tenant) < initialRate, "the tenant rate must go down under throttling");
        Assert.True(elapsed >= TimeSpan.FromSeconds(1), "every caller waited for Retry-After");
        Assert.True(elapsed < TimeSpan.FromSeconds(90), "the rate recovers once throttling stops");
        output.WriteLine($"100 requests, {throttle.ThrottledResponses(Tenant)} throttled responses, 0 failed, {elapsed.TotalSeconds:F1} s; rate {initialRate} -> {throttle.CurrentRate(Tenant):F2}/s");
    }

    [Fact]
    public async Task Retry_after_is_honoured_exactly()
    {
        _server.Given(Request.Create().WithPath("/v1.0/users").UsingGet()).InScenario("ra").WillSetStateTo("2")
            .RespondWith(Response.Create().WithStatusCode(429).WithHeader("Retry-After", "7"));
        _server.Given(Request.Create().WithPath("/v1.0/users").UsingGet()).InScenario("ra").WhenStateIs("2").WillSetStateTo("3")
            .RespondWith(Response.Create().WithStatusCode(503).WithHeader("Retry-After", "2"));
        _server.Given(Request.Create().WithPath("/v1.0/users").UsingGet()).InScenario("ra").WhenStateIs("3")
            .RespondWith(Response.Create().WithStatusCode(200).WithHeader("Content-Type", "application/json").WithBody(Users(0, 2)));

        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var waits = new List<TimeSpan>();
        var throttle = new GraphThrottle(clock: clock, delay: (wait, _) =>
        {
            waits.Add(wait);
            clock.Advance(wait);
            return Task.CompletedTask;
        });
        var (client, _) = Create(throttle);
        var users = await client.GetAsync(_context, "users", GraphJson.Default.GraphCollectionGraphUser);
        Assert.Equal(2, users.Value.Count);
        Assert.Equal([TimeSpan.FromSeconds(7), TimeSpan.FromSeconds(2)], waits);
    }

    [Fact]
    public async Task Gone_starts_the_resync_route()
    {
        _server.Given(Request.Create().WithPath("/v1.0/users/delta").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(410).WithHeader("request-id", "req-1")
                .WithBody("""{"error":{"code":"syncStateNotFound","message":"The sync state is no longer valid."}}"""));
        var (client, _) = Create();
        var error = await Assert.ThrowsAsync<DeltaResyncRequiredException>(() =>
            client.DeltaPageAsync(_context, "users/delta?$deltatoken=old", GraphJson.Default.GraphCollectionGraphUser));
        Assert.Equal("syncStateNotFound", error.Code);
        Assert.Equal("req-1", error.RequestId);
    }

    [Fact]
    public async Task A_resync_error_code_with_another_status_also_starts_the_resync_route()
    {
        _server.Given(Request.Create().WithPath("/v1.0/users/delta").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(400).WithBody("""{"error":{"code":"resyncRequired","message":"Resync"}}"""));
        var (client, _) = Create();
        await Assert.ThrowsAsync<DeltaResyncRequiredException>(() =>
            client.DeltaPageAsync(_context, "users/delta?$deltatoken=x", GraphJson.Default.GraphCollectionGraphUser));
    }

    [Fact]
    public async Task Paging_follows_next_links_and_can_resume_from_a_stored_link()
    {
        _server.Given(Request.Create().WithPath("/v1.0/users").WithParam("$skiptoken", "p2").UsingGet())
            .RespondWith(Response.Create().WithHeader("Content-Type", "application/json").WithBody(Users(2, 2, $"{Base}users?$skiptoken=p3")));
        _server.Given(Request.Create().WithPath("/v1.0/users").WithParam("$skiptoken", "p3").UsingGet())
            .RespondWith(Response.Create().WithHeader("Content-Type", "application/json").WithBody(Users(4, 1)));
        _server.Given(Request.Create().WithPath("/v1.0/users").WithParam("$top", "2").UsingGet())
            .RespondWith(Response.Create().WithHeader("Content-Type", "application/json").WithBody(Users(0, 2, $"{Base}users?$skiptoken=p2")));
        var (client, _) = Create();

        var all = new List<string>();
        var links = new List<string?>();
        await foreach (var page in client.PagesAsync(_context, "users?$top=2", GraphJson.Default.GraphCollectionGraphUser))
        {
            all.AddRange(page.Items.Select(u => u.Id));
            links.Add(page.NextLink);
        }
        Assert.Equal(["u0", "u1", "u2", "u3", "u4"], all);
        Assert.Null(links[^1]);

        var resumed = new List<string>();
        await foreach (var page in client.PagesAsync(_context, "users?$top=2", GraphJson.Default.GraphCollectionGraphUser, resumeFrom: links[0]))
        {
            resumed.AddRange(page.Items.Select(u => u.Id));
        }
        Assert.Equal(["u2", "u3", "u4"], resumed);
    }

    [Fact]
    public async Task Delta_returns_next_link_then_delta_link()
    {
        _server.Given(Request.Create().WithPath("/v1.0/users/delta").WithParam("$skiptoken", "a").UsingGet())
            .RespondWith(Response.Create().WithHeader("Content-Type", "application/json").WithBody(JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["value"] = new object[] { new Dictionary<string, object> { ["id"] = "u9", ["@removed"] = new { reason = "deleted" } } },
                ["@odata.deltaLink"] = $"{Base}users/delta?$deltatoken=new",
            })));
        _server.Given(Request.Create().WithPath("/v1.0/users/delta").WithParam("$deltatoken", "old").UsingGet())
            .RespondWith(Response.Create().WithHeader("Content-Type", "application/json").WithBody(Users(0, 2, $"{Base}users/delta?$skiptoken=a")));
        var (client, _) = Create();
        var first = await client.DeltaPageAsync(_context, "users/delta?$deltatoken=old", GraphJson.Default.GraphCollectionGraphUser);
        Assert.NotNull(first.NextLink);
        Assert.Null(first.DeltaLink);
        var second = await client.DeltaPageAsync(_context, first.NextLink!, GraphJson.Default.GraphCollectionGraphUser);
        Assert.Null(second.NextLink);
        Assert.EndsWith("$deltatoken=new", second.DeltaLink, StringComparison.Ordinal);
        Assert.NotNull(second.Items[0].Removed);
    }

    [Fact]
    public async Task A_batch_with_partial_throttling_resends_only_the_throttled_requests()
    {
        _server.Given(Request.Create().WithPath("/v1.0/$batch").UsingPost()).InScenario("batch").WillSetStateTo("second")
            .RespondWith(Response.Create().WithHeader("Content-Type", "application/json").WithBody("""
                {"responses":[
                  {"id":"1","status":200,"body":{"id":"u1"}},
                  {"id":"2","status":429,"headers":{"Retry-After":"1"}},
                  {"id":"3","status":404,"body":{"error":{"code":"ResourceNotFound"}}}
                ]}
                """));
        _server.Given(Request.Create().WithPath("/v1.0/$batch").UsingPost()).InScenario("batch").WhenStateIs("second")
            .RespondWith(Response.Create().WithHeader("Content-Type", "application/json").WithBody("""
                {"responses":[{"id":"2","status":200,"body":{"id":"u2"}}]}
                """));
        var (client, _) = Create();
        var responses = await client.BatchAsync(_context, [
            new GraphBatchRequest("1", "GET", "/users/u1"),
            new GraphBatchRequest("2", "GET", "/users/u2"),
            new GraphBatchRequest("3", "GET", "/users/u3"),
        ]);
        Assert.Equal([200, 200, 404], responses.Select(r => r.Status));
        var batches = _server.LogEntries.Where(e => e.RequestMessage!.Path.EndsWith("$batch", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, batches.Count);
        Assert.Contains("\"id\":\"2\"", batches[1].RequestMessage!.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("\"id\":\"1\"", batches[1].RequestMessage!.Body, StringComparison.Ordinal);
        await Assert.ThrowsAsync<ArgumentException>(() => client.BatchAsync(_context,
            Enumerable.Range(0, 21).Select(i => new GraphBatchRequest($"{i}", "GET", "/me")).ToList()));
    }

    [Fact]
    public async Task Requests_are_decorated_and_authenticated()
    {
        _server.Given(Request.Create().WithPath("/v1.0/users").UsingGet())
            .RespondWith(Response.Create().WithHeader("Content-Type", "application/json").WithBody(Users(0, 1)));
        var (client, _) = Create();
        await client.GetAsync(_context, "users", GraphJson.Default.GraphCollectionGraphUser);
        var headers = _server.LogEntries.Single().RequestMessage!.Headers!;
        Assert.StartsWith("ISV|Steaan|Vaulty/", headers["User-Agent"].Single(), StringComparison.Ordinal);
        Assert.True(Guid.TryParse(headers["client-request-id"].Single(), out _));
        Assert.StartsWith("Bearer ", headers["Authorization"].Single(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_next_link_to_another_host_is_refused()
    {
        var (client, _) = Create();
        var error = await Assert.ThrowsAsync<GraphException>(() =>
            client.GetAsync(_context, "https://evil.example.com/v1.0/users", GraphJson.Default.GraphCollectionGraphUser));
        Assert.Equal("foreignLink", error.Code);
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task Export_items_posts_at_most_twenty_ids()
    {
        _server.Given(Request.Create().WithPath("/v1.0/admin/exchange/mailboxes/MBX:abc@def/exportItems").UsingPost())
            .RespondWith(Response.Create().WithHeader("Content-Type", "application/json").WithBody(
                """{"value":[{"itemId":"i1","changeKey":"c1","data":"AAEC"}]}"""));
        var (client, _) = Create();
        var items = await client.ExportItemsAsync(_context with { Mailbox = "m1" }, "MBX:abc@def", ["i1"]);
        Assert.Equal("AAEC", items.Single().Data);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ExportItemsAsync(_context, "MBX:abc@def", Enumerable.Range(0, 21).Select(i => $"i{i}").ToList()));
    }

    [Fact]
    public async Task Downloads_never_carry_a_token_and_only_go_to_allowed_hosts()
    {
        _server.Given(Request.Create().WithPath("/file").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(206).WithBody("rest of file"));
        var downloads = new GraphDownloadClient(new GraphThrottle(), allowedHostSuffixes: ["localhost"], allowHttpForTests: true);
        await using (var stream = await downloads.OpenAsync(_context, new Uri($"{_server.Url}/file"), offset: 100))
        {
            Assert.Equal("rest of file", await new StreamReader(stream).ReadToEndAsync());
        }
        var headers = _server.LogEntries.Single().RequestMessage!.Headers!;
        Assert.False(headers.ContainsKey("Authorization"));
        Assert.Equal("bytes=100-", headers["Range"].Single());

        var strict = new GraphDownloadClient(new GraphThrottle());
        Assert.False(strict.IsAllowed(new Uri("https://evil.example.com/file")));
        Assert.False(strict.IsAllowed(new Uri("http://contoso-my.sharepoint.com/file")));
        Assert.True(strict.IsAllowed(new Uri("https://contoso-my.sharepoint.com/_layouts/15/download.aspx?x=1")));
        await Assert.ThrowsAsync<GraphException>(() => strict.OpenAsync(_context, new Uri("https://evil.example.com/file")));
    }

    [Fact]
    public async Task The_permission_probe_reports_present_and_missing_permissions()
    {
        _server.Given(Request.Create().WithPath("/v1.0/organization").UsingGet())
            .RespondWith(Response.Create().WithHeader("Content-Type", "application/json").WithBody("""{"value":[{"id":"o","displayName":"Contoso"}]}"""));
        _server.Given(Request.Create().WithPath("/v1.0/users").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(403).WithHeader("request-id", "r-9")
                .WithBody("""{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}"""));
        var tokens = new FakeTokens("Organization.Read.All", "Mail.ReadWrite", "MailboxItem.ImportExport.All", "Files.Read.All");
        var (client, _) = Create(tokens: tokens);
        var report = await new PermissionProbe(tokens, client).ProbeAsync(Tenant);

        Assert.Contains("User.Read.All", report.Missing);
        Assert.DoesNotContain("Mail.Read", report.Missing);              // implied by Mail.ReadWrite
        Assert.DoesNotContain("MailboxItem.Export.All", report.Missing); // implied by ImportExport
        Assert.False(report.BackupReady);
        Assert.Contains(report.Checks, c => c is { Name: "List users", Passed: false } && c.Detail.Contains("r-9", StringComparison.Ordinal));
        output.WriteLine(report.ToText());
    }

    public void Dispose() => _server.Dispose();
}

public class OnboardingTests
{
    [Fact]
    public void A_tenant_certificate_has_a_private_key_and_the_script_registers_it()
    {
        var material = TenantCertificate.Create("Contoso Ltd");
        using var certificate = TenantCertificate.Load(material.Pfx);
        Assert.True(certificate.HasPrivateKey);
        Assert.Equal(material.Thumbprint, certificate.Thumbprint);
        Assert.Contains("CN=Vaulty Contoso Ltd", certificate.Subject, StringComparison.Ordinal);
        Assert.True(material.NotAfter - material.NotBefore > TimeSpan.FromDays(700));

        var backupOnly = OnboardingScript.PowerShell("Vaulty", material, includeRestore: false);
        Assert.Contains(material.PublicCertificateBase64, backupOnly, StringComparison.Ordinal);
        Assert.Contains("'MailboxItem.Export.All'", backupOnly, StringComparison.Ordinal);
        Assert.DoesNotContain("'Mail.ReadWrite'", backupOnly, StringComparison.Ordinal);
        Assert.DoesNotContain("'MailboxItem.ImportExport.All'", backupOnly, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", backupOnly, StringComparison.Ordinal); // no private key material in the script

        var withRestore = OnboardingScript.PowerShell("Vaulty", material, includeRestore: true);
        Assert.Contains("'MailboxItem.ImportExport.All'", withRestore, StringComparison.Ordinal);
        Assert.Contains("New-MgServicePrincipalAppRoleAssignment", withRestore, StringComparison.Ordinal);
        Assert.Equal(7, OnboardingScript.ManualSteps("Vaulty", true).Count);
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", OnboardingScript.CertificatePem(material), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Roles_are_read_from_the_token()
    {
        var token = await new FakeTokens("Mail.Read", "Files.Read.All").GetTokenAsync(Guid.NewGuid());
        Assert.Equal(["Mail.Read", "Files.Read.All"], token.Roles);
        Assert.Empty(TokenClaims.Roles("not a jwt"));
    }
}
