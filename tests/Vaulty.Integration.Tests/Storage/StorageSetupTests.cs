using System.Net;
using System.Security.Cryptography;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Crypto;
using Vaulty.Core.Storage;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Secrets;
using Vaulty.Infrastructure.Storage;
using Vaulty.Integration.Tests.Database;
using WireMock.Matchers;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Vaulty.Integration.Tests.Storage;

public sealed class StorageSetupTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>, IDisposable
{
    private const string IamNs = "https://iam.amazonaws.com/doc/2010-05-08/";
    private readonly WireMockServer _s3 = WireMockServer.Start();
    private readonly WireMockServer _iam = WireMockServer.Start();

    private sealed class CapturingLogger : ILogger<StorageSetupAssistant>
    {
        public List<string> Lines { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Add(formatter(state, exception) + exception);
    }

    private void MockProvider()
    {
        _s3.Given(Request.Create().WithPath(new RegexMatcher("^/[a-z0-9-]+/?$")).UsingPut()).RespondWith(Response.Create().WithStatusCode(200));
        var n = 0;
        _iam.Given(Request.Create().UsingPost().WithBody(new RegexMatcher("Action=CreateUser")))
            .RespondWith(Response.Create().WithBody(_ => $"<CreateUserResponse xmlns=\"{IamNs}\"><CreateUserResult><User><Path>/</Path><UserName>u</UserName><UserId>AIDEXAMPLE</UserId><Arn>arn:aws:iam::100000000000:user/u</Arn><CreateDate>2026-11-09T00:00:00Z</CreateDate></User></CreateUserResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></CreateUserResponse>"));
        _iam.Given(Request.Create().UsingPost().WithBody(new RegexMatcher("Action=PutUserPolicy")))
            .RespondWith(Response.Create().WithBody($"<PutUserPolicyResponse xmlns=\"{IamNs}\"><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></PutUserPolicyResponse>"));
        _iam.Given(Request.Create().UsingPost().WithBody(new RegexMatcher("Action=CreateAccessKey")))
            .RespondWith(Response.Create().WithBody(_ =>
            {
                var i = Interlocked.Increment(ref n);
                return $"<CreateAccessKeyResponse xmlns=\"{IamNs}\"><CreateAccessKeyResult><AccessKey><UserName>u</UserName><AccessKeyId>EXAMPLEKEYID{i}</AccessKeyId><Status>Active</Status><SecretAccessKey>EXAMPLESECRETVALUE{i}xyz</SecretAccessKey><CreateDate>2026-11-09T00:00:00Z</CreateDate></AccessKey></CreateAccessKeyResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></CreateAccessKeyResponse>";
            }));
    }

    [PostgresFact]
    public async Task The_assistant_creates_buckets_and_identities_with_exactly_the_specified_policies()
    {
        MockProvider();
        await using var dataSource = VaultyDataSource.Create(db.Api);
        var secrets = new PostgresSecretStore(dataSource, new SecretCipher(RandomNumberGenerator.GetBytes(32), "host-a"), TimeProvider.System, TimeSpan.Zero);
        var settings = new PlatformSettings(dataSource);
        var logger = new CapturingLogger();
        var assistant = new StorageSetupAssistant(secrets, settings, logger);
        using var admin = new Secret("storage.admin", 0, "EXAMPLEADMINSECRET"u8);

        var steps = await assistant.RunAsync("eu-central-2", "vaulty-test", "EXAMPLEADMINKEY", admin, "test",
            new StorageEndpoints(_s3.Url!, _iam.Url!));
        Assert.Equal(5, steps.Count);

        // S3: the backup bucket is created with Object Lock (only possible at creation), then versioning; the export bucket
        // without Object Lock and with a one-day lifecycle.
        var s3 = _s3.LogEntries.Select(e => e.RequestMessage!).ToList();
        var createBackup = s3.Single(r => r.Path.TrimEnd('/') == "/vaulty-test-backup" && (r.Query is null || r.Query.Count == 0));
        Assert.Equal("true", createBackup.Headers!["x-amz-bucket-object-lock-enabled"].Single());
        var createExport = s3.Single(r => r.Path.TrimEnd('/') == "/vaulty-test-export" && (r.Query is null || r.Query.Count == 0));
        Assert.False(createExport.Headers!.ContainsKey("x-amz-bucket-object-lock-enabled") &&
                     createExport.Headers["x-amz-bucket-object-lock-enabled"].Single() == "true");
        Assert.Contains("<Status>Enabled</Status>", s3.Single(r => r.Query?.ContainsKey("versioning") == true).Body, StringComparison.Ordinal);
        var lifecycle = s3.Single(r => r.Query?.ContainsKey("lifecycle") == true).Body!;
        Assert.Contains("<Days>1</Days>", lifecycle, StringComparison.Ordinal);

        // IAM: three users with exactly the policies of StoragePolicies and one access key each.
        var iam = _iam.LogEntries.Select(e => WebUtility.UrlDecode(e.RequestMessage!.Body!)).ToList();
        Assert.Equal(3, iam.Count(b => b.Contains("Action=CreateUser", StringComparison.Ordinal)));
        Assert.Equal(3, iam.Count(b => b.Contains("Action=CreateAccessKey", StringComparison.Ordinal)));
        foreach (var role in Enum.GetValues<StorageRole>())
        {
            var name = role.ToString().ToLowerInvariant();
            var put = iam.Single(b => b.Contains("Action=PutUserPolicy", StringComparison.Ordinal) && b.Contains($"UserName=vaulty-test-{name}", StringComparison.Ordinal));
            Assert.Contains("PolicyDocument=" + StoragePolicies.For(role, "vaulty-test-backup", "vaulty-test-export"), put, StringComparison.Ordinal);
        }

        // Keys went to the secrets store; the settings and the log hold no secret.
        var stored = await settings.GetAsync<StorageSettings>(StorageSettings.SettingKey);
        Assert.NotNull(stored);
        Assert.Equal("vaulty-test-backup", stored.BackupBucket);
        Assert.False(stored.Ready);
        foreach (var role in Enum.GetValues<StorageRole>())
        {
            using var secret = await secrets.GetAsync(StorageSettings.SecretName(role));
            Assert.StartsWith("EXAMPLESECRETVALUE", secret!.RevealString(), StringComparison.Ordinal);
        }
        await using var owner = new NpgsqlConnection(db.Migrator);
        var allSettings = string.Join("\n", await owner.QueryAsync<string>("SELECT value::text FROM vaulty.platform_settings"));
        Assert.DoesNotContain("EXAMPLESECRET", allSettings, StringComparison.Ordinal);
        Assert.DoesNotContain("EXAMPLEADMIN", allSettings, StringComparison.Ordinal);
        Assert.All(logger.Lines, l => Assert.DoesNotContain("EXAMPLESECRET", l, StringComparison.Ordinal));
        Assert.Null(await secrets.GetAsync("storage.admin"));
    }

    [Fact]
    public void Policies_deny_deletes_to_the_worker_and_writes_to_garbage_collection()
    {
        var worker = StoragePolicies.For(StorageRole.Worker, "b", "e");
        Assert.Contains("\"Effect\":\"Deny\",\"Action\":[\"s3:DeleteObject\",\"s3:DeleteObjectVersion\",\"s3:BypassGovernanceRetention\"", worker, StringComparison.Ordinal);
        Assert.DoesNotContain("\"Effect\":\"Allow\",\"Action\":[\"s3:DeleteObject", worker, StringComparison.Ordinal);
        var gc = StoragePolicies.For(StorageRole.Gc, "b", "e");
        Assert.Contains("s3:DeleteObjectVersion", gc, StringComparison.Ordinal);
        Assert.DoesNotContain("arn:aws:s3:::e", gc, StringComparison.Ordinal); // no access to the export bucket
        Assert.Contains("\"Effect\":\"Deny\",\"Action\":[\"s3:PutObject\"", gc, StringComparison.Ordinal);
        var api = StoragePolicies.For(StorageRole.Api, "b", "e");
        Assert.Contains("arn:aws:s3:::b/tenants/*/keys/*", api, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        _s3.Dispose();
        _iam.Dispose();
    }
}

/// <summary>An inspector on in-memory stores: one shared store, seen through identities with different rights.</summary>
internal sealed class FakeInspector(bool backupLocked = true, bool exportLocked = false, bool versioning = true, bool workerCanDelete = false,
    TimeProvider? clock = null) : IStorageInspector
{
    private readonly InMemoryObjectStore _store = new(clock);

    public int ThrottledResponses => 0;
    public Task<bool> CanListAsync(StorageRole role, string bucket, CancellationToken cancellationToken) => Task.FromResult(true);
    public Task<bool> ObjectLockEnabledAsync(string bucket, CancellationToken cancellationToken) =>
        Task.FromResult(bucket.EndsWith("backup", StringComparison.Ordinal) ? backupLocked : exportLocked);
    public Task<bool> VersioningEnabledAsync(string bucket, CancellationToken cancellationToken) => Task.FromResult(versioning);

    public IObjectStore BackupStore(StorageRole role) => new View(_store, role == StorageRole.Gc || (role == StorageRole.Worker && workerCanDelete));

    public void Dispose()
    {
    }

    private sealed class View(InMemoryObjectStore inner, bool canDelete) : IObjectStore
    {
        public Task<ObjectInfo> PutAsync(string key, Stream content, ObjectPutOptions options, CancellationToken cancellationToken = default) =>
            inner.PutAsync(key, content, options, cancellationToken);
        public Task<Stream> GetAsync(string key, ByteRange? range = null, CancellationToken cancellationToken = default) =>
            inner.GetAsync(key, range, cancellationToken);
        public Task<ObjectInfo?> HeadAsync(string key, CancellationToken cancellationToken = default) => inner.HeadAsync(key, cancellationToken);
        public IAsyncEnumerable<ObjectInfo> ListAsync(string prefix, CancellationToken cancellationToken = default) => inner.ListAsync(prefix, cancellationToken);
        public Task DeleteAsync(string key, CancellationToken cancellationToken = default)
        {
            if (!canDelete) throw new ObjectStoreAccessDeniedException(key, "delete");
            return inner.DeleteAsync(key, cancellationToken);
        }
    }
}

public sealed class StorageConnectionTestTests
{
    private static readonly StorageSettings Settings = new("wasabi", "eu-central-2", "https://s3.example.com", "v-backup", "v-export", "assistant",
        new Dictionary<StorageRole, StorageIdentity>(), null);

    private static async Task<StorageTestResult> Run(FakeInspector inspector, FakeTimeProvider clock) =>
        await new StorageConnectionTest(clock, (wait, _) =>
        {
            clock.Advance(wait);
            return Task.CompletedTask;
        }).RunAsync(Settings, inspector);

    [Fact]
    public async Task A_correct_account_passes_all_six_checks()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var result = await Run(new FakeInspector(clock: clock), clock);
        Assert.Equal(6, result.Checks.Count);
        Assert.All(result.Checks, c => Assert.True(c.Passed, $"{c.Name}: {c.Detail}"));
        Assert.True((Settings with { LastTest = result }).Ready);
    }

    [Theory]
    [InlineData("backup-not-locked", "Object Lock on the backup bucket")]
    [InlineData("export-locked", "Object Lock on the backup bucket")]
    [InlineData("no-versioning", "Versioning on the backup bucket")]
    [InlineData("worker-deletes", "The worker cannot delete")]
    public async Task Each_failure_is_reported_on_its_own_check_and_blocks_planning(string failure, string failedCheck)
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var inspector = new FakeInspector(backupLocked: failure != "backup-not-locked", exportLocked: failure == "export-locked",
            versioning: failure != "no-versioning", workerCanDelete: failure == "worker-deletes", clock: clock);
        var result = await Run(inspector, clock);
        Assert.Equal(6, result.Checks.Count);
        Assert.False(result.Checks.Single(c => c.Name == failedCheck).Passed);
        Assert.False((Settings with { LastTest = result }).Ready);
    }
}
