using System.Security.Cryptography;
using Vaulty.Core.Abstractions;
using Vaulty.Infrastructure.Storage;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Vaulty.Integration.Tests.Storage;

/// <summary>Contract tests of the S3 adapter against a WireMock S3 endpoint (no real storage account needed).</summary>
public sealed class S3ObjectStoreTests : IDisposable
{
    private const string Bucket = "vaulty-test";
    private readonly WireMockServer _server = WireMockServer.Start();
    private readonly List<TimeSpan> _waits = [];

    private S3ObjectStore Store(int maxAttempts = 8)
    {
        using var secret = new Secret("storage.test.secret", 1, "EXAMPLESECRETKEY"u8);
        return new S3ObjectStore(new S3StoreSettings(_server.Url!, "eu-central-2", Bucket, "EXAMPLEACCESSKEY") { MaxAttempts = maxAttempts },
            secret, delay: (wait, _) =>
            {
                _waits.Add(wait);
                return Task.CompletedTask;
            });
    }

    private static string Md5Hex(byte[] data) => Convert.ToHexStringLower(MD5.HashData(data));

    [Fact]
    public async Task Put_honours_retry_after_on_503_and_sends_object_lock_headers()
    {
        var data = "pack bytes"u8.ToArray();
        var path = $"/{Bucket}/tenants/t/packs/aa/x.pack";
        _server.Given(Request.Create().WithPath(path).UsingHead()).RespondWith(Response.Create().WithStatusCode(404));
        _server.Given(Request.Create().WithPath(path).UsingPut()).InScenario("throttle").WillSetStateTo("second")
            .RespondWith(Response.Create().WithStatusCode(503).WithHeader("Retry-After", "7")
                .WithBody("<Error><Code>SlowDown</Code><Message>Reduce your request rate.</Message></Error>"));
        _server.Given(Request.Create().WithPath(path).UsingPut()).InScenario("throttle").WhenStateIs("second").WillSetStateTo("third")
            .RespondWith(Response.Create().WithStatusCode(503).WithHeader("Retry-After", "3")
                .WithBody("<Error><Code>SlowDown</Code><Message>Reduce your request rate.</Message></Error>"));
        _server.Given(Request.Create().WithPath(path).UsingPut()).InScenario("throttle").WhenStateIs("third")
            .RespondWith(Response.Create().WithStatusCode(200).WithHeader("ETag", $"\"{Md5Hex(data)}\""));

        using var store = Store();
        var lockUntil = new DateTimeOffset(2027, 3, 1, 0, 0, 0, TimeSpan.Zero);
        var info = await store.PutAsync("tenants/t/packs/aa/x.pack", new MemoryStream(data), new ObjectPutOptions(lockUntil));

        Assert.Equal(data.Length, info.Size);
        Assert.Equal([TimeSpan.FromSeconds(7), TimeSpan.FromSeconds(3)], _waits);
        Assert.Equal(2, store.ThrottledResponses);
        var put = _server.LogEntries.Last(e => e.RequestMessage!.Method == "PUT").RequestMessage!;
        Assert.Equal("COMPLIANCE", put.Headers!["x-amz-object-lock-mode"].Single());
        Assert.StartsWith("2027-03-01T00:00:00", put.Headers!["x-amz-object-lock-retain-until-date"].Single(), StringComparison.Ordinal);
        Assert.Equal(Convert.ToBase64String(MD5.HashData(data)), put.Headers!["Content-MD5"].Single());
    }

    [Fact]
    public async Task A_storm_of_503_ends_after_the_attempt_budget_without_hammering()
    {
        _server.Given(Request.Create().WithPath($"/{Bucket}/k").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(503).WithBody("<Error><Code>SlowDown</Code></Error>"));
        using var store = Store(maxAttempts: 5);
        await Assert.ThrowsAnyAsync<Amazon.Runtime.AmazonServiceException>(() => store.GetAsync("k"));
        Assert.Equal(4, _waits.Count);
        Assert.Equal(5, _server.LogEntries.Count(e => e.RequestMessage!.Method == "GET"));
    }

    [Fact]
    public async Task A_wrong_etag_is_reported_as_an_integrity_failure()
    {
        _server.Given(Request.Create().WithPath($"/{Bucket}/k").UsingHead()).RespondWith(Response.Create().WithStatusCode(404));
        _server.Given(Request.Create().WithPath($"/{Bucket}/k").UsingPut())
            .RespondWith(Response.Create().WithStatusCode(200).WithHeader("ETag", "\"00000000000000000000000000000000\""));
        using var store = Store();
        await Assert.ThrowsAsync<ObjectIntegrityException>(() =>
            store.PutAsync("k", new MemoryStream([1, 2, 3]), new ObjectPutOptions(DateTimeOffset.UtcNow.AddDays(1))));
    }

    [Fact]
    public async Task An_existing_key_is_never_overwritten()
    {
        _server.Given(Request.Create().WithPath($"/{Bucket}/k").UsingHead())
            .RespondWith(Response.Create().WithStatusCode(200).WithHeader("Content-Length", "3").WithHeader("ETag", "\"x\""));
        using var store = Store();
        await Assert.ThrowsAsync<ObjectAlreadyExistsException>(() =>
            store.PutAsync("k", new MemoryStream([1, 2, 3]), new ObjectPutOptions(DateTimeOffset.UtcNow.AddDays(1))));
        Assert.DoesNotContain(_server.LogEntries, e => e.RequestMessage!.Method == "PUT");
    }

    [Fact]
    public async Task Deleting_a_locked_version_reports_the_lock()
    {
        var until = DateTimeOffset.UtcNow.AddDays(30);
        _server.Given(Request.Create().WithPath(new WireMock.Matchers.RegexMatcher($"^/{Bucket}/?$")).WithParam("versions").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody(
                $"""
                <?xml version="1.0" encoding="UTF-8"?>
                <ListVersionsResult><Name>{Bucket}</Name><Prefix>k</Prefix><IsTruncated>false</IsTruncated>
                <Version><Key>k</Key><VersionId>v1</VersionId><IsLatest>true</IsLatest><Size>3</Size></Version>
                </ListVersionsResult>
                """));
        _server.Given(Request.Create().WithPath($"/{Bucket}/k").UsingDelete())
            .RespondWith(Response.Create().WithStatusCode(403).WithBody("<Error><Code>AccessDenied</Code><Message>Object is WORM protected</Message></Error>"));
        _server.Given(Request.Create().WithPath($"/{Bucket}/k").UsingHead())
            .RespondWith(Response.Create().WithStatusCode(200).WithHeader("Content-Length", "3")
                .WithHeader("x-amz-object-lock-mode", "COMPLIANCE")
                .WithHeader("x-amz-object-lock-retain-until-date", until.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture)));
        using var store = Store();
        var error = await Assert.ThrowsAsync<ObjectLockedException>(() => store.DeleteAsync("k"));
        Assert.NotNull(error.LockUntil);
        var delete = _server.LogEntries.Single(e => e.RequestMessage!.Method == "DELETE").RequestMessage!;
        Assert.Contains("versionId=v1", delete.Url!, StringComparison.Ordinal);
    }

    public void Dispose() => _server.Dispose();
}
