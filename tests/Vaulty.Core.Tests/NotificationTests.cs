using System.Text;
using Vaulty.Core.Domain;
using Vaulty.Core.Notifications;

namespace Vaulty.Core.Tests;

public class WebhookSignatureTests
{
    private static readonly byte[] Secret = Encoding.ASCII.GetBytes("an-example-webhook-secret-of-32b");
    private static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"type\":\"backup.partial\"}");
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    [Fact]
    public void A_signature_verifies_over_the_exact_body_within_the_tolerance()
    {
        var header = WebhookSignature.Sign(Secret, Now.ToUnixTimeSeconds(), Body);
        Assert.StartsWith("t=1800000000,v1=", header, StringComparison.Ordinal);
        Assert.True(WebhookSignature.Verify(Secret, header, Body, Now));
        Assert.True(WebhookSignature.Verify(Secret, header, Body, Now.AddMinutes(4)));
        Assert.False(WebhookSignature.Verify(Secret, header, Body, Now.AddMinutes(6)));
        Assert.False(WebhookSignature.Verify(Secret, header, Body, Now.AddMinutes(-6)));
        Assert.False(WebhookSignature.Verify(Secret, header, [.. Body, (byte)' '], Now));
        Assert.False(WebhookSignature.Verify(new byte[32], header, Body, Now));
    }

    [Fact]
    public void The_signature_covers_the_timestamp()
    {
        var header = WebhookSignature.Sign(Secret, Now.ToUnixTimeSeconds(), Body);
        var moved = header.Replace("t=1800000000", "t=1800000060", StringComparison.Ordinal);
        Assert.False(WebhookSignature.Verify(Secret, moved, Body, Now));
    }

    [Fact]
    public void During_a_rotation_either_secret_verifies()
    {
        var other = Encoding.ASCII.GetBytes("the-previous-webhook-secret-32by");
        var header = WebhookSignature.Sign(Secret, Now.ToUnixTimeSeconds(), Body) + "," + WebhookSignature.Sign(other, Now.ToUnixTimeSeconds(), Body).Split(',')[1];
        Assert.True(WebhookSignature.Verify(Secret, header, Body, Now));
        Assert.True(WebhookSignature.Verify(other, header, Body, Now));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("v1=abc")]
    [InlineData("t=1800000000")]
    [InlineData("t=abc,v1=0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("t=1800000000,v1=zz00000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("garbage")]
    public void Malformed_headers_never_verify(string? header) => Assert.False(WebhookSignature.Verify(Secret, header, Body, Now));

    [Fact]
    public void Known_vector()
    {
        // HMAC-SHA256(secret, "1800000000." + body); lets a receiver in any language check its implementation.
        Assert.Equal("t=1800000000,v1=" + Convert.ToHexStringLower(System.Security.Cryptography.HMACSHA256.HashData(Secret, Encoding.ASCII.GetBytes("1800000000.").Concat(Body).ToArray())),
            WebhookSignature.Sign(Secret, 1_800_000_000, Body));
    }
}

public class ProtectionStatusTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);

    private static (ProtectionStatus Status, string Reason) Of(string state = "active", string? last = "committed", double hoursAgo = 1, int frequency = 360,
        string consent = "granted", bool verificationFailed = false, bool lastFailed = false, bool neverRan = false) =>
        Protection.Of(new ProtectionInput(state, neverRan ? null : last, neverRan ? null : Now.AddHours(-hoursAgo), frequency, consent, verificationFailed, lastFailed), Now);

    [Fact]
    public void Partial_is_amber_and_never_protected()
    {
        var (status, reason) = Of(last: "partial");
        Assert.Equal(ProtectionStatus.Partial, status);
        Assert.Equal("partial", Protection.CssClass(status));
        Assert.NotEqual(Protection.CssClass(ProtectionStatus.Protected), Protection.CssClass(status));
        Assert.Contains("missing", reason, StringComparison.Ordinal);
        // A tenant with one partial object among protected ones is partial; a failed one outranks it.
        Assert.Equal(ProtectionStatus.Partial, Protection.Worst([ProtectionStatus.Protected, ProtectionStatus.Partial, ProtectionStatus.Protected]));
        Assert.Equal(ProtectionStatus.Failed, Protection.Worst([ProtectionStatus.Partial, ProtectionStatus.Failed]));
    }

    [Fact]
    public void An_object_waits_for_its_first_backup_only_for_a_while()
    {
        static (ProtectionStatus, string) Added(double hoursAgo, int frequency = 360) =>
            Protection.Of(new ProtectionInput("active", null, null, frequency, "granted", false, false, Now.AddHours(-hoursAgo)), Now);

        Assert.Equal(ProtectionStatus.NotRunYet, Added(2).Item1);
        Assert.Equal("Awaiting first backup", Protection.Label(ProtectionStatus.NotRunYet));
        // At least a day, and twice the interval for long intervals; after that the missing first snapshot is a failure.
        Assert.Equal(ProtectionStatus.NotRunYet, Added(23).Item1);
        var (late, reason) = Added(25);
        Assert.Equal(ProtectionStatus.Failed, late);
        Assert.Contains("first backup did not run", reason, StringComparison.Ordinal);
        Assert.Equal(ProtectionStatus.NotRunYet, Added(40, frequency: 1440).Item1);
        Assert.Equal(ProtectionStatus.Failed, Added(49, frequency: 1440).Item1);
        // Without a known creation time nothing changes.
        Assert.Equal(ProtectionStatus.NotRunYet, Of(neverRan: true).Status);
    }

    [Fact]
    public void Only_genuine_failures_are_red()
    {
        Assert.Equal(ProtectionStatus.Protected, Of().Status);
        Assert.Equal(ProtectionStatus.Failed, Of(hoursAgo: 13).Status);             // older than twice the 6 h interval
        Assert.Equal(ProtectionStatus.Protected, Of(hoursAgo: 11).Status);
        Assert.Equal(ProtectionStatus.Failed, Of(consent: "lost").Status);
        Assert.Equal(ProtectionStatus.Failed, Of(verificationFailed: true).Status);
        Assert.Equal(ProtectionStatus.Failed, Of(lastFailed: true).Status);
        Assert.Equal(ProtectionStatus.Failed, Of(neverRan: true, lastFailed: true).Status);
        Assert.Equal(ProtectionStatus.NotRunYet, Of(neverRan: true).Status);
        Assert.Equal(ProtectionStatus.SourceDeleted, Of(state: "source_deleted", hoursAgo: 500).Status);
        Assert.Equal(ProtectionStatus.Paused, Of(state: "paused", hoursAgo: 500).Status);
        foreach (var neutral in new[] { ProtectionStatus.NotRunYet, ProtectionStatus.Paused, ProtectionStatus.SourceDeleted })
        {
            Assert.Equal("neutral", Protection.CssClass(neutral));
        }
        Assert.Equal("failed", Protection.CssClass(ProtectionStatus.Failed));
    }
}
