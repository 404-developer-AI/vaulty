using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Access;

/// <summary>
/// The one-time token that lets the first administrator set up Vaulty (<c>/setup?token=</c>). The installer issues it and
/// prints it in the installation report; it is valid for 24 hours and only while no organization exists. Only its hash is
/// stored.
/// </summary>
public sealed class SetupTokens(ISecretStore secrets, NpgsqlDataSource dataSource, TimeProvider clock)
{
    public const string SecretName = "setup.token";
    public static readonly TimeSpan Validity = TimeSpan.FromHours(24);

    private sealed record Stored(string Hash, DateTimeOffset ExpiresAt);

    public async Task<string> IssueAsync(string actor, CancellationToken cancellationToken = default)
    {
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(20));
        var stored = new Stored(Hash(token), clock.GetUtcNow() + Validity);
        await secrets.SetAsync(SecretName, JsonSerializer.SerializeToUtf8Bytes(stored), actor, cancellationToken).ConfigureAwait(false);
        return token;
    }

    public async Task<bool> IsSetupOpenAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteScalarAsync<long>(new CommandDefinition("SELECT vaulty.organization_count()",
            cancellationToken: cancellationToken)).ConfigureAwait(false) == 0;
    }

    public async Task<bool> ValidateAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token) || !await IsSetupOpenAsync(cancellationToken).ConfigureAwait(false)) return false;
        using var secret = await secrets.GetAsync(SecretName, cancellationToken).ConfigureAwait(false);
        if (secret is null) return false;
        var stored = JsonSerializer.Deserialize<Stored>(secret.Reveal());
        return stored is not null && stored.ExpiresAt > clock.GetUtcNow() &&
               CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(stored.Hash), Encoding.ASCII.GetBytes(Hash(token)));
    }

    /// <summary>Invalidates the token after use.</summary>
    public async Task ConsumeAsync(CancellationToken cancellationToken = default) =>
        await secrets.SetAsync(SecretName, JsonSerializer.SerializeToUtf8Bytes(new Stored("", DateTimeOffset.UnixEpoch)), "setup",
            cancellationToken).ConfigureAwait(false);

    private static string Hash(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token.Trim())));
}

/// <summary>Creates an organization with its built-in roles, and finishes the first administrator once they have a second factor.</summary>
public sealed class OrganizationSetup(NpgsqlDataSource dataSource, AccessService access)
{
    private const string PendingAdminSetting = "pending_first_admin";

    public async Task<Guid> CreateOrganizationAsync(string name, Guid firstAdminUserId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var organizationId = Guid.CreateVersion7();
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "INSERT INTO vaulty.organizations (id, name, settings) VALUES (@organizationId, @name, @settings::jsonb)",
            new { organizationId, name = name.Trim(), settings = JsonSerializer.Serialize(new Dictionary<string, string> { [PendingAdminSetting] = firstAdminUserId.ToString() }) },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AccessService.CreateBuiltInRolesAsync(session, cancellationToken).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, "setup", "organization.created", $"organization:{organizationId}", new { name }, cancellationToken)
            .ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return organizationId;
    }

    /// <summary>
    /// Called after a user enrolled a second factor: if they are the organization's pending first administrator, they now
    /// receive the Organization admin role (which requires MFA, so it could not be given before).
    /// </summary>
    public async Task<bool> CompleteFirstAdminAsync(Guid organizationId, Guid userId, CancellationToken cancellationToken = default)
    {
        Guid? roleId;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
        {
            var pending = await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition(
                "SELECT settings ->> @key FROM vaulty.organizations WHERE id = @organizationId FOR UPDATE",
                new { key = PendingAdminSetting, organizationId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (pending != userId.ToString()) return false;
            roleId = await session.Connection.ExecuteScalarAsync<Guid?>(new CommandDefinition(
                "SELECT id FROM vaulty.roles WHERE name = @name AND built_in", new { name = BuiltInRoles.OrganizationAdmin }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.organizations SET settings = settings - @key WHERE id = @organizationId",
                new { key = PendingAdminSetting, organizationId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        await access.AssignRoleAsync(organizationId, userId, userId, roleId!.Value, null, cancellationToken).ConfigureAwait(false);
        return true;
    }
}
