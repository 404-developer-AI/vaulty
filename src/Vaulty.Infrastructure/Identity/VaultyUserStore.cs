using System.Security.Cryptography;
using System.Text;
using Dapper;
using Microsoft.AspNetCore.Identity;
using Npgsql;
using Vaulty.Core.Domain;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Identity;

/// <summary>
/// ASP.NET Core Identity store on the users and user_passkeys tables. Every statement runs in an organization session
/// (row-level security); the organization of a user name, user id or passkey is found first through the narrow
/// SECURITY DEFINER lookups. Recovery codes are stored as SHA-256 hashes only.
/// </summary>
public sealed class VaultyUserStore(NpgsqlDataSource dataSource) :
    IUserPasswordStore<User>,
    IUserSecurityStampStore<User>,
    IUserTwoFactorStore<User>,
    IUserAuthenticatorKeyStore<User>,
    IUserTwoFactorRecoveryCodeStore<User>,
    IUserLockoutStore<User>,
    IUserEmailStore<User>,
    IUserPasskeyStore<User>
{
    private const string Columns =
        "id, organization_id, user_name, normalized_user_name, email, normalized_email, email_confirmed, display_name, password_hash, " +
        "security_stamp, concurrency_stamp, two_factor_enabled, authenticator_key, lockout_end, lockout_enabled, access_failed_count, " +
        "recovery_codes, created_at, disabled_at";


    public void Dispose()
    {
    }

    // ---- lookups ------------------------------------------------------------------------------------------------------

    public async Task<User?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(userId, out var id)) return null;
        var org = await ScalarAsync<Guid?>("SELECT vaulty.user_organization(@id)", new { id }, cancellationToken).ConfigureAwait(false);
        return org is { } o ? await LoadAsync(o, "id = @id", new { id }, cancellationToken).ConfigureAwait(false) : null;
    }

    public async Task<User?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var found = await connection.QuerySingleOrDefaultAsync<(Guid UserId, Guid OrganizationId)?>(new CommandDefinition(
            "SELECT user_id, organization_id FROM vaulty.find_user_organization(@name)", new { name = normalizedUserName },
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return found is { } f ? await LoadAsync(f.OrganizationId, "id = @id", new { id = f.UserId }, cancellationToken).ConfigureAwait(false) : null;
    }

    public Task<User?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken) =>
        // User names are e-mail addresses in Vaulty; sign-in uses the user name lookup.
        FindByNameAsync(normalizedEmail, cancellationToken);

    public async Task<User?> FindByPasskeyIdAsync(byte[] credentialId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var found = await connection.QuerySingleOrDefaultAsync<(Guid UserId, Guid OrganizationId)?>(new CommandDefinition(
            "SELECT user_id, organization_id FROM vaulty.passkey_user(@credentialId)", new { credentialId },
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return found is { } f ? await LoadAsync(f.OrganizationId, "id = @id", new { id = f.UserId }, cancellationToken).ConfigureAwait(false) : null;
    }

    private async Task<User?> LoadAsync(Guid organizationId, string where, object args, CancellationToken cancellationToken)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return await session.Connection.QuerySingleOrDefaultAsync<User>(new CommandDefinition(
            $"SELECT {Columns} FROM vaulty.users WHERE {where} AND disabled_at IS NULL", args, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    // ---- create, update, delete ---------------------------------------------------------------------------------------

    public async Task<IdentityResult> CreateAsync(User user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (user.Id == Guid.Empty) user.Id = Guid.CreateVersion7();
        await using var session = await OrganizationSession.BeginAsync(dataSource, user.OrganizationId, cancellationToken).ConfigureAwait(false);
        try
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                $"""
                INSERT INTO vaulty.users ({Columns})
                VALUES (@Id, @OrganizationId, @UserName, @NormalizedUserName, @Email, @NormalizedEmail, @EmailConfirmed, @DisplayName,
                        @PasswordHash, @SecurityStamp, @ConcurrencyStamp, @TwoFactorEnabled, @AuthenticatorKey, @LockoutEnd, @LockoutEnabled,
                        @AccessFailedCount, @RecoveryCodes, now(), @DisabledAt)
                """, user, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
            return IdentityResult.Success;
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            return IdentityResult.Failed(new IdentityError { Code = "DuplicateUserName", Description = "This user name is already in use." });
        }
    }

    public async Task<IdentityResult> UpdateAsync(User user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        var previousStamp = user.ConcurrencyStamp;
        user.ConcurrencyStamp = Guid.NewGuid().ToString("N");
        await using var session = await OrganizationSession.BeginAsync(dataSource, user.OrganizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.users SET user_name = @UserName, normalized_user_name = @NormalizedUserName, email = @Email,
                   normalized_email = @NormalizedEmail, email_confirmed = @EmailConfirmed, display_name = @DisplayName,
                   password_hash = @PasswordHash, security_stamp = @SecurityStamp, concurrency_stamp = @ConcurrencyStamp,
                   two_factor_enabled = @TwoFactorEnabled, authenticator_key = @AuthenticatorKey, lockout_end = @LockoutEnd,
                   lockout_enabled = @LockoutEnabled, access_failed_count = @AccessFailedCount, recovery_codes = @RecoveryCodes,
                   disabled_at = @DisabledAt
             WHERE id = @Id AND concurrency_stamp = @previousStamp
            """,
            new
            {
                user.Id, user.UserName, user.NormalizedUserName, user.Email, user.NormalizedEmail, user.EmailConfirmed, user.DisplayName,
                user.PasswordHash, user.SecurityStamp, user.ConcurrencyStamp, user.TwoFactorEnabled, user.AuthenticatorKey, user.LockoutEnd,
                user.LockoutEnabled, user.AccessFailedCount, user.RecoveryCodes, user.DisabledAt, previousStamp,
            }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        if (rows == 1) return IdentityResult.Success;
        user.ConcurrencyStamp = previousStamp;
        return IdentityResult.Failed(new IdentityError { Code = "ConcurrencyFailure", Description = "The user was changed by someone else." });
    }

    /// <summary>Users are never deleted (the audit log refers to them); they are disabled.</summary>
    public async Task<IdentityResult> DeleteAsync(User user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        user.DisabledAt = DateTimeOffset.UtcNow;
        user.SecurityStamp = Guid.NewGuid().ToString("N");
        return await UpdateAsync(user, cancellationToken).ConfigureAwait(false);
    }

    // ---- simple properties --------------------------------------------------------------------------------------------

    public Task<string> GetUserIdAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.Id.ToString());
    public Task<string?> GetUserNameAsync(User user, CancellationToken cancellationToken) => Task.FromResult<string?>(user.UserName);
    public Task SetUserNameAsync(User user, string? userName, CancellationToken cancellationToken) => Set(() => user.UserName = userName ?? "");
    public Task<string?> GetNormalizedUserNameAsync(User user, CancellationToken cancellationToken) => Task.FromResult<string?>(user.NormalizedUserName);
    public Task SetNormalizedUserNameAsync(User user, string? normalizedName, CancellationToken cancellationToken) =>
        Set(() => user.NormalizedUserName = normalizedName ?? "");
    public Task SetPasswordHashAsync(User user, string? passwordHash, CancellationToken cancellationToken) => Set(() => user.PasswordHash = passwordHash);
    public Task<string?> GetPasswordHashAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.PasswordHash);
    public Task<bool> HasPasswordAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.PasswordHash is not null);
    public Task SetSecurityStampAsync(User user, string stamp, CancellationToken cancellationToken) => Set(() => user.SecurityStamp = stamp);
    public Task<string?> GetSecurityStampAsync(User user, CancellationToken cancellationToken) => Task.FromResult<string?>(user.SecurityStamp);
    public Task SetTwoFactorEnabledAsync(User user, bool enabled, CancellationToken cancellationToken) => Set(() => user.TwoFactorEnabled = enabled);
    public Task<bool> GetTwoFactorEnabledAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.TwoFactorEnabled);
    public Task SetAuthenticatorKeyAsync(User user, string key, CancellationToken cancellationToken) => Set(() => user.AuthenticatorKey = key);
    public Task<string?> GetAuthenticatorKeyAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.AuthenticatorKey);
    public Task<DateTimeOffset?> GetLockoutEndDateAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.LockoutEnd);
    public Task SetLockoutEndDateAsync(User user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken) => Set(() => user.LockoutEnd = lockoutEnd);
    public Task<int> IncrementAccessFailedCountAsync(User user, CancellationToken cancellationToken) => Task.FromResult(++user.AccessFailedCount);
    public Task ResetAccessFailedCountAsync(User user, CancellationToken cancellationToken) => Set(() => user.AccessFailedCount = 0);
    public Task<int> GetAccessFailedCountAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.AccessFailedCount);
    public Task<bool> GetLockoutEnabledAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.LockoutEnabled);
    public Task SetLockoutEnabledAsync(User user, bool enabled, CancellationToken cancellationToken) => Set(() => user.LockoutEnabled = enabled);
    public Task SetEmailAsync(User user, string? email, CancellationToken cancellationToken) => Set(() => user.Email = email);
    public Task<string?> GetEmailAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.Email);
    public Task<bool> GetEmailConfirmedAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.EmailConfirmed);
    public Task SetEmailConfirmedAsync(User user, bool confirmed, CancellationToken cancellationToken) => Set(() => user.EmailConfirmed = confirmed);
    public Task<string?> GetNormalizedEmailAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.NormalizedEmail);
    public Task SetNormalizedEmailAsync(User user, string? normalizedEmail, CancellationToken cancellationToken) =>
        Set(() => user.NormalizedEmail = normalizedEmail);

    // ---- recovery codes -----------------------------------------------------------------------------------------------

    public Task ReplaceCodesAsync(User user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken) =>
        Set(() => user.RecoveryCodes = recoveryCodes.Select(Hash).ToArray());

    public async Task<bool> RedeemCodeAsync(User user, string code, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        var hash = Hash(code);
        if (!user.RecoveryCodes.Contains(hash, StringComparer.Ordinal)) return false;
        user.RecoveryCodes = user.RecoveryCodes.Where(c => c != hash).ToArray();
        return (await UpdateAsync(user, cancellationToken).ConfigureAwait(false)).Succeeded;
    }

    public Task<int> CountCodesAsync(User user, CancellationToken cancellationToken) => Task.FromResult(user.RecoveryCodes.Length);

    private static string Hash(string code) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(code.Trim().Replace("-", "", StringComparison.Ordinal).ToUpperInvariant())));

    // ---- passkeys -----------------------------------------------------------------------------------------------------

    public async Task AddOrUpdatePasskeyAsync(User user, UserPasskeyInfo passkey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(passkey);
        await using var session = await OrganizationSession.BeginAsync(dataSource, user.OrganizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.user_passkeys (organization_id, user_id, credential_id, public_key, name, created_at, sign_count, transports,
                is_user_verified, is_backup_eligible, is_backed_up, attestation_object, client_data_json)
            VALUES (@org, @userId, @CredentialId, @PublicKey, @Name, @CreatedAt, @signCount, @Transports, @IsUserVerified, @IsBackupEligible,
                @IsBackedUp, @AttestationObject, @ClientDataJson)
            ON CONFLICT (user_id, credential_id) DO UPDATE SET name = excluded.name, sign_count = excluded.sign_count,
                is_user_verified = excluded.is_user_verified, is_backed_up = excluded.is_backed_up
            """,
            new
            {
                org = user.OrganizationId, userId = user.Id, passkey.CredentialId, passkey.PublicKey, passkey.Name, passkey.CreatedAt,
                signCount = (long)passkey.SignCount, passkey.Transports, passkey.IsUserVerified, passkey.IsBackupEligible, passkey.IsBackedUp,
                passkey.AttestationObject, passkey.ClientDataJson,
            }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IList<UserPasskeyInfo>> GetPasskeysAsync(User user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        await using var session = await OrganizationSession.BeginAsync(dataSource, user.OrganizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<PasskeyRow>(new CommandDefinition(
            "SELECT * FROM vaulty.user_passkeys WHERE user_id = @id ORDER BY created_at", new { id = user.Id }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => r.ToInfo()).ToList();
    }

    public async Task<UserPasskeyInfo?> FindPasskeyAsync(User user, byte[] credentialId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        await using var session = await OrganizationSession.BeginAsync(dataSource, user.OrganizationId, cancellationToken).ConfigureAwait(false);
        var row = await session.Connection.QuerySingleOrDefaultAsync<PasskeyRow>(new CommandDefinition(
            "SELECT * FROM vaulty.user_passkeys WHERE user_id = @id AND credential_id = @credentialId", new { id = user.Id, credentialId },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row?.ToInfo();
    }

    public async Task RemovePasskeyAsync(User user, byte[] credentialId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        await using var session = await OrganizationSession.BeginAsync(dataSource, user.OrganizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM vaulty.user_passkeys WHERE user_id = @id AND credential_id = @credentialId", new { id = user.Id, credentialId },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private sealed class PasskeyRow
    {
        public byte[] CredentialId { get; set; } = [];
        public byte[] PublicKey { get; set; } = [];
        public string? Name { get; set; }
        public DateTime CreatedAt { get; set; }
        public long SignCount { get; set; }
        public string[]? Transports { get; set; }
        public bool IsUserVerified { get; set; }
        public bool IsBackupEligible { get; set; }
        public bool IsBackedUp { get; set; }
        public byte[] AttestationObject { get; set; } = [];
        public byte[] ClientDataJson { get; set; } = [];

        public UserPasskeyInfo ToInfo() => new(CredentialId, PublicKey, new DateTimeOffset(DateTime.SpecifyKind(CreatedAt, DateTimeKind.Utc)),
            (uint)SignCount, Transports, IsUserVerified, IsBackupEligible, IsBackedUp, AttestationObject, ClientDataJson) { Name = Name };
    }

    // ---- helpers ------------------------------------------------------------------------------------------------------

    private static Task Set(Action action)
    {
        action();
        return Task.CompletedTask;
    }

    private async Task<T?> ScalarAsync<T>(string sql, object args, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteScalarAsync<T>(new CommandDefinition(sql, args, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }
}
