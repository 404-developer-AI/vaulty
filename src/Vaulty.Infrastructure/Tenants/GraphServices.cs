using System.Collections.Concurrent;
using Dapper;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Graph;
using Vaulty.Graph.Auth;
using Vaulty.Graph.Http;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Tenants;

/// <summary>
/// The dedicated-app credential of a tenant: its Entra tenant id and client id from the tenants table, the certificate with
/// private key from the secrets store. Cached briefly; a rotation invalidates the entry.
/// </summary>
public sealed class DedicatedAppCredentialProvider(NpgsqlDataSource dataSource, ISecretStore secrets, TimeProvider clock) : IGraphCredentialProvider
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(10);
    private readonly ConcurrentDictionary<Guid, (DateTimeOffset At, GraphCredential Credential)> _cache = new();

    public async Task<GraphCredential> GetAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        if (_cache.TryGetValue(tenantId, out var cached) && clock.GetUtcNow() - cached.At < CacheDuration) return cached.Credential;
        var credential = await LoadAsync(tenantId, useNextCertificate: false, cancellationToken).ConfigureAwait(false);
        _cache[tenantId] = (clock.GetUtcNow(), credential);
        return credential;
    }

    public void Invalidate(Guid tenantId) => _cache.TryRemove(tenantId, out _);

    /// <summary>The credential with the certificate that is being rotated in, to test it before it replaces the current one.</summary>
    public Task<GraphCredential> GetNextAsync(Guid tenantId, CancellationToken cancellationToken = default) =>
        LoadAsync(tenantId, useNextCertificate: true, cancellationToken);

    private async Task<GraphCredential> LoadAsync(Guid tenantId, bool useNextCertificate, CancellationToken cancellationToken)
    {
        Guid organizationId;
        await using (var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false))
        {
            organizationId = await connection.ExecuteScalarAsync<Guid?>(new CommandDefinition("SELECT vaulty.tenant_organization(@tenantId)",
                new { tenantId }, cancellationToken: cancellationToken)).ConfigureAwait(false)
                ?? throw new InvalidOperationException($"Tenant {tenantId} does not exist.");
        }
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var row = await session.Connection.QuerySingleAsync<(Guid EntraTenantId, Guid? ClientId, string? Certificate, string? Next)>(
            new CommandDefinition(
                "SELECT entra_tenant_id, client_id, certificate_secret_name, next_certificate_secret_name FROM vaulty.tenants WHERE id = @tenantId",
                new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var secretName = (useNextCertificate ? row.Next : row.Certificate)
                         ?? throw new InvalidOperationException("The tenant has no certificate.");
        if (row.ClientId is null) throw new InvalidOperationException("The tenant has no client id yet.");
        using var secret = await secrets.GetAsync(secretName, cancellationToken).ConfigureAwait(false)
                           ?? throw new InvalidOperationException("The tenant certificate is missing from the secrets store.");
        return new GraphCredential(row.EntraTenantId, row.ClientId.Value, TenantCertificate.Load(secret.Reveal()));
    }
}

/// <summary>The Graph pipeline of one process: one throttle shared by all tenants, one token cache, one client.</summary>
public sealed class GraphServices
{
    public GraphServices(IGraphTokenProvider tokens, GraphThrottle? throttle = null, Uri? graphBaseUri = null, HttpMessageHandler? network = null,
        Func<GraphThrottle, GraphDownloadClient>? downloads = null)
    {
        Tokens = tokens;
        Throttle = throttle ?? new GraphThrottle();
        Client = new GraphClient(GraphPipeline.Create(tokens, Throttle, network), graphBaseUri);
        Downloads = downloads?.Invoke(Throttle) ?? new GraphDownloadClient(Throttle);
    }

    public IGraphTokenProvider Tokens { get; }
    public GraphThrottle Throttle { get; }
    public GraphClient Client { get; }
    public GraphDownloadClient Downloads { get; }

    public PermissionProbe Probe() => new(Tokens, Client);
}
