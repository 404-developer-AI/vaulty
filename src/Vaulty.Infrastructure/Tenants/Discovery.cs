using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Graph;
using Vaulty.Graph.Http;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Tenants;

/// <summary>One protected object found in Microsoft 365.</summary>
public sealed record DiscoveredObject(string Kind, string SourceId, string DisplayName, string? SubKind, bool Protectable,
    IReadOnlyDictionary<string, string?> Details);

public sealed record DiscoveryResult(int Mailboxes, int SharedMailboxes, int ResourceMailboxes, int Drives, int NotProtectable, int SourceDeleted,
    int Reappeared)
{
    public Dictionary<string, long> Counts() => new()
    {
        ["mailboxes"] = Mailboxes, ["shared_mailboxes"] = SharedMailboxes, ["resource_mailboxes"] = ResourceMailboxes, ["drives"] = Drives,
        ["not_protected"] = NotProtectable, ["source_deleted"] = SourceDeleted, ["reappeared"] = Reappeared,
    };
}

/// <summary>
/// Finds the users, shared and resource mailboxes and OneDrives of a tenant and records them as protected objects.
/// Idempotent: running it twice changes nothing. An object that is no longer in Microsoft 365 becomes "source deleted"
/// (its snapshots are kept within retention); one that returns becomes active again. Archive mailboxes are recorded as
/// not protected yet, because Graph cannot export them.
/// </summary>
public sealed class TenantDiscovery(NpgsqlDataSource dataSource, GraphClient graph, TimeProvider clock)
{
    public async Task<IReadOnlyList<DiscoveredObject>> FindAsync(Guid tenantId, Action? heartbeat = null, CancellationToken cancellationToken = default)
    {
        var context = new GraphRequestContext(tenantId, Workload: "directory");
        var users = new List<GraphUser>();
        await foreach (var page in graph.PagesAsync(context, "users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType&$top=999",
                           GraphJson.Default.GraphCollectionGraphUser, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            users.AddRange(page.Items);
            heartbeat?.Invoke();
        }

        var found = new List<DiscoveredObject>();
        foreach (var batch in users.Chunk(6))
        {
            // Per user: mailbox type, mailbox ids, OneDrive. Three requests per user, up to 18 per $batch.
            var requests = batch.SelectMany(u => new[]
            {
                new GraphBatchRequest($"{u.Id}|purpose", "GET", $"/users/{u.Id}/mailboxSettings?$select=userPurpose"),
                new GraphBatchRequest($"{u.Id}|exchange", "GET", $"/users/{u.Id}/settings/exchange"),
                new GraphBatchRequest($"{u.Id}|drive", "GET", $"/users/{u.Id}/drive?$select=id,driveType,webUrl"),
            }).ToList();
            var responses = (await graph.BatchAsync(context, requests, cancellationToken).ConfigureAwait(false)).ToDictionary(r => r.Id, StringComparer.Ordinal);
            foreach (var user in batch)
            {
                var name = $"{user.DisplayName ?? user.UserPrincipalName} ({user.UserPrincipalName})";
                var purpose = responses[$"{user.Id}|purpose"];
                var exchange = responses[$"{user.Id}|exchange"];
                if (purpose.Status == 200 && exchange.Status == 200)
                {
                    var userPurpose = String(purpose.Body, "userPurpose") ?? "user";
                    var mailboxId = String(exchange.Body, "primaryMailboxId");
                    var archiveId = String(exchange.Body, "archiveMailboxId");
                    found.Add(new DiscoveredObject("mailbox", user.Id, name, userPurpose, mailboxId is not null, new Dictionary<string, string?>
                    {
                        ["upn"] = user.UserPrincipalName,
                        ["mailbox_id"] = mailboxId,
                        ["archive"] = archiveId is null ? "not detected (Graph does not report archives yet)" : "present",
                    }));
                    if (archiveId is not null)
                    {
                        found.Add(new DiscoveredObject("mailbox", user.Id + "|archive", name + " – archive", "archive", false,
                            new Dictionary<string, string?> { ["upn"] = user.UserPrincipalName, ["mailbox_id"] = archiveId, ["reason"] = "Archive mailboxes cannot be exported through Microsoft Graph yet." }));
                    }
                }
                var drive = responses[$"{user.Id}|drive"];
                if (drive.Status == 200 && String(drive.Body, "id") is { } driveId)
                {
                    found.Add(new DiscoveredObject("drive", driveId, name, String(drive.Body, "driveType"), true,
                        new Dictionary<string, string?> { ["upn"] = user.UserPrincipalName, ["user_id"] = user.Id }));
                }
            }
            heartbeat?.Invoke();
        }
        return found;
    }

    /// <summary>Records the discovered objects. Objects not in the list become source deleted.</summary>
    public async Task<DiscoveryResult> ApplyAsync(Guid organizationId, Guid tenantId, IReadOnlyList<DiscoveredObject> found,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(found);
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow();
        var reappeared = 0;
        foreach (var o in found)
        {
            var state = o.Protectable ? "active" : "not_protected";
            var previous = await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition(
                """
                INSERT INTO vaulty.protected_objects (id, organization_id, tenant_id, kind, sub_kind, source_id, display_name, state, source_details, next_run_at)
                VALUES (@id, @organizationId, @tenantId, @Kind, @SubKind, @SourceId, @DisplayName, @state, @details::jsonb, NULL)
                ON CONFLICT (tenant_id, kind, source_id) DO UPDATE SET
                    display_name = excluded.display_name, sub_kind = excluded.sub_kind, source_details = excluded.source_details,
                    state = CASE WHEN vaulty.protected_objects.state IN ('source_deleted', 'not_protected') THEN excluded.state
                                 ELSE vaulty.protected_objects.state END,
                    source_deleted_at = CASE WHEN vaulty.protected_objects.state = 'source_deleted' THEN NULL ELSE vaulty.protected_objects.source_deleted_at END
                RETURNING (SELECT p.state FROM vaulty.protected_objects p WHERE p.tenant_id = @tenantId AND p.kind = @Kind AND p.source_id = @SourceId)
                """,
                new { id = Guid.CreateVersion7(), organizationId, tenantId, o.Kind, o.SubKind, o.SourceId, o.DisplayName, state,
                    details = JsonSerializer.Serialize(o.Details) }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (previous == "source_deleted") reappeared++;
        }

        var foundKeys = found.Select(o => o.Kind + "\u001f" + o.SourceId).ToArray();
        var deleted = await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.protected_objects SET state = 'source_deleted', source_deleted_at = @now
             WHERE tenant_id = @tenantId AND state <> 'source_deleted' AND NOT ((kind || chr(31) || source_id) = ANY(@foundKeys))
            """, new { tenantId, now, foundKeys }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);

        var mailboxes = found.Where(o => o.Kind == "mailbox" && o.Protectable).ToList();
        return new DiscoveryResult(
            mailboxes.Count(m => m.SubKind is "user" or "linked" or null),
            mailboxes.Count(m => m.SubKind == "shared"),
            mailboxes.Count(m => m.SubKind is "room" or "equipment"),
            found.Count(o => o.Kind == "drive"),
            found.Count(o => !o.Protectable),
            deleted,
            reappeared);
    }

    private static string? String(JsonElement? body, string property) =>
        body is { ValueKind: JsonValueKind.Object } b && b.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
