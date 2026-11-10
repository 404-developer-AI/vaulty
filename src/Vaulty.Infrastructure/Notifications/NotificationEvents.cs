using System.Text.Json;
using Dapper;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Notifications;

/// <summary>
/// The outbox of notification events. An event is written in the same transaction as the change it reports, so it is
/// sent exactly when that change happened; the dispatcher turns it into webhook deliveries.
/// </summary>
public static class NotificationEvents
{
    public static async Task PublishAsync(OrganizationSession session, string kind, Guid? tenantId, Guid? objectId, object? payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.notification_events (id, organization_id, kind, tenant_id, protected_object_id, payload)
            VALUES (@id, vaulty.current_organization_id(), @kind, @tenantId, @objectId, @payload::jsonb)
            """, new { id = Guid.CreateVersion7(), kind, tenantId, objectId, payload = JsonSerializer.Serialize(payload ?? new { }) },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }
}
