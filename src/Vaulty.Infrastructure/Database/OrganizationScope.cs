using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;

namespace Vaulty.Infrastructure.Database;

/// <summary>The organization whose data the current unit of work may see. Null: none (every query returns nothing).</summary>
public interface IOrganizationContext
{
    Guid? OrganizationId { get; }
}

/// <summary>An organization context that is set explicitly, for workers and tests.</summary>
public sealed class FixedOrganizationContext(Guid? organizationId) : IOrganizationContext
{
    public Guid? OrganizationId { get; set; } = organizationId;
}

/// <summary>
/// Sets <c>vaulty.organization_id</c> on every connection EF Core opens, so row-level security filters every statement.
/// The value is always written, also when there is no organization (empty), so a pooled connection never carries the
/// setting of a previous user.
/// </summary>
public sealed class OrganizationConnectionInterceptor(IOrganizationContext context) : DbConnectionInterceptor
{
    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        using var command = CreateCommand(connection, context.OrganizationId);
        command.ExecuteNonQuery();
    }

    public override async Task ConnectionOpenedAsync(DbConnection connection, ConnectionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        await using var command = CreateCommand(connection, context.OrganizationId);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static DbCommand CreateCommand(DbConnection connection, Guid? organizationId)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT set_config('vaulty.organization_id', @org, false)";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "org";
        parameter.Value = organizationId?.ToString() ?? string.Empty;
        command.Parameters.Add(parameter);
        return command;
    }
}

/// <summary>
/// A connection and transaction bound to one organization with SET LOCAL, for Dapper hot paths. Disposing without
/// <see cref="CommitAsync"/> rolls back.
/// </summary>
public sealed class OrganizationSession : IAsyncDisposable
{
    private OrganizationSession(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid organizationId)
    {
        Connection = connection;
        Transaction = transaction;
        OrganizationId = organizationId;
    }

    public NpgsqlConnection Connection { get; }
    public NpgsqlTransaction Transaction { get; }
    public Guid OrganizationId { get; }

    public static async Task<OrganizationSession> BeginAsync(NpgsqlDataSource dataSource, Guid organizationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        if (organizationId == Guid.Empty) throw new ArgumentException("An organization is required.", nameof(organizationId));
        var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            await using (var command = new NpgsqlCommand("SELECT set_config('vaulty.organization_id', @org, true)",
                             connection, transaction))
            {
                command.Parameters.AddWithValue("org", organizationId.ToString());
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            return new OrganizationSession(connection, transaction, organizationId);
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// A session for a user: besides the organization, row-level security limits every row of a customer or tenant to the
    /// user's groups. A user with every customer in scope gets the organization session.
    /// </summary>
    public static async Task<OrganizationSession> BeginAsync(NpgsqlDataSource dataSource, Access.UserAccess access,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        var session = await BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        if (access.Scope.All) return session;
        try
        {
            static string List(IEnumerable<Guid> ids) => "{" + string.Join(',', ids) + "}";
            // The tenant list holds every tenant the user sees, those of whole customers included: read now, while the
            // session is not yet limited, so the policies only test the list.
            await using (var lists = new NpgsqlCommand(
                             """
                             SELECT set_config('vaulty.scope_whole', @whole, true), set_config('vaulty.scope_customers', @customers, true),
                                    set_config('vaulty.scope_tenants', coalesce((SELECT array_agg(id)::text FROM vaulty.tenants
                                                                                WHERE customer_id = ANY(@wholeIds) OR id = ANY(@tenantIds)), '{}'), true)
                             """, session.Connection, session.Transaction))
            {
                lists.Parameters.AddWithValue("whole", List(access.Scope.WholeCustomers));
                lists.Parameters.AddWithValue("customers", List(access.Scope.PartialCustomers.Keys));
                lists.Parameters.AddWithValue("wholeIds", access.Scope.WholeCustomers.ToArray());
                lists.Parameters.AddWithValue("tenantIds", access.Scope.PartialCustomers.Values.SelectMany(t => t).ToArray());
                await lists.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            await using (var restrict = new NpgsqlCommand("SELECT set_config('vaulty.scope_restricted', '1', true)", session.Connection, session.Transaction))
            {
                await restrict.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            return session;
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public Task CommitAsync(CancellationToken cancellationToken = default) => Transaction.CommitAsync(cancellationToken);

    public async ValueTask DisposeAsync()
    {
        await Transaction.DisposeAsync().ConfigureAwait(false);
        await Connection.DisposeAsync().ConfigureAwait(false);
    }
}
