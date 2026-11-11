namespace Vaulty.Core.Security;

/// <summary>
/// Where a user may act: every customer, or a set of whole customers (their tenants included, also future ones) and
/// single tenants of customers the user sees only partly. Groups decide it; the rules are evaluated by the database
/// (vaulty.user_scope), and this is the result.
/// </summary>
public sealed class AccessScope
{
    private AccessScope(bool all, IReadOnlySet<Guid> wholeCustomers, IReadOnlyDictionary<Guid, IReadOnlySet<Guid>> partial)
    {
        All = all;
        WholeCustomers = wholeCustomers;
        PartialCustomers = partial;
    }

    public static AccessScope Everything { get; } = new(true, new HashSet<Guid>(), new Dictionary<Guid, IReadOnlySet<Guid>>());

    public static AccessScope Nothing { get; } = new(false, new HashSet<Guid>(), new Dictionary<Guid, IReadOnlySet<Guid>>());

    public static AccessScope Of(IEnumerable<Guid> wholeCustomers, IEnumerable<(Guid CustomerId, Guid TenantId)> partialTenants)
    {
        var whole = wholeCustomers.ToHashSet();
        var partial = partialTenants.Where(p => !whole.Contains(p.CustomerId)).GroupBy(p => p.CustomerId)
            .ToDictionary(g => g.Key, g => (IReadOnlySet<Guid>)g.Select(p => p.TenantId).ToHashSet());
        return new AccessScope(false, whole, partial);
    }

    public bool All { get; }

    public IReadOnlySet<Guid> WholeCustomers { get; }

    /// <summary>Customers seen only partly, with the tenants of each that are seen.</summary>
    public IReadOnlyDictionary<Guid, IReadOnlySet<Guid>> PartialCustomers { get; }

    public bool IsEmpty => !All && WholeCustomers.Count == 0 && PartialCustomers.Count == 0;

    /// <summary>The customers seen wholly or partly; null means every customer.</summary>
    public IReadOnlySet<Guid>? Customers => All ? null : WholeCustomers.Concat(PartialCustomers.Keys).ToHashSet();

    public bool SeesCustomer(Guid customerId) => All || WholeCustomers.Contains(customerId) || PartialCustomers.ContainsKey(customerId);

    public bool HasWholeCustomer(Guid customerId) => All || WholeCustomers.Contains(customerId);

    public bool SeesTenant(Guid customerId, Guid tenantId) =>
        All || WholeCustomers.Contains(customerId) || PartialCustomers.TryGetValue(customerId, out var tenants) && tenants.Contains(tenantId);

    /// <summary>True when everything the other scope sees is also seen here.</summary>
    public bool Covers(AccessScope other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (All) return true;
        if (other.All) return false;
        return other.WholeCustomers.All(WholeCustomers.Contains)
               && other.PartialCustomers.All(p => WholeCustomers.Contains(p.Key) || PartialCustomers.TryGetValue(p.Key, out var mine) && p.Value.All(mine.Contains));
    }
}
