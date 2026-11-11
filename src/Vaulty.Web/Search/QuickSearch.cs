using Vaulty.Core.Domain;
using Vaulty.Infrastructure.Reporting;
using Vaulty.Infrastructure.Web;

namespace Vaulty.Web.Search;

public enum SuggestionKind
{
    Customer,
    Tenant,
    ProtectedObject,
    Items,
}

/// <summary>One answer of the search field in the top bar; selecting it opens <see cref="Href"/>.</summary>
public sealed record SearchSuggestion(SuggestionKind Kind, string Title, string Subtitle, string Href, ProtectionStatus? Status = null);

/// <summary>
/// The search field on every page: customers (code or name), tenants and protected users (mailboxes, OneDrives) by name,
/// from the same rollup the dashboard shows, so it only finds what the user may see. Items are searched on the Search page.
/// The rollup is read once per minute per session.
/// </summary>
public sealed class QuickSearch(DashboardService dashboards, CurrentAccess current, TimeProvider clock)
{
    private static readonly TimeSpan Freshness = TimeSpan.FromMinutes(1);
    private Dashboard? _dashboard;
    private DateTimeOffset _loadedAt;

    public async Task<Dashboard> DashboardAsync(CancellationToken cancellationToken = default)
    {
        if (_dashboard is null || clock.GetUtcNow() - _loadedAt > Freshness)
        {
            _dashboard = await dashboards.LoadAsync(await current.GetAsync(), cancellationToken: cancellationToken);
            _loadedAt = clock.GetUtcNow();
        }
        return _dashboard;
    }

    public async Task<IReadOnlyList<SearchSuggestion>> SuggestAsync(string? text, int limit = 8, CancellationToken cancellationToken = default)
    {
        var query = text?.Trim() ?? "";
        if (query.Length == 0) return [];
        var dashboard = await DashboardAsync(cancellationToken);
        var results = Find(dashboard, query).Take(limit).ToList();
        results.Add(new SearchSuggestion(SuggestionKind.Items, $"Search messages and files for \"{query}\"", "In the latest backup of every protected object",
            $"/search?q={Uri.EscapeDataString(query)}"));
        return results;
    }

    /// <summary>Customers, tenants and protected objects whose name (or customer code) contains the query, best match first.</summary>
    public static IEnumerable<SearchSuggestion> Find(Dashboard dashboard, string query)
    {
        ArgumentNullException.ThrowIfNull(dashboard);
        var hits = new List<(int Rank, SearchSuggestion Suggestion)>();
        foreach (var customer in dashboard.Customers)
        {
            var rank = Rank(query, customer.Name, customer.Code);
            if (rank >= 0)
            {
                hits.Add((rank, new SearchSuggestion(SuggestionKind.Customer, $"{customer.Code} · {customer.Name}",
                    $"Customer · {StatusText.Plural(customer.Tenants.Count, "tenant")}", $"/customers/{customer.Id}", customer.Status)));
            }
            foreach (var tenant in customer.Tenants)
            {
                rank = Rank(query, tenant.Name);
                if (rank >= 0)
                {
                    hits.Add((rank, new SearchSuggestion(SuggestionKind.Tenant, tenant.Name, $"Tenant · {customer.Name}", $"/tenants/{tenant.Id}", tenant.Status)));
                }
                foreach (var o in tenant.Objects)
                {
                    rank = Rank(query, o.Name);
                    if (rank >= 0)
                    {
                        hits.Add((rank + 1, new SearchSuggestion(SuggestionKind.ProtectedObject, o.Name,
                            $"{StatusText.ObjectKind(o.Kind, o.SubKind)} · {customer.Name} · {tenant.Name}", $"/objects/{o.Id}", o.Status)));
                    }
                }
            }
        }
        return hits.OrderBy(h => h.Rank).ThenBy(h => h.Suggestion.Title, StringComparer.OrdinalIgnoreCase).Select(h => h.Suggestion);
    }

    /// <summary>0 for an exact match, 1 for a prefix of the name or one of its words, 2 for any other match, -1 for none.</summary>
    private static int Rank(string query, params string?[] values)
    {
        var best = -1;
        foreach (var value in values)
        {
            if (string.IsNullOrEmpty(value)) continue;
            int rank;
            if (value.Equals(query, StringComparison.OrdinalIgnoreCase)) rank = 0;
            else if (value.StartsWith(query, StringComparison.OrdinalIgnoreCase)
                     || value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(w => w.StartsWith(query, StringComparison.OrdinalIgnoreCase))) rank = 1;
            else if (value.Contains(query, StringComparison.OrdinalIgnoreCase)) rank = 2;
            else continue;
            if (best < 0 || rank < best) best = rank;
        }
        return best;
    }
}
