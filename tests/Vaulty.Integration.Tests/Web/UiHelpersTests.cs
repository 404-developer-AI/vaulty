using Vaulty.Core.Domain;
using Vaulty.Infrastructure.Browse;
using Vaulty.Infrastructure.Reporting;
using Vaulty.Web.Search;

namespace Vaulty.Integration.Tests.Web;

/// <summary>The pieces of the interface that decide what a user sees: the search in the top bar and the list of skipped items.</summary>
public sealed class UiHelpersTests
{
    private static readonly Guid Customer = Guid.NewGuid();
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Mailbox = Guid.NewGuid();

    private static Dashboard SampleDashboard()
    {
        var counts = new Dictionary<ProtectionStatus, int> { [ProtectionStatus.Partial] = 1 };
        var mailbox = new ObjectStatusRow(Mailbox, Tenant, "Bram Janssens", "mailbox", "user", ProtectionStatus.Partial, "", null, 10, 3, null);
        var tenant = new TenantStatusRow(Tenant, Customer, "Acme Logistics HQ", "granted", "active", ProtectionStatus.Partial, "", counts, null, null, null, 0, 0, [mailbox]);
        var customer = new CustomerStatusRow(Customer, "ACME", "Acme Logistics", ProtectionStatus.Partial, counts, [tenant]);
        return new Dashboard([customer], counts, []);
    }

    [Fact]
    public void Search_finds_customers_by_code_and_name_tenants_and_protected_users()
    {
        var dashboard = SampleDashboard();

        var byCode = Assert.Single(QuickSearch.Find(dashboard, "acme"), s => s.Kind == SuggestionKind.Customer);
        Assert.Equal($"/customers/{Customer}", byCode.Href);
        Assert.Contains(QuickSearch.Find(dashboard, "logistics"), s => s.Kind == SuggestionKind.Tenant && s.Href == $"/tenants/{Tenant}");

        var person = Assert.Single(QuickSearch.Find(dashboard, "jans"));
        Assert.Equal(SuggestionKind.ProtectedObject, person.Kind);
        Assert.Equal($"/objects/{Mailbox}", person.Href);
        Assert.Equal(ProtectionStatus.Partial, person.Status);

        Assert.Empty(QuickSearch.Find(dashboard, "contoso"));
    }

    [Fact]
    public void Search_puts_exact_and_prefix_matches_before_other_matches()
    {
        var results = QuickSearch.Find(SampleDashboard(), "Acme Logistics").ToList();
        Assert.Equal(SuggestionKind.Customer, results[0].Kind);
    }

    [Fact]
    public void Skipped_items_are_read_in_both_recorded_spellings()
    {
        var list = SnapshotBrowser.ParseExceptions(
            """[{"SourceId":"a","FolderId":"f","ErrorCode":"too_large","Detail":"Files over 250 GB"},{"error_code":"corrupt","detail":"Unreadable"},{"other":1}]""");
        Assert.Equal(3, list.Count);
        Assert.Equal(("too_large", "Files over 250 GB", "f", "a"), (list[0].Code, list[0].Detail, list[0].FolderId, list[0].SourceId));
        Assert.Equal(("corrupt", "Unreadable"), (list[1].Code, list[1].Detail));
        Assert.Equal("unknown", list[2].Code);
        Assert.Empty(SnapshotBrowser.ParseExceptions(null));
        Assert.Empty(SnapshotBrowser.ParseExceptions("{}"));
    }

    [Fact]
    public void Every_reason_reads_as_plain_words_with_advice()
    {
        foreach (var code in new[] { "too_large", "hash_mismatch", "count_mismatch", "corrupt", "cancelled", "failed", "something_new" })
        {
            Assert.False(string.IsNullOrWhiteSpace(Vaulty.Web.Browse.ObjectLabels.ExceptionReason(code)));
            Assert.False(string.IsNullOrWhiteSpace(Vaulty.Web.Browse.ObjectLabels.ExceptionAdvice(code)));
        }
    }
}
