namespace Vaulty.Web.Components.Shared;

/// <summary>One step of a page's breadcrumb trail; the last step (the page itself) has no link.</summary>
public sealed record Crumb(string Label, string? Href = null);
