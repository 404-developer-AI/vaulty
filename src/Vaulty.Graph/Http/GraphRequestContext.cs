namespace Vaulty.Graph.Http;

/// <summary>Which tenant (and mailbox) a Graph request belongs to; carried in the request options through the handlers.</summary>
/// <param name="TenantId">Vaulty's tenant id (not the Entra id).</param>
/// <param name="Mailbox">The mailbox the request touches, for the per-mailbox concurrency limit; null otherwise.</param>
/// <param name="Workload">For telemetry: mail, calendar, contacts, tasks, drive, directory, probe.</param>
public sealed record GraphRequestContext(Guid TenantId, string? Mailbox = null, string Workload = "graph")
{
    public static readonly HttpRequestOptionsKey<GraphRequestContext> Key = new("vaulty.graph.context");

    public static GraphRequestContext From(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return request.Options.TryGetValue(Key, out var context)
            ? context
            : throw new InvalidOperationException("A Graph request needs a GraphRequestContext.");
    }
}

public static class GraphRequestExtensions
{
    public static HttpRequestMessage WithContext(this HttpRequestMessage request, GraphRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Options.Set(GraphRequestContext.Key, context);
        return request;
    }
}
