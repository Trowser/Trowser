using Trowser.Security.Orchestration;

namespace Trowser.EndpointProbe;

/// <summary>How a probe uses checked endpoints in the Endpoint Probe dialog.</summary>
public enum EndpointProbeRunScope
{
    /// <summary>Pinned to checked URL/method; uses captured body/headers where supported.</summary>
    Endpoint,

    /// <summary>Session or current-page oriented; not limited to the selected request template.</summary>
    SiteWide
}

/// <summary>Probe definitions available in the Endpoint Probe dialog.</summary>
public sealed class EndpointProbeDefinition
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required string Group { get; init; }
    public bool IsPlaybook { get; init; }
    public EndpointProbeRunScope RunScope { get; init; }
}

public static class EndpointProbeCatalog
{
    public const string RequestFuzzerId = "request-fuzzer";
    public const string AuthControlIdentifierId = "auth-control-identifier";

    private static readonly HashSet<string> ExcludedPlaybookIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "full", "a02-misconfig", "a03-supplychain"
    };

    public static IReadOnlyList<EndpointProbeDefinition> Build(PlaybookRegistry registry)
    {
        var list = new List<EndpointProbeDefinition>();

        foreach (var pb in registry.All.Values.OrderBy(p => p.Id, StringComparer.OrdinalIgnoreCase))
        {
            if (ExcludedPlaybookIds.Contains(pb.Id))
                continue;
            list.Add(new EndpointProbeDefinition
            {
                Id = pb.Id,
                Title = pb.Title,
                Group = "Security",
                IsPlaybook = true,
                RunScope = ClassifyRunScope(pb.Id, isPlaybook: true)
            });
        }

        list.Add(new EndpointProbeDefinition
        {
            Id = AuthControlIdentifierId,
            Title = "Auth Control Identifier",
            Group = "Security",
            IsPlaybook = false,
            RunScope = EndpointProbeRunScope.Endpoint
        });

        list.Add(new EndpointProbeDefinition
        {
            Id = RequestFuzzerId,
            Title = "Request Fuzzer",
            Group = "Reliability",
            IsPlaybook = false,
            RunScope = EndpointProbeRunScope.Endpoint
        });

        return list;
    }

    /// <summary>True when the probe primarily targets the checked request (URL/method/body).</summary>
    public static bool IsEndpointPinnedProbe(string probeId) =>
        ClassifyRunScope(probeId, isPlaybook: !probeId.Equals(RequestFuzzerId, StringComparison.OrdinalIgnoreCase)
            && !probeId.Equals(AuthControlIdentifierId, StringComparison.OrdinalIgnoreCase))
            == EndpointProbeRunScope.Endpoint;

    private static EndpointProbeRunScope ClassifyRunScope(string probeId, bool isPlaybook)
    {
        if (!isPlaybook)
            return EndpointProbeRunScope.Endpoint;

        return EndpointScopeHelper.IsProbeHeavyPlaybook(probeId)
            ? EndpointProbeRunScope.Endpoint
            : EndpointProbeRunScope.SiteWide;
    }
}
