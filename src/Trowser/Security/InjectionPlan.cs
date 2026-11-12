using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Pre-computed injection routing for auto-scan: which scanners apply per endpoint parameter.
/// Built once per pipeline run when <see cref="AutoScanPipeline.AutoScanOptions.UseSmartInjectionRouting"/> is on.
/// </summary>
public sealed class InjectionScanPlan
{
    public int EndpointsConsidered { get; init; }
    public int ProbesRouted { get; init; }
    public int ProbesSkippedByRouting { get; init; }

    public bool AllowsProbe(AttackSurfaceEndpoint ep, string paramName, string scanner)
    {
        var kind = InjectionParamClassifier.Classify(paramName, ep.UrlTemplate);
        return InjectionParamClassifier.AllowsScanner(
            kind, scanner, InjectionParamClassifier.IsLoginEndpoint(ep.UrlTemplate));
    }

    public bool AllowsFullSsti(AttackSurfaceEndpoint ep, string paramName, SstiEscalationTracker? escalation)
    {
        var kind = InjectionParamClassifier.Classify(paramName, ep.UrlTemplate);
        var endpointKey = AttackSurfaceMapper.FormatDisplayUrl(ep);
        var escalated = escalation?.IsEscalated(endpointKey, paramName) == true;
        return InjectionParamClassifier.AllowsFullSsti(kind, escalated);
    }

    public bool AllowsScaffoldScanner(InjectionParamKind kind, string scanner) =>
        InjectionParamClassifier.AllowsScanner(kind, scanner, isLoginEndpoint: kind == InjectionParamKind.Auth);
}

public static class InjectionPlanBuilder
{
    public static InjectionScanPlan Build(
        IReadOnlyList<AttackSurfaceEndpoint> endpoints,
        int maxEndpoints,
        int maxProbesPerEndpoint = 3)
    {
        var probesRouted = 0;
        var probesSkipped = 0;

        foreach (var ep in endpoints.Take(maxEndpoints))
        {
            var paramNames = ep.Parameters.Query
                .Concat(ep.Parameters.Body)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(maxProbesPerEndpoint);

            foreach (var param in paramNames)
            {
                if (InjectionParamClassifier.Classify(param, ep.UrlTemplate) == InjectionParamKind.UrlLike)
                    probesSkipped++;
                else
                    probesRouted++;
            }
        }

        return new InjectionScanPlan
        {
            EndpointsConsidered = Math.Min(endpoints.Count, maxEndpoints),
            ProbesRouted = probesRouted,
            ProbesSkippedByRouting = probesSkipped
        };
    }
}
