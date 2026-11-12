using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security.GadgetChains;

internal static class GadgetChainIntegrator
{
    public static ChainAnalysisResult? Analyze(AutomationContext ctx, GadgetChainScanner.GadgetChainResult result)
    {
        var chain = result.ChainFindings.Where(f =>
            !string.Equals(f.Severity, "info", StringComparison.OrdinalIgnoreCase)).ToList();
        if (chain.Count == 0)
            return null;

        var pool = new List<ChainableFinding>(chain);
        var seen = pool.Select(f => f.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var f in ChainAnalysisService.CollectFindings(ctx))
        {
            if (!IsRelevant(f))
                continue;
            if (!seen.Add(f.Id))
                continue;
            pool.Add(f);
        }

        return ChainAnalysisService.Analyze(new ChainPatternCatalog(), pool);
    }

    private static bool IsRelevant(ChainableFinding f) =>
        f.Category.StartsWith("client-gadget", StringComparison.OrdinalIgnoreCase)
        || f.Category.Equals("dom-clobbering", StringComparison.OrdinalIgnoreCase)
        || f.Category.Equals("client-prototype-pollution", StringComparison.OrdinalIgnoreCase)
        || f.Category.Equals("dom-xss", StringComparison.OrdinalIgnoreCase);
}
