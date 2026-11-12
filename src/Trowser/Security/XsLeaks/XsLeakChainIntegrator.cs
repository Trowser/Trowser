using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security.XsLeaks;

/// <summary>Runs ChainAnalysisService on XS-Leaks chain findings plus related session findings.</summary>
internal static class XsLeakChainIntegrator
{
    public static ChainAnalysisResult? Analyze(AutomationContext ctx, XsLeakScanner.XsLeakResult result)
    {
        var xsChain = result.ChainFindings.Where(f =>
            !string.Equals(f.Severity, "info", StringComparison.OrdinalIgnoreCase)
            || f.Category.Equals("xs-leaks+cors", StringComparison.OrdinalIgnoreCase)).ToList();
        if (xsChain.Count == 0) return null;

        var pool = new List<ChainableFinding>(xsChain);
        var seen = pool.Select(f => f.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var f in ChainAnalysisService.CollectFindings(ctx))
        {
            if (!IsRelevantToXsLeaks(f)) continue;
            if (!seen.Add(f.Id)) continue;
            pool.Add(f);
        }

        var catalog = new ChainPatternCatalog();
        return ChainAnalysisService.Analyze(catalog, pool);
    }

    private static bool IsRelevantToXsLeaks(ChainableFinding f)
    {
        if (f.Category.StartsWith("xs-leaks", StringComparison.OrdinalIgnoreCase))
            return true;
        if (f.Category.Equals("cors", StringComparison.OrdinalIgnoreCase)
            || f.Category.Equals("cors-misconfiguration", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }
}
