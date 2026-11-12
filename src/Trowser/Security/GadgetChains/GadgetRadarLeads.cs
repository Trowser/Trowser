using Trowser.Security.DomFlow;
using Trowser.Security.Runtime;

namespace Trowser.Security.GadgetChains;

/// <summary>
/// Separates radar <em>leads</em> (hints for manual follow-up) from auto clobber/DOM-flow proof targets.
/// </summary>
public static class GadgetRadarLeads
{
    public const string DiscoveryTrap = "trap";
    public const string DiscoveryScriptScan = "script-scan";

    private static readonly HashSet<string> DocumentBuiltinNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "navigator", "documentElement", "body", "head", "title", "location", "cookie", "domain",
        "referrer", "activeElement", "fonts", "timeline", "picture", "fragmentDirective",
        "xml", "xmlVersion", "doctype", "implementation", "characterSet", "contentType",
        "readyState", "compatMode", "visibilityState", "hidden", "defaultView", "styleSheets",
        "scripts", "images", "links", "forms", "anchors", "all", "createElement", "querySelector"
    };

    private static readonly HashSet<string> WindowBuiltinNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "location", "document", "navigator", "history", "screen", "performance", "console",
        "localStorage", "sessionStorage", "indexedDB", "crypto", "fetch", "self", "top",
        "parent", "frames", "length", "name", "status", "origin", "devicePixelRatio"
    };

    public static string NormalizeDiscovery(RuntimeEvent evt)
    {
        if (evt.Extra.TryGetValue("how", out var how) && !string.IsNullOrWhiteSpace(how))
            return how.Trim();
        if (!string.IsNullOrWhiteSpace(evt.Data)
            && (evt.Data.Equals(DiscoveryScriptScan, StringComparison.OrdinalIgnoreCase)
                || evt.Data.Equals(DiscoveryTrap, StringComparison.OrdinalIgnoreCase)))
            return evt.Data.Trim();
        return DiscoveryTrap;
    }

    public static bool IsClobberProbeCandidate(GadgetRadarService.GadgetRadarHit hit)
    {
        if (string.IsNullOrWhiteSpace(hit.Key) || hit.Key.Length is < 2 or > 64)
            return false;

        var receiver = hit.Receiver ?? InferReceiver(hit.Name);
        if (receiver.Equals("document", StringComparison.OrdinalIgnoreCase))
        {
            if (DocumentBuiltinNames.Contains(hit.Key))
                return false;
            if (hit.Discovery.Equals(DiscoveryScriptScan, StringComparison.OrdinalIgnoreCase))
                return false;
            return hit.Discovery.Equals(DiscoveryTrap, StringComparison.OrdinalIgnoreCase);
        }

        if (receiver.Equals("window", StringComparison.OrdinalIgnoreCase))
        {
            if (WindowBuiltinNames.Contains(hit.Key))
                return false;
            return true;
        }

        return false;
    }

    public static List<string> SelectClobberProbeNames(
        IReadOnlyList<GadgetRadarService.GadgetRadarHit> hits,
        IReadOnlyList<string>? explicitOverride = null)
    {
        if (explicitOverride is { Count: > 0 })
        {
            return explicitOverride
                .Where(n => n.Length >= 2 && IsSafeClobberIdentifier(n))
                .Where(n => !DocumentBuiltinNames.Contains(n) && !WindowBuiltinNames.Contains(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(8)
                .ToList();
        }

        return hits
            .Where(IsClobberProbeCandidate)
            .OrderByDescending(h => h.Rank)
            .Select(h => h.Key!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .ToList();
    }

    public static bool ShouldEmitDomFlowFinding(DomFlowGraph.DomFlowChain chain)
    {
        if (!DomFlowGraph.IsAttackerReachableSource(chain.Source))
            return false;
        if (!string.Equals(chain.Tier, "exploitable", StringComparison.OrdinalIgnoreCase))
            return false;

        if (string.Equals(chain.Consequence, "exec", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(chain.Confidence, "canary", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(chain.Consequence, "inert", StringComparison.OrdinalIgnoreCase))
            return false;

        return chain.Consequence is "executable-markup" or "nav-hijack" or "request-forgery"
               && chain.Confidence is "canary" or "value-match"
               && DomFlowGraph.StackIncludesPageScript(chain.Stack);
    }

    public static bool IsDomFlowLead(DomFlowGraph.DomFlowChain chain)
    {
        if (!DomFlowGraph.IsAttackerReachableSource(chain.Source))
            return false;
        if (string.Equals(chain.Tier, "probe-artifact", StringComparison.OrdinalIgnoreCase))
            return false;
        if (ShouldEmitDomFlowFinding(chain))
            return false;

        return string.Equals(chain.Tier, "exploitable", StringComparison.OrdinalIgnoreCase)
               || (string.Equals(chain.Tier, "hygiene", StringComparison.OrdinalIgnoreCase)
                   && chain.Confidence is "value-match" or "canary");
    }

    public static GadgetChainLead ToDomFlowLead(DomFlowGraph.DomFlowChain chain) =>
        new()
        {
            Kind = "dom-flow",
            Name = $"{chain.Source} → {chain.Sink}",
            Detail = $"consequence={chain.Consequence}, confidence={chain.Confidence}, tier={chain.Tier}",
            SuggestedAction = SecurityNextActions.TraceInputMonitorSinks
        };

    public static GadgetChainLead ToRadarLead(GadgetRadarService.GadgetRadarHit hit) =>
        new()
        {
            Kind = "gadget-read",
            Name = hit.Name,
            Detail = $"discovery={hit.Discovery}, count={hit.Count}, firstPartyStack={hit.FirstPartyStack}, clobberProbe={hit.ClobberProbeCandidate}",
            SuggestedAction = hit.ClobberProbeCandidate
                ? "Active clobber probe may apply — confirm HTML injection point separately."
                : SecurityNextActions.GadgetRadarRead
        };

    internal static bool IsSafeClobberIdentifier(string name)
    {
        if (name.Length is < 2 or > 64)
            return false;
        if (!char.IsLetter(name[0]) && name[0] != '_')
            return false;
        return name.All(c => char.IsLetterOrDigit(c) || c is '_' or '-');
    }

    private static string InferReceiver(string name)
    {
        if (name.StartsWith("window.", StringComparison.OrdinalIgnoreCase))
            return "window";
        if (name.StartsWith("document.", StringComparison.OrdinalIgnoreCase))
            return "document";
        return "";
    }
}

public sealed class GadgetChainLead
{
    public string Kind { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Detail { get; init; }
    public string? SuggestedAction { get; init; }
}
