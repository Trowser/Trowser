using Trowser.Automation;
using Trowser.Security;

namespace Trowser.Security.XsLeaks;

/// <summary>Suggests secret-dependent victim state pairs from session traffic and captured identities.</summary>
public sealed class XsLeakStateGenerator
{
    private readonly AutomationContext _ctx;
    private readonly IdentityStore _identities;

    public XsLeakStateGenerator(AutomationContext ctx, IdentityStore? identities = null)
    {
        _ctx = ctx;
        _identities = identities ?? ctx.OrchestrateIdentityStore ?? new IdentityStore();
    }

    public sealed class GenerationResult
    {
        public List<XsLeakScanner.StateSpec> States { get; init; } = new();
        public string Strategy { get; init; } = "none";
        public string? Detail { get; init; }
    }

    public async Task<GenerationResult> TryGenerateAsync(string? focusUrl = null)
    {
        var current = focusUrl ?? await _ctx.GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(current)
            || current.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
        {
            return new GenerationResult
            {
                Strategy = "none",
                Detail = "Navigate to the target application (not about:blank) and browse authenticated APIs before autoStates."
            };
        }

        if (!Uri.TryCreate(current, UriKind.Absolute, out var pageUri))
        {
            return new GenerationResult { Strategy = "none", Detail = "No absolute page URL." };
        }

        var identityPair = TryIdentityPair(pageUri);
        if (identityPair != null)
            return identityPair;

        var searchPair = TrySearchHitMiss(pageUri);
        if (searchPair != null)
            return searchPair;

        var protectedPair = TryProtectedVsSyntheticMiss(pageUri);
        if (protectedPair != null)
            return protectedPair;

        return new GenerationResult
        {
            Strategy = "none",
            Detail = "Capture two identities on this host, browse authenticated APIs, or pass explicit states[]."
        };
    }

    private GenerationResult? TryIdentityPair(Uri pageUri)
    {
        var catalog = _identities.List()
            .Where(e => IdentityHostMatches(pageUri.Host, e.Domain))
            .OrderByDescending(e => e.CookieCount + e.LocalStorageCount)
            .ToList();

        if (catalog.Count == 0)
            return null;

        var protectedUrl = ProtectedResourceOracle.SelectProtectedUrl(_ctx, pageUri);
        var url = protectedUrl ?? pageUri.ToString();
        if (ProtectedResourceOracle.IsUnreliableProtectedOracle(url))
            url = pageUri.ToString();

        if (catalog.Count >= 2)
        {
            var a = catalog[0].Name;
            var b = catalog[1].Name;
            return new GenerationResult
            {
                Strategy = "identity-pair",
                Detail = $"Same URL with identities '{a}' vs '{b}' (domain={pageUri.Host}).",
                States =
                [
                    new XsLeakScanner.StateSpec { Label = a, Url = url, Identity = a, Role = "hit" },
                    new XsLeakScanner.StateSpec { Label = b, Url = url, Identity = b, Role = "miss" }
                ]
            };
        }

        var only = catalog[0].Name;
        return new GenerationResult
        {
            Strategy = "identity-pair",
            Detail = $"Identity '{only}' vs anonymous on same URL (domain={pageUri.Host}).",
            States =
            [
                new XsLeakScanner.StateSpec { Label = only, Url = url, Identity = only, Role = "hit" },
                new XsLeakScanner.StateSpec { Label = "anonymous", Url = url, Identity = "anonymous", Role = "miss" }
            ]
        };
    }

    public static bool IdentityHostMatches(string pageHost, string? identityDomain)
    {
        if (string.IsNullOrWhiteSpace(identityDomain) || string.IsNullOrWhiteSpace(pageHost))
            return false;
        if (pageHost.Equals(identityDomain, StringComparison.OrdinalIgnoreCase))
            return true;
        if (pageHost.EndsWith("." + identityDomain, StringComparison.OrdinalIgnoreCase))
            return true;
        if (identityDomain.EndsWith("." + pageHost, StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private GenerationResult? TrySearchHitMiss(Uri pageUri)
    {
        var observed = XsLeakSearchTrafficOracle.TryFindPair(_ctx.Network.Entries, pageUri.Host);
        if (observed == null)
            return null;

        if (observed.HitState != null && observed.MissState != null)
        {
            return new GenerationResult
            {
                Strategy = "search-hit-miss",
                Detail = $"{observed.ParamKey} from session traffic. {observed.Detail}",
                States = [observed.HitState, observed.MissState]
            };
        }

        return new GenerationResult
        {
            Strategy = "search-hit-miss",
            Detail = $"Query param '{observed.ParamKey}' from session traffic. {observed.Detail}",
            States =
            [
                new XsLeakScanner.StateSpec { Label = "search-hit", Url = observed.HitUrl, Role = "hit" },
                new XsLeakScanner.StateSpec { Label = "search-miss", Url = observed.MissUrl, Role = "miss" }
            ]
        };
    }

    private GenerationResult? TryProtectedVsSyntheticMiss(Uri pageUri)
    {
        var protectedUrl = ProtectedResourceOracle.SelectProtectedUrl(_ctx, pageUri);
        if (string.IsNullOrWhiteSpace(protectedUrl))
            return null;

        var miss = pageUri.GetLeftPart(UriPartial.Authority)
                   + "/trowser-xsleak-probe-miss-" + Guid.NewGuid().ToString("N")[..8];
        return new GenerationResult
        {
            Strategy = "protected-vs-synthetic-miss",
            Detail = "Authenticated resource vs same-origin synthetic 404 path (informational if only existence leaks).",
            States =
            [
                new XsLeakScanner.StateSpec { Label = "protected", Url = protectedUrl, Role = "hit" },
                new XsLeakScanner.StateSpec { Label = "synthetic-miss", Url = miss, Role = "miss" }
            ]
        };
    }

}
