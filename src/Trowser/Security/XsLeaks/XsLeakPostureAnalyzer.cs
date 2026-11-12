using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

/// <summary>
/// Isolation posture for XS-Leaks: COOP/CORP/COEP, frame embedding, Fetch Metadata hints, SameSite model.
/// Interaction-oriented (what cross-site embeds can do), not a generic header lint.
/// </summary>
public sealed class XsLeakPostureAnalyzer
{
    private readonly AutomationContext _ctx;

    public XsLeakPostureAnalyzer(AutomationContext ctx) => _ctx = ctx;

    public sealed class ControlVerdict
    {
        public string Control { get; init; } = "";
        public string Status { get; init; } = "absent";
        public string? Detail { get; init; }
    }

    public sealed class PostureResult
    {
        public string VictimOrigin { get; init; } = "";
        public string CookieMode { get; init; } = "unknown";
        public List<ControlVerdict> Controls { get; init; } = new();
        public List<string> Recommendations { get; init; } = new();

        public object ToApiObject() => new
        {
            victimOrigin = VictimOrigin,
            cookieMode = CookieMode,
            controls = Controls.Select(c => new { c.Control, c.Status, c.Detail }),
            recommendations = Recommendations
        };
    }

    public async Task<PostureResult> AnalyzeAsync(
        string victimUrl,
        string cookieMode,
        IReadOnlyList<string>? probeMitigationTags = null)
    {
        var origin = "";
        if (Uri.TryCreate(victimUrl, UriKind.Absolute, out var uri))
            origin = uri.GetLeftPart(UriPartial.Authority);

        var entries = _ctx.ActiveTab.Network.Entries
            .Where(e => !string.IsNullOrEmpty(e.Url)
                        && (string.IsNullOrEmpty(origin)
                            || e.Url.StartsWith(origin, StringComparison.OrdinalIgnoreCase)))
            .TakeLast(40)
            .ToList();

        var controls = new List<ControlVerdict>();
        var tagList = CollectMitigationTags(entries);
        if (probeMitigationTags is { Count: > 0 })
            tagList = tagList.Concat(probeMitigationTags).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var parsed = XsLeakMitigations.Parse(tagList);

        controls.Add(EmbedControl("COOP", parsed.Coop,
            string.IsNullOrEmpty(parsed.Coop) ? "absent" : "present",
            "Cross-Origin-Opener-Policy limits window/opener XS-Leaks."));
        controls.Add(EmbedControl("CORP", parsed.Corp,
            string.IsNullOrEmpty(parsed.Corp) ? "absent" : "present",
            "Cross-Origin-Resource-Policy limits cross-origin resource observables."));
        controls.Add(EmbedControl("COEP", parsed.Coep,
            string.IsNullOrEmpty(parsed.Coep) ? "absent" : "present",
            "Cross-Origin-Embedder-Policy enables cross-origin isolation."));
        controls.Add(EmbedControl("X-Frame-Options", parsed.Xfo,
            string.IsNullOrEmpty(parsed.Xfo) ? "absent" : "present",
            "XFO blocks cross-origin framing when set to DENY/SAMEORIGIN."));
        controls.Add(new ControlVerdict
        {
            Control = "CSP-frame-ancestors",
            Status = parsed.HasFrameAncestors ? "present" : "absent",
            Detail = "frame-ancestors in CSP prevents arbitrary cross-origin embeds."
        });

        var fetchMeta = AnalyzeFetchMetadata(entries);
        controls.Add(fetchMeta);

        var sameSite = new ControlVerdict
        {
            Control = "SameSite-cookie-model",
            Status = cookieMode.Contains("strict", StringComparison.OrdinalIgnoreCase) ? "enforced"
                : cookieMode.Contains("none", StringComparison.OrdinalIgnoreCase) ? "cross-site-cookies"
                : "partial",
            Detail = $"Session cookie mode: {cookieMode} (subresource vs navigation differ)."
        };
        controls.Add(sameSite);
        var swControl = await AnalyzeServiceWorkerAsync();
        controls.Add(swControl);
        if (swControl.Status == "present")
        {
            controls.Add(await XsLeakServiceWorkerAnalyzer.InspectAsync(_ctx));
            var cacheControl = await XsLeakServiceWorkerAnalyzer.InspectCacheAsync(_ctx);
            if (cacheControl != null)
                controls.Add(cacheControl);
        }

        var recs = new List<string>();
        if (string.IsNullOrEmpty(parsed.Coop))
            recs.Add("Add Cross-Origin-Opener-Policy: same-origin on authenticated HTML documents.");
        if (string.IsNullOrEmpty(parsed.Corp))
            recs.Add("Add Cross-Origin-Resource-Policy: same-origin (or same-site) on sensitive responses.");
        if (!parsed.HasFrameAncestors && string.IsNullOrEmpty(parsed.Xfo))
            recs.Add("Deny cross-origin framing via CSP frame-ancestors 'none' or X-Frame-Options: DENY.");
        if (fetchMeta.Status == "absent")
            recs.Add("Enforce Fetch Metadata (reject or redirect cross-site Sec-Fetch-Site on sensitive routes).");

        var corsWildcard = entries.Any(e =>
            e.ResponseHeaders.TryGetValue("Access-Control-Allow-Origin", out var acao)
            && acao.Trim() == "*");
        if (corsWildcard)
        {
            controls.Add(new ControlVerdict
            {
                Control = "CORS-wildcard",
                Status = "present",
                Detail = "Access-Control-Allow-Origin: * on victim responses — cross-origin read of JSON may bypass subresource oracles; run browser_security_cors on the same endpoints."
            });
            recs.Add("Wildcard CORS on API responses can enable cross-origin fetch() reads; chain with XS-Leak oracles on the same URL.");
        }

        if (controls.Any(c => c.Control == "Service-Worker" && c.Status == "present"))
            recs.Add("Review service worker scope: broad scopes can cache or intercept responses used in XS-Leak state pairs.");

        return new PostureResult
        {
            VictimOrigin = origin,
            CookieMode = cookieMode,
            Controls = controls,
            Recommendations = recs
        };
    }

    private async Task<ControlVerdict> AnalyzeServiceWorkerAsync()
    {
        try
        {
            var raw = await _ctx.ExecuteJs(
                """
                (function(){
                  if (!('serviceWorker' in navigator)) return 'unsupported';
                  if (navigator.serviceWorker.controller) return 'controlled';
                  return 'none';
                })()
                """);
            var status = (raw ?? "").Trim().Trim('"');
            return new ControlVerdict
            {
                Control = "Service-Worker",
                Status = status switch
                {
                    "controlled" => "present",
                    "unsupported" => "absent",
                    _ => "absent"
                },
                Detail = status switch
                {
                    "controlled" =>
                        "Document is service-worker controlled — SW scope/cache may mediate XS-Leak observables; verify scope boundaries.",
                    "unsupported" => "Service workers not available in this browser context.",
                    _ => "No controlling service worker on the current document."
                }
            };
        }
        catch
        {
            return new ControlVerdict
            {
                Control = "Service-Worker",
                Status = "unknown",
                Detail = "Could not inspect service worker state on the active tab."
            };
        }
    }

    private static ControlVerdict AnalyzeFetchMetadata(IReadOnlyList<NetworkEntry> entries)
    {
        var withSite = entries
            .SelectMany(e => e.RequestHeaders.Where(h =>
                h.Key.StartsWith("Sec-Fetch-", StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (withSite.Count == 0)
        {
            return new ControlVerdict
            {
                Control = "Fetch-Metadata",
                Status = "unknown",
                Detail = "No Sec-Fetch-* captured for victim origin in this session (browse the app first)."
            };
        }

        var crossSite = entries.Where(e =>
                e.RequestHeaders.TryGetValue("Sec-Fetch-Site", out var v)
                && v.Equals("cross-site", StringComparison.OrdinalIgnoreCase))
            .ToList();

        return new ControlVerdict
        {
            Control = "Fetch-Metadata",
            Status = crossSite.Count > 0 ? "observed-cross-site" : "same-origin-only",
            Detail = crossSite.Count > 0
                ? $"{crossSite.Count} cross-site request(s) observed — verify server rejects sensitive reads."
                : "Only same-origin Sec-Fetch-Site observed in captured traffic."
        };
    }

    private static ControlVerdict EmbedControl(string name, string? value, string status, string detail) =>
        new()
        {
            Control = name,
            Status = string.IsNullOrEmpty(value) ? "absent" : status,
            Detail = string.IsNullOrEmpty(value) ? detail : $"{detail} Value: {value}."
        };

    private static List<string> CollectMitigationTags(IReadOnlyList<NetworkEntry> entries)
    {
        var tags = new List<string>();
        foreach (var e in entries)
        {
            foreach (var (k, v) in e.ResponseHeaders)
            {
                var key = k.ToLowerInvariant();
                var val = v ?? "";
                if (key == "cross-origin-opener-policy") tags.Add("COOP:" + val);
                if (key == "cross-origin-resource-policy") tags.Add("CORP:" + val);
                if (key == "cross-origin-embedder-policy") tags.Add("COEP:" + val);
                if (key == "x-frame-options") tags.Add("XFO:" + val);
                if (key == "content-security-policy" && val.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase))
                    tags.Add("CSP-frame-ancestors");
            }
        }
        return tags.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
