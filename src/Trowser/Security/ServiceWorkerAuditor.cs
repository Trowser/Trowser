using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Audits service worker registrations, script content, scope boundaries, and cache surface (browser-native).
/// </summary>
public sealed class ServiceWorkerAuditor
{
    private readonly AutomationContext _ctx;
    private static readonly Regex ImportScriptsRegex = new(
        @"importScripts\s*\(\s*['""](?<u>[^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ServiceWorkerAuditor(AutomationContext ctx) => _ctx = ctx;

    public sealed record SwRegistrationRow
    {
        public string Scope { get; init; } = "";
        public string? ScriptUrl { get; init; }
        public string? State { get; init; }
        public string? UpdateViaCache { get; init; }
        public bool ControlsCurrentPage { get; init; }
        public int? ScriptBytes { get; init; }
        public List<string> ScriptFlags { get; init; } = [];
    }

    public sealed record ServiceWorkerAuditResult
    {
        public string Url { get; init; } = "";
        public bool Supported { get; init; }
        public string? ControllerScriptUrl { get; init; }
        public List<SwRegistrationRow> Registrations { get; init; } = [];
        public List<string> CacheNames { get; init; } = [];
        public List<UnifiedSecurityFinding> Findings { get; init; } = [];
        public List<string> NextActions { get; init; } = [];
        public TrustedTypesPosture TrustedTypes { get; init; } = new();
        public string Summary { get; init; } = "";
    }

    public async Task<ServiceWorkerAuditResult> RunAsync(
        bool fetchScripts = true,
        int maxScriptBytes = 256_000,
        CancellationToken ct = default)
    {
        var pageUrl = await _ctx.GetCurrentUrl() ?? "";
        var tt = await TrustedTypesPosture.FromDocumentHeadersAsync(_ctx);

        var raw = await _ctx.ExecuteJs(EnumerateJs);
        var parsed = ParseEnumeration(raw);
        var result = new ServiceWorkerAuditResult
        {
            Url = pageUrl,
            Supported = parsed.Supported,
            ControllerScriptUrl = parsed.ControllerScriptUrl,
            CacheNames = parsed.CacheNames,
            TrustedTypes = tt
        };

        if (!parsed.Supported)
        {
            return result with
            {
                Summary = "Service workers are not supported in this context.",
                NextActions = ["No service worker audit applicable."]
            };
        }

        if (parsed.Registrations.Count == 0)
        {
            return result with
            {
                Summary = "No service worker registrations on this origin.",
                NextActions = [SecurityNextActions.ClientSurface]
            };
        }

        var findings = new List<UnifiedSecurityFinding>();
        var rows = new List<SwRegistrationRow>();

        foreach (var reg in parsed.Registrations)
        {
            ct.ThrowIfCancellationRequested();
            var row = new SwRegistrationRow
            {
                Scope = reg.Scope,
                ScriptUrl = reg.ScriptUrl,
                State = reg.State,
                UpdateViaCache = reg.UpdateViaCache,
                ControlsCurrentPage = reg.ControlsCurrentPage
            };

            AnalyzeScope(reg, pageUrl, findings);
            if (fetchScripts && !string.IsNullOrWhiteSpace(reg.ScriptUrl))
            {
                var (body, bytes) = await FetchScriptTextAsync(reg.ScriptUrl!, maxScriptBytes, ct);
                row = row with { ScriptBytes = bytes };
                if (body != null)
                    AnalyzeScriptBody(body, reg, findings, row.ScriptFlags);
                else if (bytes == 0)
                    findings.Add(MakeFinding(
                        "sw-script-unreadable",
                        "low",
                        "Service worker script could not be fetched from the page context.",
                        reg.ScriptUrl!,
                        "Verify worker script manually (DevTools → Application → Service Workers)."));
            }

            rows.Add(row);
        }

        if (parsed.CacheNames.Count > 0)
        {
            findings.Add(MakeFinding(
                "sw-cache-storage",
                "info",
                $"{parsed.CacheNames.Count} named Cache Storage bucket(s): {string.Join(", ", parsed.CacheNames.Take(8))}.",
                pageUrl,
                "Inspect cached responses for authenticated API payloads used in XS-Leak or cache-deception chains."));
        }

        return result with
        {
            Registrations = rows,
            Findings = findings,
            Summary =
                $"{rows.Count} registration(s); {findings.Count(f => f.Severity is "high" or "critical" or "medium")} notable finding(s).",
            NextActions = BuildNextActions(findings, rows)
        };
    }

    private static List<string> BuildNextActions(List<UnifiedSecurityFinding> findings, List<SwRegistrationRow> rows)
    {
        var next = new List<string>();
        if (findings.Any(f => f.Id.StartsWith("sw-scope", StringComparison.OrdinalIgnoreCase)))
            next.Add("Review scope vs app base path — narrow registration where possible.");
        if (findings.Any(f => f.Id.StartsWith("sw-script", StringComparison.OrdinalIgnoreCase)))
            next.Add("Read worker script for fetch handlers that cache credentialed responses or call importScripts from third parties.");
        if (rows.Count > 0)
            next.Add(SecurityNextActions.DomFlowsObserve);
        if (findings.Count == 0 && rows.Count > 0)
            next.Add("Manual review: confirm updateViaCache, skipWaiting/clients.claim, and no path-relative scope confusion.");
        return next;
    }

    private static void AnalyzeScope(SwRegParsedRow reg, string pageUrl, List<UnifiedSecurityFinding> findings)
    {
        if (!Uri.TryCreate(reg.Scope, UriKind.Absolute, out var scopeUri)
            || !Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            return;

        if (!string.Equals(scopeUri.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(MakeFinding(
                "sw-scope-host-mismatch",
                "medium",
                $"Registration scope host ({scopeUri.Host}) differs from page host ({pageUri.Host}).",
                reg.Scope,
                "Unexpected cross-host scope — verify this is intentional."));
            return;
        }

        var scopePath = scopeUri.AbsolutePath;
        if (scopePath == "/" || scopePath.Length == 0)
        {
            findings.Add(MakeFinding(
                "sw-scope-root",
                "medium",
                "Service worker scope is the origin root (/). Any path on this origin is controlled.",
                reg.Scope,
                "Prefer the narrowest scope directory that covers the PWA (e.g. /app/)."));
        }

        var pagePath = pageUri.AbsolutePath;
        if (scopePath.Length > 1
            && pagePath.StartsWith(scopePath, StringComparison.OrdinalIgnoreCase)
            && !reg.ControlsCurrentPage
            && pagePath.Length > scopePath.TrimEnd('/').Length + 1)
        {
            findings.Add(MakeFinding(
                "sw-scope-prefix",
                "info",
                $"Page path ({pagePath}) is under scope prefix ({scopePath}) but this document is not yet controlled.",
                reg.Scope,
                "After activation, the worker may intercept navigations under this prefix."));
        }

        if (!string.IsNullOrWhiteSpace(reg.ScriptUrl)
            && Uri.TryCreate(reg.ScriptUrl, UriKind.Absolute, out var scriptUri))
        {
            if (!string.Equals(scriptUri.Host, scopeUri.Host, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(MakeFinding(
                    "sw-script-cross-origin",
                    "high",
                    $"Worker script URL host ({scriptUri.Host}) differs from scope host ({scopeUri.Host}).",
                    reg.ScriptUrl!,
                    "Scripts must be same-origin — verify registration is valid and not confused with a CDN path."));
            }

            if (!pagePath.StartsWith(scopePath.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)
                && scopePath != "/")
            {
                findings.Add(MakeFinding(
                    "sw-scope-path-confusion",
                    "low",
                    "Page path is outside the registered scope prefix — scope takeover via path-relative registration is less likely here.",
                    reg.Scope,
                    "Re-test from pages inside the scope directory."));
            }
        }
    }

    private static void AnalyzeScriptBody(
        string body,
        SwRegParsedRow reg,
        List<UnifiedSecurityFinding> findings,
        List<string> flags)
    {
        if (body.Contains("clients.claim", StringComparison.OrdinalIgnoreCase))
        {
            flags.Add("clients.claim");
            findings.Add(MakeFinding(
                "sw-script-clients-claim",
                "info",
                "Worker script calls clients.claim() — may take control of uncontrolled clients quickly.",
                reg.ScriptUrl ?? reg.Scope,
                "Ensure scope is minimal; review for unintended page interception."));
        }

        if (body.Contains("skipWaiting", StringComparison.OrdinalIgnoreCase))
            flags.Add("skipWaiting");

        if (Regex.IsMatch(body, @"addEventListener\s*\(\s*['""]fetch['""]", RegexOptions.IgnoreCase))
        {
            flags.Add("fetch-handler");
            if (body.Contains("credentials", StringComparison.OrdinalIgnoreCase)
                || body.Contains("include", StringComparison.OrdinalIgnoreCase))
            {
                flags.Add("fetch-credentials");
                findings.Add(MakeFinding(
                    "sw-script-fetch-credentials",
                    "medium",
                    "fetch event handler references credentials — cross-origin subrequests may carry cookies.",
                    reg.ScriptUrl ?? reg.Scope,
                    "Audit cache.put of authenticated responses; pair with POST /api/security/xs-leaks for cache oracles."));
            }
        }

        if (body.Contains("cache.put", StringComparison.OrdinalIgnoreCase)
            || body.Contains("caches.open", StringComparison.OrdinalIgnoreCase))
        {
            flags.Add("cache-api");
            findings.Add(MakeFinding(
                "sw-script-cache-mutation",
                "medium",
                "Worker script uses Cache API — authenticated responses may be stored and replayed.",
                reg.ScriptUrl ?? reg.Scope,
                "Review cache keys and Vary handling; test cache-deception on API paths under scope."));
        }

        foreach (Match m in ImportScriptsRegex.Matches(body))
        {
            var u = m.Groups["u"].Value;
            flags.Add($"importScripts:{u}");
            if (u.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                || u.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                || u.StartsWith("//", StringComparison.Ordinal))
            {
                findings.Add(MakeFinding(
                    "sw-script-importscripts-remote",
                    "high",
                    $"importScripts loads remote URL: {u}",
                    reg.ScriptUrl ?? reg.Scope,
                    "Remote worker imports expand trust boundary — verify integrity and origin."));
            }
        }
    }

    private async Task<(string? Body, int Bytes)> FetchScriptTextAsync(
        string scriptUrl,
        int maxBytes,
        CancellationToken ct)
    {
        var urlJson = JsonSerializer.Serialize(scriptUrl);
        var max = maxBytes;
        try
        {
            var raw = await _ctx.ExecuteJs(
                $$"""
                (async function(){
                  var url = {{urlJson}};
                  try {
                    var r = await fetch(url, { credentials: 'include', cache: 'no-store' });
                    var t = await r.text();
                    if (t.length > {{max}}) t = t.substring(0, {{max}});
                    return JSON.stringify({ ok: r.ok, status: r.status, bytes: t.length, body: t });
                  } catch(e) {
                    return JSON.stringify({ ok: false, error: e.message || String(e) });
                  }
                })()
                """);
            ct.ThrowIfCancellationRequested();
            using var doc = JsonDocument.Parse(UnquoteJson(raw));
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out _))
                return (null, 0);
            if (!root.TryGetProperty("body", out var b))
                return (null, 0);
            var text = b.GetString() ?? "";
            return (text, text.Length);
        }
        catch
        {
            return (null, 0);
        }
    }

    private static UnifiedSecurityFinding MakeFinding(
        string id,
        string severity,
        string title,
        string endpoint,
        string remediation) =>
        UnifiedSecurityFinding.Create(
            category: "service-worker",
            title: title,
            severity: severity,
            confidence: SecurityConfidence.Likely,
            endpoint: endpoint,
            evidence: title,
            proofHint: remediation,
            tier: severity is "high" or "critical" ? SecurityFindingTier.Exploitable : SecurityFindingTier.Hygiene,
            id: id);

    private const string EnumerateJs = """
        (async function(){
          try {
            if (!('serviceWorker' in navigator))
              return JSON.stringify({ supported: false });
            var controller = null;
            if (navigator.serviceWorker.controller) {
              controller = {
                scriptURL: navigator.serviceWorker.controller.scriptURL,
                state: navigator.serviceWorker.controller.state
              };
            }
            var regs = await navigator.serviceWorker.getRegistrations();
            var rows = [];
            for (var i = 0; i < regs.length; i++) {
              var r = regs[i];
              var active = r.active || r.waiting || r.installing;
              rows.push({
                scope: r.scope,
                scriptURL: active ? active.scriptURL : null,
                state: active ? active.state : null,
                updateViaCache: r.updateViaCache || null,
                controlsCurrentPage: !!navigator.serviceWorker.controller
                  && navigator.serviceWorker.controller.scriptURL === (active ? active.scriptURL : '')
              });
            }
            var cacheNames = [];
            try {
              if (self.caches && caches.keys)
                cacheNames = (await caches.keys()).slice(0, 40);
            } catch(e) {}
            return JSON.stringify({
              supported: true,
              controller: controller,
              registrations: rows,
              cacheNames: cacheNames
            });
          } catch(e) {
            return JSON.stringify({ supported: true, error: e.message || String(e), registrations: [], cacheNames: [] });
          }
        })()
        """;

    private sealed class SwRegParsed
    {
        public bool Supported { get; init; }
        public string? ControllerScriptUrl { get; init; }
        public List<SwRegParsedRow> Registrations { get; init; } = [];
        public List<string> CacheNames { get; init; } = [];
    }

    private sealed class SwRegParsedRow
    {
        public string Scope { get; init; } = "";
        public string? ScriptUrl { get; init; }
        public string? State { get; init; }
        public string? UpdateViaCache { get; init; }
        public bool ControlsCurrentPage { get; init; }
    }

    private static SwRegParsed ParseEnumeration(string? raw)
    {
        var json = UnquoteJson(raw);
        if (string.IsNullOrWhiteSpace(json))
            return new SwRegParsed { Supported = false };

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var supported = root.TryGetProperty("supported", out var s) && s.GetBoolean();
            if (!supported)
                return new SwRegParsed { Supported = false };

            string? controller = null;
            if (root.TryGetProperty("controller", out var c) && c.ValueKind == JsonValueKind.Object
                && c.TryGetProperty("scriptURL", out var su))
                controller = su.GetString();

            var regs = new List<SwRegParsedRow>();
            if (root.TryGetProperty("registrations", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in arr.EnumerateArray())
                {
                    regs.Add(new SwRegParsedRow
                    {
                        Scope = el.TryGetProperty("scope", out var sc) ? sc.GetString() ?? "" : "",
                        ScriptUrl = el.TryGetProperty("scriptURL", out var scu) ? scu.GetString() : null,
                        State = el.TryGetProperty("state", out var st) ? st.GetString() : null,
                        UpdateViaCache = el.TryGetProperty("updateViaCache", out var uv) ? uv.GetString() : null,
                        ControlsCurrentPage = el.TryGetProperty("controlsCurrentPage", out var cp) && cp.GetBoolean()
                    });
                }
            }

            var caches = new List<string>();
            if (root.TryGetProperty("cacheNames", out var cn) && cn.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in cn.EnumerateArray())
                {
                    if (el.GetString() is { } name)
                        caches.Add(name);
                }
            }

            return new SwRegParsed
            {
                Supported = true,
                ControllerScriptUrl = controller,
                Registrations = regs,
                CacheNames = caches
            };
        }
        catch
        {
            return new SwRegParsed { Supported = true };
        }
    }

    private static string UnquoteJson(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return "";
        var t = raw.Trim();
        if (t.Length >= 2 && t.StartsWith('"') && t.EndsWith('"'))
            t = JsonSerializer.Deserialize<string>(t) ?? t;
        return t;
    }

    public object ToApiResponse(ServiceWorkerAuditResult r) => new
    {
        url = r.Url,
        supported = r.Supported,
        controllerScriptUrl = r.ControllerScriptUrl,
        summary = r.Summary,
        registrations = r.Registrations.Select(x => new
        {
            scope = x.Scope,
            scriptUrl = x.ScriptUrl,
            state = x.State,
            updateViaCache = x.UpdateViaCache,
            controlsCurrentPage = x.ControlsCurrentPage,
            scriptBytes = x.ScriptBytes,
            scriptFlags = x.ScriptFlags
        }),
        cacheNames = r.CacheNames,
        trustedTypes = r.TrustedTypes.ToApiObject(),
        findings = r.Findings.Select(SecurityScanResult.ToApiFinding),
        nextActions = r.NextActions
    };
}
