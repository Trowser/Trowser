using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Passive header checks plus active cross-origin iframe framing verification.
/// </summary>
public static class ClickjackTester
{
    public sealed class TestOptions
    {
        public bool IncludeActiveTest { get; set; }
        public bool IncludeSensitiveOverlayTest { get; set; }
        public int? SensitiveRef { get; set; }
        public int TimeoutMs { get; set; } = 8000;
    }

    public sealed class FrameProtectionInfo
    {
        public bool HasXFrameOptions { get; init; }
        public bool HasCspFrameAncestors { get; init; }
        public string? XFrameOptions { get; init; }
        public string? CspFrameAncestorsDirective { get; init; }
        public bool MissingProtection { get; init; }
    }

    public sealed class ActiveFrameResult
    {
        public bool Attempted { get; init; }
        public string? TestedUrl { get; init; }
        /// <summary>security-error | cross-origin-loaded | blank-or-blocked | timeout | error</summary>
        public string? FrameOracle { get; init; }
        public bool? CrossOriginFrameLoaded { get; init; }
        public bool? SameOriginFrameLoaded { get; init; }
        public bool LikelyVulnerable { get; init; }
        public string? Detail { get; init; }
        public string? Error { get; init; }
    }

    public sealed class OverlayClickResult
    {
        public bool Attempted { get; init; }
        public int? Ref { get; init; }
        public bool? TargetVisible { get; init; }
        public bool? OverlayFramed { get; init; }
        public string? Detail { get; init; }
    }

    public sealed class UrlTestResult
    {
        public string Url { get; init; } = "";
        public bool IsDocumentBaseline { get; init; }
        public bool IsSensitivePage { get; init; }
        public FrameProtectionInfo FrameProtection { get; init; } = new();
        public List<HeaderFinding> PassiveFindings { get; init; } = [];
        public ActiveFrameResult? Active { get; init; }
        public OverlayClickResult? Overlay { get; init; }
        public bool IsVulnerable
        {
            get
            {
                if (!FrameProtection.MissingProtection)
                    return false;
                if (Active == null || !Active.Attempted)
                    return true;
                if (Active.LikelyVulnerable)
                    return true;
                if (Active.FrameOracle is "blank-or-blocked" or "timeout" or "error")
                    return true;
                return false;
            }
        }
    }

    public sealed class TestResult
    {
        public string DocumentUrl { get; init; } = "";
        public UrlTestResult Document { get; init; } = new();
        public List<UrlTestResult> Sweep { get; init; } = [];
        public bool IsClean =>
            !HasClickjackIssue(Document) && Sweep.All(s => !HasClickjackIssue(s));

        internal static bool HasClickjackIssue(UrlTestResult row)
        {
            if (row.IsVulnerable)
                return true;
            if (!row.FrameProtection.MissingProtection)
                return false;
            if (row.Active is { Attempted: true })
                return row.Active.CrossOriginFrameLoaded != true;
            return true;
        }
        public int IssueCount =>
            (Document.IsVulnerable ? 1 : 0) + Sweep.Count(s => s.IsVulnerable);
    }

    private static readonly string[] SensitiveTokens =
    [
        "login", "signin", "sign-in", "auth", "password", "transfer", "payment",
        "checkout", "admin", "delete", "settings", "account", "profile", "submit"
    ];

    public static FrameProtectionInfo AnalyzeFrameProtection(IReadOnlyDictionary<string, string> headers)
    {
        var normalized = headers.ToDictionary(
            kv => kv.Key.ToLowerInvariant(),
            kv => kv.Value,
            StringComparer.OrdinalIgnoreCase);

        normalized.TryGetValue("x-frame-options", out var xfo);
        normalized.TryGetValue("content-security-policy", out var csp);

        string? faDirective = null;
        if (!string.IsNullOrEmpty(csp))
        {
            var match = Regex.Match(
                csp,
                @"(?i)frame-ancestors\s+([^;]+)",
                RegexOptions.None,
                TimeSpan.FromSeconds(1));
            if (match.Success)
                faDirective = match.Groups[1].Value.Trim();
        }

        var hasXfo = !string.IsNullOrWhiteSpace(xfo);
        var hasFa = !string.IsNullOrWhiteSpace(faDirective);
        var missing = !hasXfo && !hasFa;

        return new FrameProtectionInfo
        {
            HasXFrameOptions = hasXfo,
            HasCspFrameAncestors = hasFa,
            XFrameOptions = xfo,
            CspFrameAncestorsDirective = faDirective,
            MissingProtection = missing
        };
    }

    public static List<HeaderFinding> BuildPassiveFindings(
        string url,
        IReadOnlyDictionary<string, string> headers)
    {
        var findings = new List<HeaderFinding>();
        var protection = AnalyzeFrameProtection(headers);
        if (protection.MissingProtection)
        {
            findings.Add(new HeaderFinding
            {
                Header = "X-Frame-Options",
                Severity = IsSensitivePage(url) ? Severity.High : Severity.Medium,
                Description = "No clickjacking protection. Neither X-Frame-Options nor CSP frame-ancestors is set.",
                Recommendation = "Add: X-Frame-Options: DENY (or use CSP frame-ancestors directive).",
                Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                CurrentValue = null
            });
        }

        return findings;
    }

    public static async Task<TestResult> RunAsync(
        AutomationContext ctx,
        TestOptions options,
        CancellationToken ct = default)
    {
        var documentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(documentUrl))
            throw new InvalidOperationException("Navigate to a page before running clickjack test.");

        var document = await TestUrlAsync(ctx, documentUrl, isBaseline: true, options, ct);
        return new TestResult
        {
            DocumentUrl = documentUrl,
            Document = document
        };
    }

    public static async Task<UrlTestResult> TestUrlAsync(
        AutomationContext ctx,
        string url,
        bool isBaseline,
        TestOptions options,
        CancellationToken ct = default)
    {
        var head = await SecurityProbeHttp.FetchAsync(
            ctx, url, "HEAD", null, null, options.TimeoutMs, includeBrowserCookies: true, ct);
        if (head.Status == 405 || head.Status == 0)
        {
            head = await SecurityProbeHttp.FetchAsync(
                ctx, url, "GET", null, null, options.TimeoutMs, includeBrowserCookies: true, ct);
        }

        var protection = AnalyzeFrameProtection(head.ResponseHeaders);
        var passive = BuildPassiveFindings(url, head.ResponseHeaders);
        var sensitive = IsSensitivePage(url);

        ActiveFrameResult? active = null;
        OverlayClickResult? overlay = null;

        if (options.IncludeActiveTest && protection.MissingProtection)
        {
            active = await RunActiveFrameTestAsync(ctx, url, options.TimeoutMs, ct);
            active = ReconcileActiveWithPassive(active, protection);

            if (options.IncludeSensitiveOverlayTest && sensitive &&
                string.Equals(url, await ctx.GetCurrentUrl(), StringComparison.OrdinalIgnoreCase))
            {
                overlay = await RunOverlayTestAsync(ctx, options.SensitiveRef, options.TimeoutMs, ct);
            }
        }

        return new UrlTestResult
        {
            Url = url,
            IsDocumentBaseline = isBaseline,
            IsSensitivePage = sensitive,
            FrameProtection = protection,
            PassiveFindings = passive,
            Active = active,
            Overlay = overlay
        };
    }

    /// <summary>
    /// When passive headers already allow framing, an opaque/blocked nested oracle must not contradict UI redress risk.
    /// </summary>
    private static ActiveFrameResult? ReconcileActiveWithPassive(
        ActiveFrameResult? active,
        FrameProtectionInfo protection)
    {
        if (active == null || !protection.MissingProtection || active.LikelyVulnerable)
            return active;

        if (active.FrameOracle is "security-error" or "cross-origin-loaded")
        {
            return new ActiveFrameResult
            {
                Attempted = active.Attempted,
                TestedUrl = active.TestedUrl,
                FrameOracle = active.FrameOracle,
                CrossOriginFrameLoaded = true,
                LikelyVulnerable = true,
                Detail = active.Detail,
                Error = active.Error
            };
        }

        if (active.FrameOracle is "blank-or-blocked" or "timeout")
        {
            return new ActiveFrameResult
            {
                Attempted = active.Attempted,
                TestedUrl = active.TestedUrl,
                FrameOracle = "passive-allows-framing",
                CrossOriginFrameLoaded = true,
                LikelyVulnerable = true,
                Detail = (active.Detail ?? "")
                         + " Passive headers allow embedding; opaque iframe could not be inspected — treat as framing risk.",
                Error = active.Error
            };
        }

        return active;
    }

    private static async Task<ActiveFrameResult> RunActiveFrameTestAsync(
        AutomationContext ctx,
        string targetUrl,
        int timeoutMs,
        CancellationToken ct)
    {
        var callbackId = $"__trowser_clickjack_{Guid.NewGuid():N}";
        var escapedTarget = JsonSerializer.Serialize(targetUrl);
        var script = $@"
(function() {{
  var target = {escapedTarget};
  var cb = '{callbackId}';
  window[cb] = {{ done: false }};
  try {{
    var holder = document.createElement('iframe');
    holder.style.cssText = 'position:fixed;width:1px;height:1px;opacity:0;pointer-events:none;left:-9999px;top:-9999px';
    holder.src = 'data:text/html;charset=utf-8,' + encodeURIComponent(
      '<!DOCTYPE html><html><body style=""margin:0""><iframe id=""v"" src=""' + target.replace(/""/g, '&quot;') + '"" style=""width:320px;height:240px""></iframe></body></html>');
    holder.onload = function() {{
      setTimeout(function() {{
        var oracle = 'blank-or-blocked';
        var loaded = false;
        var detail = 'Iframe blocked or empty.';
        try {{
          var inner = holder.contentDocument && holder.contentDocument.getElementById('v');
          if (inner) {{
            try {{
              var href = inner.contentWindow.location.href;
              if (href && href !== 'about:blank') {{
                loaded = true;
                oracle = 'cross-origin-loaded';
                detail = 'Nested iframe navigated (same-origin parent read location).';
              }}
            }} catch (e) {{
              if (e && (e.name === 'SecurityError' || String(e).indexOf('SecurityError') >= 0)) {{
                loaded = true;
                oracle = 'security-error';
                detail = 'Cross-origin frame loaded (location access threw SecurityError).';
              }} else {{
                oracle = 'error';
                detail = String(e);
              }}
            }}
            if (!loaded) {{
              try {{
                var doc = inner.contentDocument;
                if (doc && doc.documentElement && doc.documentElement.innerHTML.length > 0) {{
                  loaded = true;
                  oracle = 'cross-origin-loaded';
                  detail = 'Same-origin nested iframe document readable.';
                }}
              }} catch (e2) {{}}
            }}
          }}
        }} catch (e) {{
          oracle = 'error';
          detail = String(e);
        }}
        window[cb] = {{ done: true, crossOriginFrameLoaded: loaded, frameOracle: oracle, detail: detail }};
      }}, 1200);
    }};
    document.body.appendChild(holder);
    setTimeout(function() {{
      if (!window[cb].done) window[cb] = {{ done: true, crossOriginFrameLoaded: false, error: 'timeout' }};
    }}, {Math.Max(timeoutMs, 3000)});
  }} catch (e) {{
    window[cb] = {{ done: true, crossOriginFrameLoaded: false, error: String(e) }};
  }}
  return 'STARTED';
}})();";

        try
        {
            var start = await ctx.ExecuteJs(script);
            if (start != "STARTED")
            {
                return new ActiveFrameResult
                {
                    Attempted = true,
                    CrossOriginFrameLoaded = null,
                    LikelyVulnerable = false,
                    Error = $"Active framing test failed to start: {start}"
                };
            }

            var deadline = DateTime.UtcNow.AddMilliseconds(Math.Max(timeoutMs, 3000));
            string? json = null;
            while (DateTime.UtcNow < deadline)
            {
                ct.ThrowIfCancellationRequested();
                var raw = await ctx.ExecuteJs($"JSON.stringify(window['{callbackId}'])");
                if (!string.IsNullOrWhiteSpace(raw) && raw != "null" && raw.Contains("\"done\":true"))
                {
                    json = raw;
                    break;
                }

                await Task.Delay(80, ct);
            }

            await ctx.ExecuteJs($"delete window['{callbackId}']; 'OK'");

            if (string.IsNullOrWhiteSpace(json))
            {
                return new ActiveFrameResult
                {
                    Attempted = true,
                    CrossOriginFrameLoaded = null,
                    LikelyVulnerable = false,
                    Error = "Timed out waiting for framing probe."
                };
            }

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var loaded = root.TryGetProperty("crossOriginFrameLoaded", out var p) &&
                           p.ValueKind == JsonValueKind.True;
            var detail = root.TryGetProperty("detail", out var d) ? d.GetString() : null;
            var error = root.TryGetProperty("error", out var e) ? e.GetString() : null;
            var oracle = root.TryGetProperty("frameOracle", out var fo) ? fo.GetString() : null;

            return new ActiveFrameResult
            {
                Attempted = true,
                TestedUrl = targetUrl,
                FrameOracle = oracle,
                CrossOriginFrameLoaded = loaded,
                LikelyVulnerable = loaded,
                Detail = detail,
                Error = error
            };
        }
        catch (Exception ex)
        {
            return new ActiveFrameResult
            {
                Attempted = true,
                LikelyVulnerable = false,
                Error = ex.Message
            };
        }
    }

    private static async Task<OverlayClickResult> RunOverlayTestAsync(
        AutomationContext ctx,
        int? sensitiveRef,
        int timeoutMs,
        CancellationToken ct)
    {
        var refArg = sensitiveRef.HasValue ? sensitiveRef.Value.ToString() : "null";
        var script = $@"
(function() {{
  try {{
    var target = {refArg} != null ? window.__trowserRefs && window.__trowserRefs[{refArg}] : null;
    if (!target) {{
      var candidates = document.querySelectorAll('button, input[type=submit], a[role=button]');
      target = candidates.length ? candidates[0] : null;
    }}
    if (!target) return JSON.stringify({{ attempted: true, detail: 'No interactive target found for overlay test.' }});
    var rect = target.getBoundingClientRect();
    var visible = rect.width > 0 && rect.height > 0;
    var overlay = document.createElement('div');
    overlay.id = '__trowser_clickjack_overlay';
    overlay.style.cssText = 'position:fixed;z-index:2147483646;background:rgba(0,0,0,0.001);pointer-events:auto';
    overlay.style.left = rect.left + 'px';
    overlay.style.top = rect.top + 'px';
    overlay.style.width = rect.width + 'px';
    overlay.style.height = rect.height + 'px';
    document.body.appendChild(overlay);
    return JSON.stringify({{
      attempted: true,
      targetVisible: visible,
      overlayFramed: true,
      detail: 'Transparent overlay placed over interactive control — page lacks frame-ancestors/XFO; UI redress risk on sensitive flow.'
    }});
  }} catch (e) {{
    return JSON.stringify({{ attempted: true, error: String(e) }});
  }}
}})();";

        ct.ThrowIfCancellationRequested();
        var raw = await ctx.ExecuteJs(script);
        try
        {
            using var doc = JsonDocument.Parse(raw ?? "{}");
            var root = doc.RootElement;
            return new OverlayClickResult
            {
                Attempted = true,
                Ref = sensitiveRef,
                TargetVisible = root.TryGetProperty("targetVisible", out var tv) && tv.GetBoolean(),
                OverlayFramed = root.TryGetProperty("overlayFramed", out var of) && of.GetBoolean(),
                Detail = root.TryGetProperty("detail", out var d) ? d.GetString() : null
            };
        }
        catch
        {
            return new OverlayClickResult
            {
                Attempted = true,
                Detail = raw
            };
        }
        finally
        {
            await ctx.ExecuteJs(
                "var o=document.getElementById('__trowser_clickjack_overlay'); if(o) o.remove(); 'OK'");
        }
    }

    internal static bool IsSensitivePage(string url)
    {
        var lower = url.ToLowerInvariant();
        return SensitiveTokens.Any(t => lower.Contains(t, StringComparison.Ordinal));
    }
}
