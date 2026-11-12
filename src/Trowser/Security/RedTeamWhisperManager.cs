using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;
using Trowser.Security.LlmRedTeam;

namespace Trowser.Security;

/// <summary>
/// Generates contextual <b>clues</b> after navigation — for the human tester and for LLM-driven testing.
/// Cheap DOM/network heuristics run on each page; tech-stack and cache identification run once per domain.
/// Does not repeat the same clue in toasts during a session, and skips topics Security Shadow already covers.
/// </summary>
public sealed class RedTeamWhisperManager
{
    /// <summary>Kinds Security Shadow already reports — Whisper must not duplicate them.</summary>
    internal static readonly HashSet<string> ShadowCoveredKinds = new(StringComparer.OrdinalIgnoreCase)
    {
        "csp", "missing-csp", "inline-handlers", "javascript-url", "javascript-links",
        "mixed-content", "cookies", "security-headers", "sensitive-url", "sensitive-query",
        "sql-error", "source-maps", "storage", "xss"
    };

    private readonly object _lock = new();
    private readonly List<string> _lastHints = [];
    private readonly List<WhisperClue> _lastClues = [];
    private readonly List<WhisperClue> _lastNewClues = [];
    private readonly HashSet<string> _seenFingerprints = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _probedHosts = new(StringComparer.OrdinalIgnoreCase);

    public WhisperConfig Config { get; } = new();

    /// <summary>Fired when new (session-unseen) clues are produced.</summary>
    public event Action<IReadOnlyList<WhisperClue>>? CluesGenerated;

    /// <summary>Fired after <see cref="Configure"/> changes enablement or options (GUI, API, MCP).</summary>
    public event Action? ConfigChanged;

    public LlmSurfaceSummary? LastLlmSurface { get; private set; }

    public LlmRedTeamScanResult? LastLlmScan { get; private set; }

    public void Configure(bool enabled, bool? notifyGui = null)
    {
        Config.Enabled = enabled;
        if (notifyGui.HasValue) Config.NotifyGui = notifyGui.Value;
        ConfigChanged?.Invoke();
    }

    /// <summary>Clear session fingerprints so the next visit can toast again (tests / new engagement).</summary>
    public void ResetSession()
    {
        lock (_lock)
        {
            _seenFingerprints.Clear();
            _probedHosts.Clear();
            _lastHints.Clear();
            _lastClues.Clear();
            _lastNewClues.Clear();
            LastLlmSurface = null;
            LastLlmScan = null;
        }
    }

    public IReadOnlyList<string> LastHints
    {
        get { lock (_lock) return _lastHints.ToList(); }
    }

    public IReadOnlyList<WhisperClue> LastClues
    {
        get { lock (_lock) return _lastClues.ToList(); }
    }

    public IReadOnlyList<WhisperClue> LastNewClues
    {
        get { lock (_lock) return _lastNewClues.ToList(); }
    }

    public void UpdateLlmSurface(LlmSurfaceSummary surface)
    {
        lock (_lock)
        {
            LastLlmSurface = surface;
        }
    }

    public void RecordLlmScan(LlmRedTeamScanResult result)
    {
        lock (_lock)
        {
            LastLlmScan = result;
            LastLlmSurface = result.Surface;
        }

        var host = HostFromUrl(result.Surface.Endpoints.FirstOrDefault()?.Url) ?? "_";
        var clues = BuildLlmScanClues(result, host);
        Ingest(clues, replaceLast: false);
    }

    /// <summary>Analyze the current page and optional network log. Runs on UI thread internally.</summary>
    public async Task AnalyzeAsync(WebView2 webView, string pageUrl, NetworkLog? network)
    {
        if (!Config.Enabled) return;
        var core = webView.CoreWebView2;
        if (core == null) return;
        if (!pageUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !pageUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return;

        var host = HostFromUrl(pageUrl) ?? "_";
        var clues = new List<WhisperClue>();

        try
        {
            var dom = await await webView.Dispatcher.InvokeAsync(async () =>
            {
                var raw = await core.ExecuteScriptAsync(WhisperCollectorScript);
                return ParseDomClues(raw, pageUrl, host);
            });
            ApplyChatUiGate(dom, network, pageUrl, host);
            clues.AddRange(dom);
        }
        catch
        {
            return;
        }

        AppendNetworkClues(clues, network, pageUrl, host);
        AppendLlmSurfaceClues(clues, host);

        bool isNewHost;
        lock (_lock)
            isNewHost = !string.IsNullOrEmpty(host) && host != "_" && _probedHosts.Add(host);

        if (isNewHost)
        {
            try
            {
                var domainClues = await CollectDomainCluesAsync(webView, network, pageUrl, host);
                clues.AddRange(domainClues);
            }
            catch
            {
                /* domain checks are optional */
            }
        }

        clues.RemoveAll(c => ShadowCoveredKinds.Contains(c.Kind));
        Ingest(clues, replaceLast: true);
    }

    private void Ingest(List<WhisperClue> clues, bool replaceLast)
    {
        List<WhisperClue> fresh;
        lock (_lock)
        {
            if (replaceLast)
            {
                _lastClues.Clear();
                _lastHints.Clear();
            }

            foreach (var c in clues)
            {
                if (_lastClues.Any(x => x.Fingerprint.Equals(c.Fingerprint, StringComparison.OrdinalIgnoreCase)))
                    continue;
                _lastClues.Add(c);
                _lastHints.Add(c.Title);
            }

            fresh = [];
            foreach (var c in clues)
            {
                if (_seenFingerprints.Add(c.Fingerprint))
                    fresh.Add(c);
            }

            _lastNewClues.Clear();
            _lastNewClues.AddRange(fresh);
        }

        if (fresh.Count > 0)
            CluesGenerated?.Invoke(fresh);
    }

    private async Task<List<WhisperClue>> CollectDomainCluesAsync(
        WebView2 webView, NetworkLog? network, string pageUrl, string host)
    {
        var clues = new List<WhisperClue>();
        if (network == null) return clues;

        var detector = new TechStackDetector(webView, network);
        var stack = await detector.RunAsync();

        if (stack.Detections.Count > 0)
        {
            var names = stack.Detections
                .OrderByDescending(d => d.Confidence)
                .Take(8)
                .Select(d => string.IsNullOrEmpty(d.Version) ? d.Name : $"{d.Name} {d.Version}")
                .ToList();
            var waf = stack.Waf.Select(w => w.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var detail = string.Join("; ", stack.Detections.Take(12).Select(d =>
                $"{d.Name} [{d.Category}] {d.Evidence}"));
            if (waf.Count > 0)
                detail += $". WAF: {string.Join(", ", waf)}";

            clues.Add(new WhisperClue
            {
                Kind = "tech-stack",
                Title = $"Stack on {host}: {string.Join(", ", names.Take(5))}",
                Detail = detail,
                WhyItMatters = waf.Count > 0
                    ? "Known stack plus a WAF — payloads may be filtered; try encoding, alternate verbs, or endpoints the WAF does not sit in front of."
                    : "Knowing the stack tells you which class of bugs (template injection, deserialization, framework debug pages) are worth a closer look.",
                SuggestedNext = "POST /api/security/tech-stack for the full inventory; then pick scanners that match the stack.",
                Url = pageUrl,
                Fingerprint = WhisperClue.MakeFingerprint("tech-stack", host)
            });
        }

        var cache = stack.Cache;
        if (cache.Detected && cache.DocumentStatus != CacheHeaderAnalyzer.DocumentStatusNotCached)
        {
            var vendors = cache.Vendors.Count > 0 ? string.Join(", ", cache.Vendors) : "HTTP cache";
            clues.Add(new WhisperClue
            {
                Kind = "cache",
                Title = $"Cache {cache.DocumentStatus} via {vendors} on {host}",
                Detail = CacheHeaderAnalyzer.FormatEvidence(cache)
                         + (cache.Vary.Count > 0 ? $". Vary: {string.Join(", ", cache.Vary)}" : ""),
                WhyItMatters = cache.DocumentStatus == CacheHeaderAnalyzer.DocumentStatusHit
                    ? "This URL is served from a shared cache. An error or unkeyed header stored here can affect other users."
                    : "A caching layer is in front of this origin — cache key mapping, deception, and live-key error pollution are in play.",
                SuggestedNext = "POST /api/security/cache-map (safe indication), then cache-pollution-scan / cache-poison-scan with safetyMode: active if you intend to confirm.",
                Url = pageUrl,
                Fingerprint = WhisperClue.MakeFingerprint("cache", host)
            });
        }

        return clues;
    }

    private void AppendLlmSurfaceClues(List<WhisperClue> clues, string host)
    {
        LlmSurfaceSummary? surface;
        LlmRedTeamScanResult? scan;
        lock (_lock)
        {
            surface = LastLlmSurface;
            scan = LastLlmScan;
        }

        if (surface == null) return;

        if (surface.ChatWidgetCount > 0)
        {
            clues.Add(new WhisperClue
            {
                Kind = "chat-ui",
                Title = $"Chat UI detected ({surface.ChatWidgetCount} input(s))",
                Detail = $"{surface.ChatWidgetCount} chat-like input(s) on the page.",
                WhyItMatters = "In-page assistants are prompt-injection and data-exfil surfaces, not just UX.",
                SuggestedNext = "POST /api/security/llm-redteam-scan with safetyMode: active after browsing the chat.",
                Fingerprint = WhisperClue.MakeFingerprint("chat-ui", host)
            });
        }

        if (surface.ChatEndpointCount > 0)
        {
            clues.Add(new WhisperClue
            {
                Kind = "llm-api",
                Title = $"LLM API traffic ({surface.ChatEndpointCount} endpoint(s))",
                Detail = $"{surface.ChatEndpointCount} chat/completion-like endpoint(s) in the network log.",
                WhyItMatters = "HTTP adapters are often easier to probe than the chat widget.",
                SuggestedNext = "POST /api/security/llm-endpoint-discover, then llm-redteam-scan.",
                Fingerprint = WhisperClue.MakeFingerprint("llm-api", host)
            });
        }

        if (surface.WebMcpToolCount > 0)
        {
            clues.Add(new WhisperClue
            {
                Kind = "webmcp",
                Title = $"WebMCP tools on page ({surface.WebMcpToolCount})",
                Detail = $"{surface.WebMcpToolCount} tool(s) registered.",
                WhyItMatters = "Tools are excessive-agency / confused-deputy surface.",
                SuggestedNext = "Review tool schemas; llm-redteam-scan runs WebMCP abuse probes.",
                Fingerprint = WhisperClue.MakeFingerprint("webmcp", host)
            });
        }

        if (surface.IframeCopilotCount > 0)
        {
            clues.Add(new WhisperClue
            {
                Kind = "copilot-iframe",
                Title = "Embedded copilot iframe detected",
                Detail = "Chat may be cross-origin.",
                WhyItMatters = "The interesting API is often on another origin than the page you see.",
                SuggestedNext = "Probe the HTTP endpoint from the network log rather than the iframe DOM.",
                Fingerprint = WhisperClue.MakeFingerprint("copilot-iframe", host)
            });
        }

        if (scan != null && scan.HasFindings)
        {
            clues.Add(new WhisperClue
            {
                Kind = "llm-scan-summary",
                Title = $"Last LLM red-team scan: {scan.FiredCount} probe(s) fired",
                Detail = $"Transport: {scan.Transport}; {scan.FiredCount}/{scan.TotalProbes} fired.",
                WhyItMatters = "A fired probe is a lead, not a confirmed vuln — read the matched evidence.",
                SuggestedNext = "Review POST /api/security/llm-redteam-scan findings.",
                Fingerprint = WhisperClue.MakeFingerprint("llm-scan-summary", host)
            });
        }
    }

    private static List<WhisperClue> BuildLlmScanClues(LlmRedTeamScanResult result, string host)
    {
        var clues = new List<WhisperClue>();
        foreach (var f in result.Findings.Take(5))
        {
            clues.Add(new WhisperClue
            {
                Kind = "llm-scan",
                Title = $"LLM red team [{f.Category}]: probe `{f.ProbeId}` fired",
                Detail = $"matched: {f.Matched}",
                WhyItMatters = "The model accepted or reflected an attack-shaped probe.",
                SuggestedNext = "Reproduce with llm-redteam-scan verbose:true and capture the response.",
                Fingerprint = WhisperClue.MakeFingerprint("llm-scan", host, f.ProbeId)
            });
        }

        foreach (var w in result.WebMcpAbuseFindings.Take(3))
        {
            clues.Add(new WhisperClue
            {
                Kind = "webmcp-abuse",
                Title = $"WebMCP abuse: tool `{w.ToolName}` accepted {w.PayloadKind} payload",
                Detail = w.ToolName,
                WhyItMatters = "A tool that accepts unexpected payload kinds can be driven off-policy.",
                Fingerprint = WhisperClue.MakeFingerprint("webmcp-abuse", host, w.ToolName)
            });
        }

        if (result.IndirectInjection?.InjectionObserved == true)
        {
            clues.Add(new WhisperClue
            {
                Kind = "indirect-injection",
                Title = "Indirect injection: planted token appeared in the model response",
                Detail = $"token `{result.IndirectInjection.InjectedToken}`",
                WhyItMatters = "Content the model retrieved later influenced its output.",
                Fingerprint = WhisperClue.MakeFingerprint("indirect-injection", host)
            });
        }

        return clues;
    }

    private static void AppendNetworkClues(List<WhisperClue> clues, NetworkLog? network, string pageUrl, string host)
    {
        if (network == null) return;
        var entries = network.PageEntries;
        if (entries.Count > 60)
            entries = entries.Skip(Math.Max(0, entries.Count - 60)).ToList();

        var graphql = 0;
        var swagger = 0;
        var admin = 0;
        var ws = 0;
        foreach (var e in entries)
        {
            if (e.IsTrowserGenerated) continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u)) continue;
            var pq = u.PathAndQuery;

            if (pq.Contains("/graphql", StringComparison.OrdinalIgnoreCase)
                || pq.Contains("/gql", StringComparison.OrdinalIgnoreCase)
                || e.ContentType.Contains("graphql", StringComparison.OrdinalIgnoreCase))
                graphql++;

            if (pq.Contains("swagger", StringComparison.OrdinalIgnoreCase)
                || pq.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                || pq.Contains("/api-docs", StringComparison.OrdinalIgnoreCase))
                swagger++;

            if (LooksLikeAdminPath(pq))
                admin++;

            if (e.ResourceType.Contains("WebSocket", StringComparison.OrdinalIgnoreCase)
                || pq.Contains("/ws", StringComparison.OrdinalIgnoreCase)
                || pq.Contains("/socket", StringComparison.OrdinalIgnoreCase))
                ws++;
        }

        if (graphql > 0)
        {
            clues.Add(new WhisperClue
            {
                Kind = "graphql",
                Title = $"GraphQL-like traffic ({graphql} request(s))",
                Detail = "Path or content-type looks like GraphQL.",
                WhyItMatters = "Introspection, batching, and nested queries often leak more than the UI shows.",
                SuggestedNext = "POST /api/security/graphql-analyze on a captured operation.",
                Url = pageUrl,
                Fingerprint = WhisperClue.MakeFingerprint("graphql", host)
            });
        }

        if (swagger > 0)
        {
            clues.Add(new WhisperClue
            {
                Kind = "swagger",
                Title = "OpenAPI / Swagger surface in the network log",
                Detail = $"{swagger} swagger/openapi/api-docs-like request(s).",
                WhyItMatters = "Spec files enumerate methods and models the UI never exposes.",
                SuggestedNext = "Open the spec URL, then probe undocumented operations with /api/fetch.",
                Url = pageUrl,
                Fingerprint = WhisperClue.MakeFingerprint("swagger", host)
            });
        }

        if (admin > 0)
        {
            clues.Add(new WhisperClue
            {
                Kind = "admin-path",
                Title = "Admin / debug-style path in network traffic",
                Detail = "Saw /admin, /actuator, /wp-admin, or similar.",
                WhyItMatters = "Management endpoints are high-value if reachable while you are a normal user.",
                SuggestedNext = "Confirm status as the current user vs logged-out; try IDOR on neighboring IDs.",
                Url = pageUrl,
                Fingerprint = WhisperClue.MakeFingerprint("admin-path", host)
            });
        }

        if (ws > 0)
        {
            clues.Add(new WhisperClue
            {
                Kind = "websocket",
                Title = "WebSocket traffic on this page",
                Detail = $"{ws} WebSocket-like request(s).",
                WhyItMatters = "WS channels often skip the authz checks that HTTP APIs have.",
                SuggestedNext = "POST /api/security/websocket-audit; replay a captured message with a tweaked id.",
                Url = pageUrl,
                Fingerprint = WhisperClue.MakeFingerprint("websocket", host)
            });
        }
    }

    private static bool LooksLikeAdminPath(string pathAndQuery)
    {
        return pathAndQuery.Contains("/admin", StringComparison.OrdinalIgnoreCase)
               || pathAndQuery.Contains("/wp-admin", StringComparison.OrdinalIgnoreCase)
               || pathAndQuery.Contains("/actuator", StringComparison.OrdinalIgnoreCase)
               || pathAndQuery.Contains("/debug", StringComparison.OrdinalIgnoreCase)
               || pathAndQuery.Contains("/.git", StringComparison.OrdinalIgnoreCase)
               || pathAndQuery.Contains("/phpmyadmin", StringComparison.OrdinalIgnoreCase)
               || pathAndQuery.Contains("/manager/html", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Keyword-only textareas are not "chat UI". Promote a hint only when the network log
    /// has the same cheap LLM-traffic signal that <c>llm-endpoint-discover</c> uses.
    /// Widget globals already emit <c>chat-ui</c> from the collector.
    /// </summary>
    private static void ApplyChatUiGate(List<WhisperClue> clues, NetworkLog? network, string pageUrl, string host)
    {
        var hints = clues.Where(c => c.Kind == "chat-ui-hint").ToList();
        clues.RemoveAll(c => c.Kind == "chat-ui-hint");
        if (clues.Any(c => c.Kind == "chat-ui") || hints.Count == 0)
            return;
        if (!LlmEndpointDiscovery.HasCorroboratingLlmTraffic(network?.PageEntries))
            return;

        var hint = hints[0];
        var (why, next) = DescribeKind("chat-ui");
        clues.Add(new WhisperClue
        {
            Kind = "chat-ui",
            Title = "Chat UI corroborated by LLM-like network traffic",
            Detail = hint.Detail,
            WhyItMatters = why,
            SuggestedNext = next,
            Url = pageUrl,
            Fingerprint = WhisperClue.MakeFingerprint("chat-ui", host)
        });
    }

    private static List<WhisperClue> ParseDomClues(string raw, string pageUrl, string host)
    {
        var list = new List<WhisperClue>();
        if (string.IsNullOrWhiteSpace(raw) || raw == "null") return list;
        try
        {
            if (raw.StartsWith('"'))
                raw = JsonSerializer.Deserialize<string>(raw) ?? "";
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return list;

            foreach (var el in doc.RootElement.EnumerateArray())
            {
                string kind, title, detail;
                if (el.ValueKind == JsonValueKind.String)
                {
                    title = el.GetString() ?? "";
                    kind = InferKindFromLegacyTitle(title);
                    detail = "";
                }
                else if (el.ValueKind == JsonValueKind.Object)
                {
                    kind = el.TryGetProperty("kind", out var k) ? k.GetString() ?? "" : "";
                    title = el.TryGetProperty("title", out var t) ? t.GetString() ?? "" : "";
                    detail = el.TryGetProperty("detail", out var d) ? d.GetString() ?? "" : "";
                }
                else
                    continue;

                if (string.IsNullOrWhiteSpace(title)) continue;
                if (ShadowCoveredKinds.Contains(kind)) continue;

                var (why, next) = DescribeKind(kind);
                list.Add(new WhisperClue
                {
                    Kind = kind,
                    Title = title,
                    Detail = detail,
                    WhyItMatters = why,
                    SuggestedNext = next,
                    Url = pageUrl,
                    Fingerprint = WhisperClue.MakeFingerprint(kind, host)
                });
            }
        }
        catch
        {
            return list;
        }

        return list;
    }

    private static string InferKindFromLegacyTitle(string title)
    {
        if (title.Contains("GET form with password", StringComparison.OrdinalIgnoreCase))
            return "get-password-form";
        if (title.Contains("hidden input", StringComparison.OrdinalIgnoreCase))
            return "hidden-inputs";
        if (title.Contains("Password field on HTTP", StringComparison.OrdinalIgnoreCase))
            return "password-http";
        if (title.Contains("AI/chat", StringComparison.OrdinalIgnoreCase)
            || title.Contains("Chat widget", StringComparison.OrdinalIgnoreCase)
            || title.Contains("Chat UI corroborated", StringComparison.OrdinalIgnoreCase))
            return "chat-ui";
        if (title.Contains("WebMCP", StringComparison.OrdinalIgnoreCase))
            return "webmcp";
        if (title.Contains("iframe", StringComparison.OrdinalIgnoreCase))
            return "copilot-iframe";
        if (title.Contains("CSP", StringComparison.OrdinalIgnoreCase))
            return "csp";
        if (title.Contains("inline event", StringComparison.OrdinalIgnoreCase))
            return "inline-handlers";
        if (title.Contains("javascript:", StringComparison.OrdinalIgnoreCase))
            return "javascript-url";
        return "dom";
    }

    private static (string why, string? next) DescribeKind(string kind) => kind switch
    {
        "get-password-form" => (
            "GET login puts credentials in the URL, history, Referer, and server logs.",
            "Submit once and inspect the resulting URL plus the network log."),
        "hidden-inputs" => (
            "Hidden fields are a common place for frontend-only access control and price/role values.",
            "Change a hidden value in the Request Editor or DevTools and resubmit."),
        "password-http" => (
            "The password field is on a non-TLS page — credentials are not encrypted in transit.",
            "Confirm the form action is also HTTP; treat as a transport finding."),
        "file-upload" => (
            "Uploads are a classic path to stored XSS, path issues, and parser bugs.",
            "Try an unexpected Content-Type and a polyglot (HTML in a .png) on a throwaway account."),
        "chat-ui" => (
            "In-page assistants are prompt-injection and data-exfil surfaces.",
            "POST /api/security/llm-endpoint-discover to confirm, then llm-redteam-scan with safetyMode: active."),
        "webmcp" => (
            "Registered tools can be abused if the model is steered.",
            "Dump window.__trowserWebMcp.tools and review schemas."),
        "copilot-iframe" => (
            "The interesting API may be on another origin.",
            "Use the network log rather than the iframe DOM."),
        "swagger-ui" => (
            "A spec UI usually means a machine-readable API map is one click away.",
            "Open /swagger.json or /openapi.json and enumerate operations."),
        "debug-banner" => (
            "Debug or framework error chrome often leaks paths, versions, and config.",
            "Copy the page text and look for stack frames or connection strings."),
        _ => ("Worth a closer look while you are already on this page.", null)
    };

    private static string? HostFromUrl(string? url)
    {
        if (string.IsNullOrEmpty(url)) return null;
        return Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.Host : null;
    }

    /// <summary>
    /// In-page collector. Intentionally omits CSP, javascript: URLs, and inline handlers —
    /// Security Shadow already reports those.
    /// </summary>
    private const string WhisperCollectorScript = """
(function(){
  var hints = [];
  function add(kind, title, detail) {
    hints.push({ kind: kind, title: title, detail: detail || '' });
  }
  try {
    var forms = document.querySelectorAll('form');
    for (var i = 0; i < forms.length; i++) {
      var f = forms[i];
      var m = (f.method || 'get').toLowerCase();
      if (m === 'get' && f.querySelector('input[type="password"]')) {
        add('get-password-form',
            'GET form with password field — credentials may appear in URL and server logs.',
            'action=' + (f.getAttribute('action') || location.pathname));
        break;
      }
    }
    var hid = document.querySelectorAll('input[type="hidden"]').length;
    if (hid > 5) {
      add('hidden-inputs',
          'Many hidden inputs (' + hid + ') — try tampering values before submit (frontend-only checks?).',
          hid + ' hidden input(s)');
    }
    var pwd = document.querySelectorAll('input[type="password"]').length;
    if (pwd > 0 && location.protocol === 'http:') {
      add('password-http', 'Password field on HTTP — credentials are not encrypted in transit.', location.href);
    }
    var files = document.querySelectorAll('input[type="file"]').length;
    if (files > 0) {
      add('file-upload', 'File upload control on this page (' + files + ').', files + ' file input(s)');
    }
    function chatFieldText(el) {
      var t = ((el.id || '') + ' ' + (el.getAttribute('name') || '') + ' ' +
        (el.placeholder || '') + ' ' + (el.getAttribute('aria-label') || '') + ' ' +
        (el.getAttribute('data-testid') || '') + ' ' + (el.getAttribute('label') || '')).toLowerCase();
      try {
        if (el.id && window.CSS && CSS.escape) {
          var lab = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
          if (lab) t += ' ' + (lab.textContent || '').toLowerCase();
        }
        if (el.labels) {
          for (var li = 0; li < el.labels.length; li++)
            t += ' ' + (el.labels[li].textContent || '').toLowerCase();
        }
      } catch (e) {}
      return t;
    }
    function isCommentLikeField(el, t) {
      if (/comment|feedback|review|kommentar|anteckning|notering|internal[-_\s]?note/.test(t))
        return true;
      return !!el.closest('[class*="comment"],[id*="comment"],[class*="feedback"],[id*="feedback"]');
    }
    function hasChatKeyword(t) {
      return /\b(ask|chat|copilot|prompt|assistant|question)\b/.test(t)
        || /\bai\b/.test(t)
        || /how can i help|type your message|message chatgpt|ask anything/.test(t);
    }
    function detectChatGlobals() {
      var names = [];
      try {
        if (window.Intercom) names.push('Intercom');
        if (window.drift || window.driftt) names.push('Drift');
        if (window.$crisp) names.push('Crisp');
        if (window.zE || window.zEmbed) names.push('Zendesk');
        if (window.tidioChatApi) names.push('Tidio');
        if (window.HubSpotConversations) names.push('HubSpot');
        if (window.LiveChatWidget) names.push('LiveChat');
        if (window.botpressWebChat || window.botpress) names.push('Botpress');
        if (window.Kommunicate) names.push('Kommunicate');
        if (window.Tawk_API) names.push('Tawk');
      } catch (e) {}
      return names;
    }
    var chatGlobals = detectChatGlobals();
    var chatInputs = document.querySelectorAll('textarea,[contenteditable="true"],input[type="text"]');
    var aiInputs = 0;
    for (var j = 0; j < chatInputs.length; j++) {
      var el = chatInputs[j];
      var t = chatFieldText(el);
      if (isCommentLikeField(el, t)) continue;
      if (hasChatKeyword(t)) aiInputs++;
      else if (el.closest('[class*="copilot"],[data-testid*="chat"],[class*="assistant"],[class*="chat"],[id*="chat"]'))
        aiInputs++;
    }
    if (chatGlobals.length) {
      add('chat-ui', 'Chat widget detected (' + chatGlobals.join(', ') + ').',
          chatGlobals.join(', ') + (aiInputs ? '; ' + aiInputs + ' chat-like input(s)' : ''));
    } else if (aiInputs > 0) {
      add('chat-ui-hint', 'Possible chat-like input (' + aiInputs + ') — unconfirmed.',
          aiInputs + ' chat-like input(s)');
    }
    var wm = window.__trowserWebMcp && window.__trowserWebMcp.tools;
    if (wm) {
      var n = 0; for (var k in wm) n++;
      if (n > 0) add('webmcp', 'WebMCP tools registered (' + n + ').', n + ' tool(s)');
    }
    var ifr = document.querySelectorAll('iframe[src*="chat"],iframe[src*="copilot"],iframe[title*="chat" i]');
    if (ifr.length) add('copilot-iframe', 'Embedded chat/copilot iframe(s).', ifr.length + ' iframe(s)');
    if (document.querySelector('.swagger-ui, #swagger-ui, redoc, [id*="swagger"]')) {
      add('swagger-ui', 'Swagger / OpenAPI UI on this page.', location.pathname);
    }
    var bodyText = (document.body && document.body.innerText || '').slice(0, 2000);
    if (/Whitelabel Error Page|Django Debug|Traceback \(most recent call last\)|Spring Boot|Xdebug/i.test(bodyText)
        || document.querySelector('[class*="debug-toolbar"], #djDebug')) {
      add('debug-banner', 'Framework debug / error chrome visible on the page.', 'Look at the page text for stack frames.');
    }
  } catch (e) { }
  return JSON.stringify(hints);
})();
""";
}
