using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Windows.Threading;
using System.Xml.Linq;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Orchestration.Rendering;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.Seo;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    #region GET Handlers

    private async Task HandleGetInfo(HttpListenerResponse response)
    {
        var url = await _context.GetCurrentUrl();
        var title = await _context.GetTitle();
        var guard = _context.NavigationGuard;
        await WriteSuccess(response, new
        {
            version = App.Version,
            port = _port,
            sessionName = SessionName,
            currentUrl = url,
            currentTitle = title,
            navigationScope = guard?.Scope ?? "*.*",
            navigationRestricted = guard?.IsRestricted ?? false,
            safeMode = SafeMode,
            externalMcpMode = McpClientConfig.FormatMode(ExternalMcpMode),
            authenticated = ApiKeyRequired && !string.IsNullOrEmpty(_apiKey),
            assertionCount = _context.Assert.TotalCount,
            consoleEntryCount = _context.Console.Count,
            networkEntryCount = _context.Network.Count,
            tabCount = _context.GetTabCount(),
            activeTab = _context.GetActiveTabIndex()
        });
    }

    private async Task HandleGetHelp(HttpListenerResponse response)
    {
        await WriteSuccess(response, new
        {
            message = "Trowser LLM API -- control a running Trowser browser instance.",
            endpoints = new object[]
            {
                new { method = "GET", path = "/api/ping", description = "Health check (always responds, even when browser is busy). Returns busy status and current operation." },
                new { method = "POST", path = "/api/abort", description = "Force-cancel the current operation and return server to idle (bypasses gate, works when busy)" },
                new { method = "POST", path = "/api/force-navigate", description = "Recover frozen page: { \"url\": \"about:blank\", \"terminateScripts\": true } — CDP Runtime.terminateExecution + Page.navigate; bypasses gate; cancels stuck operation" },
                new { method = "GET", path = "/api/info", description = "Server and page info" },
                new { method = "GET", path = "/api/state", description = "Full page state (URL, title, headings, frames, interactive elements, errors). Query: ?limit=150 (default cap; ?fullElements=true or ?limit=0 for all), ?format=compact, ?q=, ?tag=, ?type=, ?selector=CSS, ?frame=, ?visible=false" },
                new { method = "GET", path = "/api/frames", description = "List iframes: frameId, name, url, sameOrigin, parentFrameId" },
                new { method = "POST", path = "/api/state/enrich", description = "Batch-fetch text/attributes for refs: { \"refs\": [0,1,2], \"fields\": [\"text\",\"href\",\"type\",\"name\",\"id\",\"class\",\"required\",\"maxLength\",...] }" },
                new { method = "POST", path = "/api/diff-state", description = "Diff two stored snapshots: { \"before\": N, \"after\": M } refGeneration from GET /api/state — elements added/removed, text/value changes, URL/title, new console/network errors" },
                new { method = "POST", path = "/api/state/refresh", description = "Force full page state rescan after DOM mutations. Returns same data as GET /api/state with refreshed:true" },
                new { method = "GET", path = "/api/screenshot", description = "Capture screenshot. Query params: ?base64=true" },
                new { method = "GET", path = "/api/interactive", description = "All interactive elements with selectors and ref numbers" },
                new { method = "GET", path = "/api/console", description = "Browser console messages" },
                new { method = "POST", path = "/api/console/clear", description = "Clear console log" },
                new { method = "GET", path = "/api/network", description = "Network traffic log. Query: ?errors=true, ?url=X, ?method=GET, ?status=404, ?statusRange=500-599, ?type=Script, ?limit=N|?last=N, ?summary=true, ?includeBody, ?includeHeaders, ?id=N. One full entry: GET /api/network/{id}" },
                new { method = "GET", path = "/api/network/{id}", description = "One captured network entry by id, with request/response headers and any captured body. Query: ?includeBody=false, ?includeHeaders=false, ?responseBodyOffset, ?responseBodyLimit, ?maxUrlChars, ?tabIndex, ?urlMatch" },
                new { method = "GET", path = "/api/network/har", description = "Export network log as HAR 1.2 JSON. Query: ?includeBody=true, ?url=, ?method=, ?errors=true, ?page=true, ?path=file" },
                new { method = "POST", path = "/api/network/clear", description = "Clear network log" },
                new { method = "GET", path = "/api/downloads", description = "List captured downloads (id, url, suggestedFileName, path, state, bytes, mime)" },
                new { method = "POST", path = "/api/downloads/wait", description = "Wait until download completed + file on disk: { \"fileNameContains\": \"report\", \"timeout\": 30000, \"afterId\": 0 }" },
                new { method = "POST", path = "/api/downloads/assert", description = "Assert download: { \"fileNameContains\", \"mime\", \"minBytes\", \"exists\" }" },
                new { method = "POST", path = "/api/downloads/clear", description = "Clear download log: { \"deleteFiles\": false }" },
                new { method = "POST", path = "/api/clear-all", description = "Reset all test state: console, network, cookies, mocks, intercepts, assertions, throttle, viewport, emulation, downloads, trace, storage. Optional body: { \"preserve\": [\"cookies\", \"storage\"] }" },
                new { method = "POST", path = "/api/clear-session", description = "Lighter reset: clears test artifacts (console, network, assertions, mocks, intercepts, throttle, viewport, emulation); preserves cookies/storage unless clearCookies:true" },
                new { method = "GET", path = "/api/assertions", description = "Current test assertion results" },
                new { method = "GET", path = "/api/page-text", description = "All visible page text (document.body.innerText)" },
                new { method = "GET", path = "/api/page-text/all", description = "All text nodes including hidden/off-screen + shadow DOM; one line per text node" },
                new { method = "GET", path = "/api/page-text/screen-reader", description = "Screen reader strings: alt, aria-label, aria-labelledby/by, title, SVG title/desc + shadow" },
                new { method = "GET", path = "/api/source", description = "Full page HTML source (document.documentElement.outerHTML)" },
                new { method = "POST", path = "/api/navigate", description = "Navigate: { \"url\": \"...\" } or session history { \"action\": \"back\" | \"forward\" } (CDP)" },
                new { method = "POST", path = "/api/go-back", description = "Navigate back in history (same as navigate with action back)" },
                new { method = "POST", path = "/api/go-forward", description = "Navigate forward in history (same as navigate with action forward)" },
                new { method = "POST", path = "/api/click", description = "Click element: { \"ref\": N, \"frame\": \"child\", \"button\": \"left|right|middle\", \"clickCount\": 1|2 }" },
                new { method = "POST", path = "/api/click-at", description = "CDP click at viewport x/y (CSS px); hits painted targets including cross-origin iframes" },
                new { method = "POST", path = "/api/drag", description = "Drag: { \"from\": {\"ref\":N}, \"to\": {\"selector\":\"#dst\"}, \"steps\": 10, \"frame\": \"optional\" }" },
                new { method = "POST", path = "/api/type", description = "Type into element: { \"ref\": N, \"text\": \"...\" } or { \"ref\": N, \"value\": \"...\" } (value=content alias) or { \"selector\": \"...\", \"text\": \"...\", \"html\": \"<b>rich</b>\" }. 400 if no text/value/html." },
                new { method = "POST", path = "/api/upload", description = "File input: { \"ref\": N | selector..., \"path\": \"C:\\\\full\\\\path\" | \"paths\": [...], or \"base64\" + \"fileName\", optional \"submit\": true }" },
                new { method = "POST", path = "/api/select", description = "Select dropdown: { \"ref\": N, \"value\": \"...\" } or { \"selector\": \"...\", \"value\": \"...\" }" },
                new { method = "POST", path = "/api/find", description = "Search visible page text: { \"text\": \"...\", \"caseSensitive\": false, \"regex\": false, \"scrollTo\": 0, \"highlight\": true }" },
                new { method = "POST", path = "/api/find/clear", description = "Remove find highlights from the page" },
                new { method = "POST", path = "/api/text", description = "Get element text: { \"ref\": N } or { \"selector\": \"...\" }. Multi-extract: { \"targets\", \"selectors\", \"patterns\" }. patterns: string = label (line slice after label), or { \"name\"|\"key\", \"regex\", \"group\"? (default 0) }, or { \"name\", \"label\" } without regex. \"values\" includes every key with null on failure (missed regex, bad selector, etc.). POST /api/extract-text is the same handler." },
                new { method = "POST", path = "/api/extract-text", description = "Alias for POST /api/text multi-extract (targets / selectors / patterns)." },
                new { method = "POST", path = "/api/attribute", description = "Get element attribute: { \"ref\": N, \"attribute\": \"...\" }" },
                new { method = "POST", path = "/api/property", description = "Get element DOM property (live value): { \"ref\": N, \"property\": \"value\" }" },
                new { method = "POST", path = "/api/hover", description = "Hover over element: { \"ref\": N } or { \"selector\": \"...\" }" },
                new { method = "POST", path = "/api/scroll", description = "Scroll page/element: { \"direction\": \"down\" } or { \"ref\": N, \"scrollIntoView\": true }" },
                new { method = "POST", path = "/api/execute-js", description = "Execute JavaScript: { \"script\": \"...\", \"frame\": \"optional frameId/name\", \"timeout\": 30000 }. Awaits Promises; multi-statement scripts auto-return last expression; prefer /api/fetch for HTTP." },
                new { method = "POST", path = "/api/execute-script", description = "Execute C# test script: { \"code\": \"...\" }" },
                new { method = "POST", path = "/api/record/start", description = "Start interaction recording to a temp .csx (human DOM actions). 409 if already recording." },
                new { method = "GET", path = "/api/record/status", description = "Recording status: { recording, startUrl, startedAt, actionCount }" },
                new { method = "POST", path = "/api/record/stop", description = "Stop recording: { description?, toJournal?, path? }. Returns script + narration. path writes .csx via ExportPathGuard (blocked in --safe)." },
                new { method = "POST", path = "/api/wait", description = "Wait for element: { \"selector\": \"...\", \"timeout\": 10000 }" },
                new { method = "POST", path = "/api/wait-for-navigation", description = "Wait for page navigation: { \"timeout\": 10000 }" },
                new { method = "POST", path = "/api/wait-for-final-navigation", description = "Wait for redirect chain to settle: { \"quietPeriod\": 500, \"timeout\": 15000 }" },
                new { method = "POST", path = "/api/wait-for-idle", description = "Wait for network quiet + no CSS animations: { \"quietPeriod\": 500, \"timeout\": 10000 }" },
                new { method = "POST", path = "/api/accessibility", description = "Run WCAG audit: { \"level\": \"AA\" }" },
                new { method = "POST", path = "/api/tab-order", description = "Verify keyboard tab order (real Tab/Shift+Tab): { \"selector\": \"#main\", \"expectedOrder\": [\"Email\", \"Password\"] }" },
                new { method = "POST", path = "/api/performance", description = "Measure Web Vitals performance: Core Web Vitals, navigation timing, resource summary" },
                new { method = "POST", path = "/api/resource/snapshot", description = "Resource snapshot: JS heap, DOM nodes, event listeners, open WebSockets (CDP). Passive. Optional rememberBaseline: true for a follow-up compare." },
                new { method = "POST", path = "/api/resource/compare", description = "Compare a saved baseline to current page after your own actions. Pass baseline from snapshot, or useRememberedBaseline: true. Passive." },
                new { method = "POST", path = "/api/resource/probe", description = "Resource leak probe: baseline → repeat actions or reloads → GC → compare. Returns findings with severity. Click/type actions require safetyMode: active." },
                new { method = "POST", path = "/api/security", description = "Passive security overview (Quicktests → 1 Security Scan modules): tech stack, CVEs, headers, CORS, XSS, cookies, storage, methods, discover" },
                new { method = "POST", path = "/api/security/js-libraries", description = "Retire.js scan for known vulnerable JavaScript library versions on the current page" },
                new { method = "POST", path = "/api/security/headers", description = "Analyze HTTP response headers for security misconfigurations (OWASP)" },
                new { method = "POST", path = "/api/validate-html", description = "Validate HTML markup using html-validate" },
                new { method = "POST", path = "/api/seo", description = "SEO audit: title, meta description, robots, canonical, OG/Twitter tags, hreflang, JSON-LD, h1 count" },
                new { method = "POST", path = "/api/compatibility", description = "Analyze JavaScript for backward compatibility with older browsers (iOS 15, Android 10)" },
                new { method = "POST", path = "/api/audit-all", description = "Full page health: accessibility, performance, security (CVE + XSS + mixed content), security/headers, validate-html, SEO, compatibility, check-links, consistency. Optional body merges all per-endpoint options." },
                new { method = "POST", path = "/api/quicktest", description = "Alias for POST /api/audit-all — combined audits in a single round-trip." },
                new { method = "POST", path = "/api/surpriseme", description = "Run a random non-destructive quicktest from the embedded catalog. Returns quicktest name and assertion summary." },
                new { method = "POST", path = "/api/check-links", description = "Check links for broken URLs: { \"scope\": \"anchors\", \"external\": true, \"timeoutMs\": 5000, \"concurrency\": 10 }" },
                new { method = "POST", path = "/api/security/xss", description = "DOM XSS audit: inline handlers, javascript: URLs, dangerous sinks, cross-domain scripts" },
                new { method = "POST", path = "/api/security/mixed-content", description = "Mixed content audit: detect HTTP resources on HTTPS pages (scripts, images, stylesheets)" },
                new { method = "POST", path = "/api/security/cookies", description = "Cookie security audit: Secure, HttpOnly, SameSite, domain scoping, lifetime" },
                new { method = "POST", path = "/api/security/path-traversal", description = "Path traversal probes on GET query params (network log or explicit urls). Requires safetyMode: active" },
                new { method = "POST", path = "/api/security/ssrf-scan", description = "SSRF scanner: injects internal IPs, cloud metadata URLs, protocol handlers, and callback probe URLs into URL-like parameters from network log or explicit request template. Correlates Tier 1 client-side OOB callbacks. Requires safetyMode: active" },
                new { method = "POST", path = "/api/security/ssrf-orchestrator", description = "SSRF orchestrator: scaffold paths + ssrf-scan + open-redirect escalation + jwt-header-abuse + callback poll + chain-analyze. Requires safetyMode: active" },
                new { method = "POST", path = "/api/security/open-redirect-scan", description = "Open redirect scanner (CWE-601): probes redirect/url/next parameters with external URLs using redirect:manual and checks Location header for off-site redirects. Requires safetyMode: active" },
                new { method = "POST", path = "/api/security/storage", description = "Web storage security audit: tokens, PII, JWTs, HTML/XSS risk in localStorage/sessionStorage" },
                new { method = "POST", path = "/api/security/source-maps", description = "Source map & debug mode audit: sourceMappingURL refs, accessible .map files, Angular/React/Vue debug indicators" },
                new { method = "POST", path = "/api/security/tech-stack", description = "Tech stack fingerprinting: servers, frameworks, JS libraries, WAFs, CDNs, CMSes from headers, cookies, DOM, and script analysis. No params needed." },
                new { method = "POST", path = "/api/security/js-audit", description = "Fetch page script[src] assets and heuristically scan for hardcoded creds, internal URLs, debug/tuning flags (complements source-maps). Requires safetyMode: active" },
                new { method = "POST", path = "/api/security/mass-assignment-scan", description = "Mass-assignment probe: re-sends a JSON or form-urlencoded body with privileged fields and checks whether the value is echoed or newly persisted. Requires safetyMode: active" },
                new { method = "POST", path = "/api/security/auto-scan", description = "Automated scan pipeline: runs attack-surface then targeted scanners (SQLi, IDOR, CSRF, path-traversal, SSRF, open-redirect, SSTI, mass-assignment) against discovered endpoints. Requires safetyMode: active" },
                new { method = "POST", path = "/api/security/secrets-harvest", description = "Unified secret/credential harvesting: JS bundles, cookies, storage, network responses, network request headers (Bearer tokens, API keys), page text, source maps. Requires safetyMode: active" },
                new { method = "POST", path = "/api/security/oidc-analyze", description = "OIDC provider security analysis: fetches .well-known/openid-configuration, flags dangerous grant types (implicit, password), weak PKCE, admin/financial scopes, test authenticators, signing algorithms, dynamic registration, and probes all discovered endpoints. Auto-detects issuer from network log. With testGrantTypes: true, actively probes token endpoint with detected client IDs to verify dangerous grant types are usable (not just advertised)." },
                new { method = "POST", path = "/api/security/oauth-flow-test", description = "OAuth2/OIDC authorization-flow testing: passive analysis of captured authorize/callback traffic (state, PKCE, fragment tokens, mix-up, referrer/window.opener leaks) plus active probes (redirect_uri manipulation, state/PKCE/scope/response_type tampering, stolen-code token exchange). Auto-detects from network log. passiveOnly skips active probes; otherwise requires safetyMode: active." },
                new { method = "POST", path = "/api/security/graphql-analyze", description = "GraphQL endpoint security analysis: introspection test, mutation/subscription discovery, query batching, alias amplification, depth limit probing, max limit testing, draft/preview access, field suggestion exploitation, rate limit extraction. Requires safetyMode: active" },
                new { method = "POST", path = "/api/page-text/structured", description = "Extract structured text: headings, paragraphs, links, buttons, labels, images, word count" },
                new { method = "POST", path = "/api/consistency", description = "GUI consistency audit: fonts, colors, sizing, spacing" },
                new { method = "POST", path = "/api/third-party", description = "Third-party resource inventory: external scripts, stylesheets, iframes, fonts, SRI coverage" },
                new { method = "POST", path = "/api/security/supply-chain-scan", description = "Supply chain scan: Retire.js, third-party/SRI, manifest fetch + OSV.dev, CI/CD exposure, JS bundle fingerprinting, Retire+OSV cross-check, optional CVE reachability PoCs. safetyMode: active required for includeCveReachability." },
                new { method = "POST", path = "/api/security/osv-check", description = "OSV enrichment for a raw manifest body (JSON, lockfile, requirements.txt, etc.) without web fetch. Body: { manifest, fileName, ecosystem?, maxPackages? }." },
                new { method = "POST", path = "/api/monkey-test", description = "Run monkey testing for robustness (gremlins.js). Requires safetyMode: active — may trigger server-side actions." },
                new { method = "POST", path = "/api/monkey-trowser", description = "Run Monkey Trowser smart robustness test. Optional \"scope\" or auto-scope from current page when unset. Requires safetyMode: active — may trigger server-side actions." },
                new { method = "POST", path = "/api/settings/scope", description = "Set navigation scope programmatically: { \"scope\": \"https://*.example.com/*\" } (same as Settings / --scope)." },
                new { method = "GET", path = "/api/settings/throttle", description = "Get API request pacing: maxRequestsPerSecond, delayBetweenNavigations (0 = off)." },
                new { method = "POST", path = "/api/settings/throttle", description = "Set request pacing to reduce WAF/bot blocks: { \"maxRequestsPerSecond\": 2, \"delayBetweenNavigations\": 3000 } — min gap between API ops and extra pad before navigation endpoints." },
                new { method = "POST", path = "/api/interrupter", description = "Run TrowserInterrupter fault-injection test: auto-discovers APIs (including form POSTs), injects faults, reloads, checks for failures (console errors, content changes, error pages). Supports customFaults, actions (interaction replay), waitForIdle. Requires safetyMode: active." },
                new { method = "POST", path = "/api/attack-form", description = "Adaptive form attack ('Attack this form'): inspects the live page to discover the editable fields wired to a form/submit control, infers each field's semantic type, and probes for client-side validation gaps (unenforced required/pattern/min/max, email/number/date fields built as plain text, unbounded length). Body: { target?, submit?, maxFields?, perField? }. target is a CSS/semantic selector for a form, submit button, or field (default: primary form). submit=true also replays the form server-side (flags 5xx, stack traces, reflected XSS) and requires safetyMode: active." },
                new { method = "POST", path = "/api/assert/page-contains", description = "Assert page contains text: { \"text\": \"...\", \"message\": \"...\" }" },
                new { method = "POST", path = "/api/assert/page-not-contains", description = "Assert page does not contain text: { \"text\": \"...\", \"message\": \"...\" }" },
                new { method = "POST", path = "/api/assert/element-visible", description = "Assert element is visible: { \"ref\": N } or { \"selector\": \"...\" }" },
                new { method = "POST", path = "/api/assert/element-not-visible", description = "Assert element is not visible: { \"ref\": N } or { \"selector\": \"...\" }" },
                new { method = "POST", path = "/api/assert/element-text", description = "Assert element text equals: { \"ref\": N, \"expected\": \"...\" }" },
                new { method = "POST", path = "/api/assert/element-text-batch", description = "Assert many element texts in one call: { \"assertions\": [{ \"selector\": \"#id\", \"expected\": \"5\", \"contains?\": false, \"message?\": \"...\", \"timeout?\": ms }], \"timeout?\": default ms }" },
                new { method = "POST", path = "/api/assert/element-contains-text", description = "Assert element text contains: { \"ref\": N, \"expected\": \"...\" }" },
                new { method = "POST", path = "/api/assert/element-attribute", description = "Assert element attribute: { \"ref\": N, \"attribute\": \"...\", \"expected\": \"...\" }" },
                new { method = "POST", path = "/api/assert/url", description = "Assert URL contains: { \"expected\": \"...\" }" },
                new { method = "POST", path = "/api/assert/title", description = "Assert page title contains: { \"expected\": \"...\" }" },
                new { method = "POST", path = "/api/assert/element-count", description = "Assert element count: { \"selector\": \"...\", \"expected\": N }" },
                new { method = "POST", path = "/api/assert/reset", description = "Reset all assertion results" },
                new { method = "POST", path = "/api/batch", description = "Execute multiple actions: { \"actions\": [{\"action\":\"click\",\"ref\":5},{\"action\":\"text\",\"ref\":3}] }" },
                new { method = "POST", path = "/api/test-scenario", description = "Run a sequence of API calls in-process (one round-trip): { \"steps\": [{ \"method\", \"path\", \"query?\", \"body?\", \"capture?\": { \"varName\": \"data.path\" }, \"assert?\": { \"data.text\": \"expected\" } | [{ \"path\": \"data.x\", \"equals\"|\"expected\": \"...\", \"contains?\": bool }] }], \"file?\", \"stopOnError?\", \"maxSteps?\" }. Same JSON can be saved as a .trw file." },
                new { method = "POST", path = "/api/key", description = "Send keyboard key: { \"key\": \"Tab\" } or { \"key\": \"Enter\", \"ref\": 5, \"modifiers\": [\"Shift\"] }" },
                new { method = "GET", path = "/api/cookies", description = "Get all cookies for current URL. Query params: ?name=sessionId" },
                new { method = "POST", path = "/api/cookies/set", description = "Set cookie: { \"name\": \"x\", \"value\": \"v\", \"domain\": \".example.com\", \"secure\": true, \"sameSite\": \"Lax\" }" },
                new { method = "POST", path = "/api/cookies/delete", description = "Delete cookie: { \"name\": \"x\", \"domain\": \".example.com\", \"path\": \"/\" }" },
                new { method = "POST", path = "/api/cookies/clear", description = "Delete all cookies" },
                new { method = "GET", path = "/api/mock", description = "List active mock rules" },
                new { method = "POST", path = "/api/mock", description = "Add mock: { \"urlPattern\": \"*/api/users*\", \"status\": 500, \"body\": \"{...}\", \"delay\": 2000 }" },
                new { method = "POST", path = "/api/mock/remove", description = "Remove mock: { \"urlPattern\": \"*/api/users*\" }" },
                new { method = "POST", path = "/api/mock/clear", description = "Clear all mock rules" },
                new { method = "GET", path = "/api/intercept", description = "List intercept (breakpoint) rules and pending requests" },
                new { method = "POST", path = "/api/intercept", description = "Add breakpoint: { \"urlPattern\": \"regex\", \"method\": \"GET\" }" },
                new { method = "POST", path = "/api/intercept/remove", description = "Remove breakpoint: { \"urlPattern\": \"regex\" }" },
                new { method = "POST", path = "/api/intercept/clear", description = "Clear all breakpoints and release pending requests" },
                new { method = "POST", path = "/api/intercept/continue", description = "Continue a pending request: { \"requestId\": 1, \"url\": \"...\", \"method\": \"...\", \"headers\": {} }" },
                new { method = "POST", path = "/api/intercept/fulfill", description = "Fulfill with custom response: { \"requestId\": 1, \"status\": 200, \"body\": \"...\", \"headers\": {} }" },
                new { method = "POST", path = "/api/intercept/abort", description = "Abort a pending request: { \"requestId\": 1 }" },
                new { method = "POST", path = "/api/intercept/replay", description = "Replay a pending request N times concurrently: { \"requestId\": 1, \"concurrency\": 10 }" },
                new { method = "POST", path = "/api/load-test", description = "Fire a request N times concurrently: { \"url\": \"...\", \"method\": \"GET\", \"concurrency\": 10, \"useBrowserCookies\": true }" },
                new { method = "POST", path = "/api/fetch", description = "Send HTTP request from browser context (includes cookies/auth): { \"url\": \"...\", \"method\": \"POST\", \"headers\": {}, \"body\": \"...\", \"json\": {} }" },
                new { method = "POST", path = "/api/fetch/batch", description = "Multiple fetch() calls in parallel or sequence: { \"requests\": [{ \"url\", \"method\", \"headers\", \"body\"|\"json\" }], \"concurrent\": true }" },
                new { method = "GET", path = "/api/viewport", description = "Get current viewport size and available presets" },
                new { method = "POST", path = "/api/viewport", description = "Set viewport: { \"width\": 390, \"height\": 844 } or { \"preset\": \"SmallPhone\" }. Presets: SmallPhone (320×568), BigPhone (412×915), LandscapePhone (844×390), SmallPad (768×1024), BigPad (1024×1366), Desktop (full screen), BigDesktop (1920×1080)" },
                new { method = "GET", path = "/api/emulation", description = "Get environment overrides (geolocation, locale, timezone, colorScheme, reducedMotion, userAgent, permissions)" },
                new { method = "POST", path = "/api/emulation", description = "Set environment overrides: { \"geolocation\": {\"latitude\":59.3,\"longitude\":18.0}, \"locale\": \"sv-SE\", \"timezone\": \"Europe/Stockholm\", \"colorScheme\": \"dark\" }" },
                new { method = "DELETE", path = "/api/emulation", description = "Clear all environment overrides" },
                new { method = "POST", path = "/api/trace/start", description = "Start action timeline: { \"domSnapshots\": false, \"maxSteps\": 200 }" },
                new { method = "POST", path = "/api/trace/stop", description = "Stop action timeline recording" },
                new { method = "GET", path = "/api/trace", description = "Get action timeline steps" },
                new { method = "GET", path = "/api/trace/export", description = "Export action timeline JSON" },
                new { method = "GET", path = "/api/screen-curtain", description = "Get screen curtain state: { \"enabled\": true|false } — black overlay hiding page visuals for blind/screen-reader testing" },
                new { method = "POST", path = "/api/screen-curtain", description = "Set or toggle screen curtain: { \"enabled\": true|false } or { \"toggle\": true }. Same as Ctrl+B in the GUI." },
                new { method = "GET", path = "/api/tabs", description = "List all open tabs with index, id, title, URL, isActive, and owner (human|agent|shared)" },
                new { method = "POST", path = "/api/tabs/new", description = "Open a new tab: { \"url\": \"...\", \"owner\": \"human|agent|shared\" }. Agent-owned by default. Switches to the new tab." },
                new { method = "POST", path = "/api/tabs/close", description = "Close a tab: { \"tabIndex\": N } (required; \"index\" accepted as alias)" },
                new { method = "POST", path = "/api/tabs/switch", description = "Switch active tab: { \"tabIndex\": N }" },
                new { method = "GET", path = "/api/dialog", description = "Get the most recent native dialog (alert/confirm/prompt)" },
                new { method = "POST", path = "/api/dialog/handle", description = "Configure dialog handling: { \"accept\": true/false, \"promptText\": \"...\" }" },
                new { method = "POST", path = "/api/dialog/dismiss", description = "Clear the last dialog record" },
                new { method = "POST", path = "/mcp", description = "MCP Streamable HTTP — JSON-RPC 2.0 (GET/DELETE → 405; empty POST → 202)" },
                new { method = "GET", path = "/api/journal", description = "Get journal entries (unified session log). Query params: ?since=N (entries after index N), ?last=N (last N entries), ?type=action|note|bug|enhancement|observation|charter|testing|test-idea|user|assertion|message|error, ?source=api|gui|system, ?tag=tagname (filter by tag)" },
                new { method = "POST", path = "/api/journal", description = "Add a structured entry: { \"kind\": \"bug|enhancement|observation|charter|testing|test-idea|user|note\", \"note\": \"title...\", \"steps\": \"...\" or [\"step1\",\"step2\"], \"actual\": \"...\", \"expected\": \"...\", \"priority\": \"low|medium|high|critical\" (bug/enhancement rank), \"oracle\": \"...\", \"notes\": \"...\", \"screenshot\": \"/path/to/file.png\", \"severity\": \"info|low|medium|high|critical\" (notes/observations only — not bugs/enhancements), \"tags\": [\"login\",\"security\"], \"url\": \"https://...\" (auto-captured if omitted) }. API actions are logged automatically. Response includes all stored fields for verification." },
                new { method = "GET", path = "/api/journal/export", description = "Generate a formatted test report from the journal. Query params: ?format=html|markdown|json (default html), ?path=file.html (optional — save to disk), ?json=true (wrap report in JSON). format=json is a JournalEntry + pointer round-trip." },
                new { method = "POST", path = "/api/journal/import", description = "Import a trowser-journal JSON bundle (entries + pointers). Body: the bundle, or { \"path\": \"file.json\" } / { \"json\": \"...\" }. New indexes are assigned." },
                new { method = "POST", path = "/api/repro/capture", description = "Build a .trw from journal actions since a checkpoint: { \"checkpointId\", \"name\", \"path\", \"oracle\" }." },
                new { method = "POST", path = "/api/repro/verify", description = "Replay a .trw / bundle / workflow k times: { \"trwPath\"|\"bundlePath\"|\"workflow\", \"runs\": 3, \"clearSession\": true, \"identity\", \"expect\", \"safetyMode\": \"active\" }. Returns reproducible | flaky | not-reproducible." },
                new { method = "GET", path = "/api/test-data", description = "Get a random test data string or security payload. Query: ?kind=strings|payloads (default: active kind). Returns { \"text\": \"...\", \"kind\": \"strings|payloads\" }" },
                new { method = "POST", path = "/api/message", description = "Display a message overlay to the human tester (gate-free). Body: { \"text\", \"level\": \"info|warning|error\", \"duration\" }." },
                new { method = "GET", path = "/api/inspiration", description = "Get a random testing inspiration message. Use for creative test ideas — follow it if it sparks something, skip it if not. Returns { \"message\": \"...\" }" },
                new { method = "GET", path = "/api/scripting-help", description = "Curated C# scripting (.csx) cheat sheet for LLMs/agents. Query: ?topic=overview|map|interaction|assert|wait|network|fetch|mock|security|template|topics. Returns { topic, text }." },
                new { method = "GET", path = "/api/coverage", description = "Reflective coverage lens derived from the journal: pages visited, interactive elements exercised, and which quality characteristics have been touched. Awareness of gaps, not a target." },
                new { method = "GET", path = "/api/ssl/certificates", description = "List all loaded client certificates (alias, subject, thumbprint, expiry, active status)" },
                new { method = "POST", path = "/api/ssl/certificates", description = "Add a client certificate: { \"filePath\": \"path/to/cert.pfx\", \"password\": \"...\", \"alias\": \"my-cert\" }" },
                new { method = "DELETE", path = "/api/ssl/certificates", description = "Remove a client certificate: { \"alias\": \"my-cert\" }" },
                new { method = "GET", path = "/api/ssl/certificates/active", description = "Get the currently active client certificate" },
                new { method = "POST", path = "/api/ssl/certificates/active", description = "Set the active client certificate: { \"alias\": \"my-cert\" }. Pass null/empty alias to clear." },
                new { method = "GET", path = "/api/orchestrate/playbooks", description = "List all available security playbooks (id, title, category, endpoint)" },
                new { method = "GET", path = "/api/orchestrate/runs/{runId}", description = "Poll an async playbook run started with POST /api/orchestrate/{id} and \"async\": true (gate-free)" },
                new { method = "POST", path = "/api/orchestrate/dry-run/{id}", description = "Preview playbook steps without executing: { \"safetyMode\": \"safe\", \"depth\": \"standard\" }" },
                new { method = "POST", path = "/api/orchestrate/{id}", description = "Run a security playbook: { \"scope\": { \"host\": \"...\" }, \"safetyMode\": \"safe\", \"depth\": \"standard\", \"format\": \"vpx-compact\", \"async\": false }" },
                new { method = "POST", path = "/api/vpx/render", description = "Re-render a VPX document: { \"vpx\": { ... }, \"format\": \"markdown\" }" }
            }
        });
    }

    private async Task HandleGetState(HttpListenerRequest request, HttpListenerResponse response)
    {
        var fullText = ApiQuery(request)["fullText"] == "true";
        var selector = ApiQuery(request)["selector"];
        var frame = ApiQuery(request)["frame"];
        var snapshot = await _context.GetSnapshot(fullText, selector, frame);
        snapshot["refGeneration"] = _context.RefGeneration;
        _clientRefGeneration = _context.RefGeneration;

        // Visible filter: default true (hide ref:-1 elements). Pass ?visible=false to include hidden.
        var visibleParam = ApiQuery(request)["visible"];
        bool visibleOnly = visibleParam == null || visibleParam != "false";

        var tagFilter = ApiQuery(request)["tag"];
        var typeFilter = ApiQuery(request)["type"];
        var qFilter = ApiQuery(request)["q"];
        int.TryParse(ApiQuery(request)["limit"], out var limitFilter);
        var fullElements = ApiQuery(request)["fullElements"] == "true";
        var format = ApiQuery(request)["format"];
        var compactFormat = string.Equals(format, "compact", StringComparison.OrdinalIgnoreCase);

        if (snapshot.TryGetValue("interactiveElements", out var elemObj)
            && elemObj is List<Dictionary<string, object>> elements)
        {
            HashSet<int>? refsInContainer = null;
            if (!string.IsNullOrEmpty(selector))
                refsInContainer = await _context.GetRefsInContainer(selector, elements);

            var filtered = InteractiveSnapshotFilter.Apply(
                elements,
                visibleOnly,
                limitFilter,
                fullElements,
                tagFilter,
                typeFilter,
                qFilter,
                selector,
                refsInContainer,
                compactFormat);

            snapshot["interactiveElements"] = filtered.Elements;
            if (filtered.Truncated)
            {
                snapshot["interactiveElementsTruncated"] = true;
                snapshot["interactiveElementsTotal"] = filtered.TotalBeforeLimit;
                snapshot["interactiveElementsHint"] =
                    "More elements exist. Use ?fullElements=true, ?limit=N, ?q=, ?selector=, or POST /api/state/enrich.";
            }
            if (filtered.CompactLines != null)
                snapshot["interactiveElementsLines"] = filtered.CompactLines;
        }

        // Security Shadow summary (when active)
        var shadowSummary = _context.SecurityShadow?.GetStateSummary();
        if (shadowSummary != null)
            snapshot["securityShadow"] = shadowSummary;

        if (_context.PowerMode != null)
            snapshot["powerMode"] = new
            {
                enabled = _context.PowerMode.Config.Enabled,
                showOverlays = _context.PowerMode.Config.ShowOverlays
            };
        if (_context.RedTeamWhisper != null)
        {
            var wh = _context.RedTeamWhisper;
            snapshot["redTeamWhisper"] = new
            {
                enabled = wh.Config.Enabled,
                notifyGui = wh.Config.NotifyGui,
                lastHints = wh.LastHints,
                clues = wh.LastClues.Select(c => c.ToApiObject()),
                newClues = wh.LastNewClues.Select(c => c.ToApiObject()),
                llmSurface = wh.LastLlmSurface == null ? null : LlmRedTeamRequestParser.FormatSurface(wh.LastLlmSurface),
                lastLlmScan = wh.LastLlmScan == null ? null : new
                {
                    wh.LastLlmScan.FiredCount,
                    wh.LastLlmScan.TotalProbes,
                    wh.LastLlmScan.Transport,
                    hasFindings = wh.LastLlmScan.HasFindings
                }
            };
        }

        snapshot["securityPreflight"] = BuildSecurityPreflightPayload(_context.Network.Entries);

        // Section filtering: only include requested sections
        var sectionsParam = ApiQuery(request)["sections"];
        if (!string.IsNullOrEmpty(sectionsParam))
        {
            var requested = new HashSet<string>(
                sectionsParam.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                StringComparer.OrdinalIgnoreCase);

            // Always keep refGeneration (needed for stale-ref detection)
            requested.Add("refGeneration");

            var keysToRemove = snapshot.Keys.Where(k => !requested.Contains(k)).ToList();
            foreach (var key in keysToRemove)
                snapshot.Remove(key);
        }

        await WriteSuccess(response, snapshot);
    }

    /// <summary>
    /// Force a full page state rescan. Useful after DOM mutations where GET /api/state
    /// might return stale or empty results due to timing.
    /// </summary>
    private async Task HandlePostStateRefresh(HttpListenerRequest request, HttpListenerResponse response)
    {
        // Small delay to let any in-flight DOM mutations settle
        await Task.Delay(100);

        var snapshot = await _context.GetSnapshot(false, null);
        snapshot["refGeneration"] = _context.RefGeneration;
        _clientRefGeneration = _context.RefGeneration;
        snapshot["refreshed"] = true;

        await WriteSuccess(response, snapshot);
    }

    private async Task HandlePostStateEnrich(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var refs = body.GetIntArray("refs");
        var fields = body.GetStringArray("fields");

        if (refs == null || refs.Count == 0)
        {
            await WriteError(response, 400, "Missing required field: refs (array of ref numbers)");
            return;
        }
        if (fields == null || fields.Count == 0)
        {
            await WriteError(response, 400, "Missing required field: fields (array of field names, e.g. text, href, ariaLabel, type, name, id, class, required, maxLength, ...)");
            return;
        }

        fields = fields.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
        if (fields.Count == 0)
        {
            await WriteError(response, 400, "fields must contain at least one field name");
            return;
        }

        var unsupported = fields.Where(f => !AutomationContext.IsEnrichFieldSupported(f)).ToList();
        var supported = fields.Where(f => AutomationContext.IsEnrichFieldSupported(f)).ToList();

        if (supported.Count == 0)
        {
            await WriteError(response, 400, $"No supported fields provided. Unsupported: {string.Join(", ", unsupported)}. " +
                "Supported fields: text, href, ariaLabel, checked, value, placeholder, disabled, " +
                "tag, id, className, class, name, type, role, title, htmlFor, for, " +
                "required, readOnly, maxLength, pattern, min, max, step, autocomplete, multiple, selected, " +
                "src, alt, target, action, method, tabIndex, contentEditable, data-testid, testId");
            return;
        }

        var results = await _context.EnrichRefs(refs, supported);
        if (unsupported.Count > 0)
        {
            await WriteSuccess(response, new
            {
                elements = results,
                warnings = new[]
                {
                    $"Unsupported fields ignored: {string.Join(", ", unsupported)}. " +
                    "Supported fields: text, href, ariaLabel, checked, value, placeholder, disabled, " +
                    "tag, id, className, class, name, type, role, title, htmlFor, for, " +
                    "required, readOnly, maxLength, pattern, min, max, step, autocomplete, multiple, selected, " +
                    "src, alt, target, action, method, tabIndex, contentEditable, data-testid, testId"
                }
            });
        }
        else
        {
            await WriteSuccess(response, new { elements = results });
        }
    }

    private async Task HandlePostDiffState(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        if (!body.HasProperty("before") || !body.HasProperty("after"))
        {
            await WriteError(response, 400,
                "Provide integer \"before\" and \"after\" (refGeneration values from GET /api/state or GET /api/interactive).");
            return;
        }

        var beforeGen = body.GetInt("before", -1);
        var afterGen = body.GetInt("after", -1);
        if (beforeGen < 0 || afterGen < 0)
        {
            await WriteError(response, 400, "\"before\" and \"after\" must be non-negative refGeneration values.");
            return;
        }

        int? tabIdx = null;
        if (body.HasProperty("tabIndex"))
        {
            var ti = body.GetInt("tabIndex", -1);
            if (ti < 0)
            {
                await WriteError(response, 400, "tabIndex must be >= 0 when provided.");
                return;
            }

            tabIdx = ti;
        }

        var diff = _context.BuildRefGenerationDiff(beforeGen, afterGen, out var error, tabIdx);
        if (diff == null)
        {
            await WriteError(response, 404, error!);
            return;
        }

        await WriteSuccess(response, diff);
    }

    private async Task HandleGetScreenshot(HttpListenerRequest request, HttpListenerResponse response)
    {
        var format = (ApiQuery(request)["format"] ?? "png").ToLowerInvariant();
        if (format != "jpeg") format = "png";

        int quality = 80;
        var qualityParam = ApiQuery(request)["quality"];
        if (qualityParam != null && int.TryParse(qualityParam, out var q))
            quality = Math.Clamp(q, 1, 100);

        var ext = format == "jpeg" ? "jpg" : "png";
        var filenameParam = ApiQuery(request)["filename"];
        var filePath = BuildScreenshotPath(filenameParam, ext);

        var refParam = ApiQuery(request)["ref"];
        var selectorParam = ApiQuery(request)["selector"];
        var paddingParam = ApiQuery(request)["padding"];
        int padding = 0;
        if (paddingParam != null && int.TryParse(paddingParam, out var p))
            padding = Math.Clamp(p, 0, 200);

        string? elementSelector = null;

        if (refParam != null)
        {
            if (!int.TryParse(refParam, out var refIndex))
            {
                await WriteError(response, 400, "ref must be an integer");
                return;
            }
            elementSelector = _context.GetSelectorByRef(refIndex);
            if (elementSelector == null)
            {
                await WriteError(response, 400, $"Invalid ref: {refIndex}. Call GET /api/state first to get valid ref numbers.");
                return;
            }
        }
        else if (!string.IsNullOrWhiteSpace(selectorParam))
        {
            elementSelector = selectorParam;
        }

        byte[] bytes;
        try
        {
            if (elementSelector != null)
                bytes = await _context.ScreenshotElementToBytes(elementSelector, padding, format, quality);
            else
                bytes = await _context.ScreenshotToBytes(format, quality);
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
            return;
        }

        await File.WriteAllBytesAsync(filePath, bytes);

        var wantBase64 = ApiQuery(request)["base64"] == "true";

        if (wantBase64)
        {
            var base64 = Convert.ToBase64String(bytes);
            await WriteSuccess(response, new { path = filePath, format, base64 });
        }
        else
        {
            await WriteSuccess(response, new { path = filePath, format });
        }
    }

    /// <summary>
    /// Builds a screenshot file path from an optional user-supplied filename.
    /// Sanitises the name to prevent path traversal, reserved device names,
    /// and ensures the result stays inside <see cref="_screenshotDir"/>.
    /// Falls back to a timestamped default when no name is given.
    /// </summary>
    private string BuildScreenshotPath(string? filename, string ext)
    {
        if (string.IsNullOrWhiteSpace(filename))
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");
            return Path.Combine(_screenshotDir, $"trowser-{timestamp}.{ext}");
        }

        // Strip any existing extension that matches a supported image format, then force the correct one
        var trimmed = filename.Trim();
        var existingExt = Path.GetExtension(trimmed);
        if (existingExt.Equals(".png", StringComparison.OrdinalIgnoreCase)
            || existingExt.Equals(".jpg", StringComparison.OrdinalIgnoreCase)
            || existingExt.Equals(".jpeg", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[..^existingExt.Length];
        }

        // Remove path separators and invalid filename characters
        var invalid = Path.GetInvalidFileNameChars();
        var sanitised = new string(trimmed.Where(c => !invalid.Contains(c)).ToArray()).Trim().TrimEnd('.');

        // Guard against Windows reserved device names
        var nameUpper = sanitised.ToUpperInvariant();
        var reservedNames = new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
            "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
            "LPT6", "LPT7", "LPT8", "LPT9" };
        if (string.IsNullOrWhiteSpace(sanitised) || Array.Exists(reservedNames, r => r == nameUpper))
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");
            return Path.Combine(_screenshotDir, $"trowser-{timestamp}.{ext}");
        }

        // Truncate overly long names
        if (sanitised.Length > 200)
            sanitised = sanitised[..200];

        var candidate = Path.Combine(_screenshotDir, $"{sanitised}.{ext}");

        // Containment check: result must be inside _screenshotDir
        if (!Path.GetFullPath(candidate).StartsWith(Path.GetFullPath(_screenshotDir), StringComparison.OrdinalIgnoreCase))
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");
            return Path.Combine(_screenshotDir, $"trowser-{timestamp}.{ext}");
        }

        // Handle collisions: overwrite by default (predictable paths for .trw scenarios)
        return candidate;
    }

    private async Task HandleCompareScreenshots(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        byte[] beforeBytes;
        var beforeStr = body.GetString("before");
        if (string.IsNullOrEmpty(beforeStr))
        {
            await WriteError(response, 400, "Missing required field: before (file path or base64 image data)");
            return;
        }

        try
        {
            beforeBytes = ExportPathGuard.IsExistingLocalFile(beforeStr)
                ? await File.ReadAllBytesAsync(beforeStr)
                : Convert.FromBase64String(beforeStr);
        }
        catch (FormatException)
        {
            await WriteError(response, 400, "Invalid 'before' value: not a valid file path or base64 data");
            return;
        }

        byte[] afterBytes;
        var afterStr = body.GetString("after");
        if (!string.IsNullOrEmpty(afterStr))
        {
            try
            {
                afterBytes = ExportPathGuard.IsExistingLocalFile(afterStr)
                    ? await File.ReadAllBytesAsync(afterStr)
                    : Convert.FromBase64String(afterStr);
            }
            catch (FormatException)
            {
                await WriteError(response, 400, "Invalid 'after' value: not a valid file path or base64 data");
                return;
            }
        }
        else
        {
            afterBytes = await _context.ScreenshotToBytes();
        }

        int threshold = body.GetInt("threshold", 30);
        threshold = Math.Clamp(threshold, 0, 255);

        var result = await _context.CompareScreenshots(beforeBytes, afterBytes, threshold);

        var diffBase64 = Convert.ToBase64String(result.DiffImagePng);
        var diffTimestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");
        var diffPath = Path.Combine(_screenshotDir, $"trowser-diff-{diffTimestamp}.png");
        await File.WriteAllBytesAsync(diffPath, result.DiffImagePng);

        await WriteSuccess(response, new
        {
            diffPath,
            diffBase64,
            diffPercent = result.DiffPercent,
            changedPixels = result.ChangedPixels,
            totalPixels = result.TotalPixels,
            width = result.Width,
            height = result.Height,
            match = result.DiffPercent == 0
        });
    }

    private int? ResolveTabIndexFromQuery(HttpListenerRequest request)
    {
        var q = ApiQuery(request);
        if (int.TryParse(q["tabIndex"], out var ti))
            return _context.ResolveTabTarget(ti, null);
        var urlMatch = q["urlMatch"];
        if (!string.IsNullOrWhiteSpace(urlMatch))
            return _context.ResolveTabTarget(null, urlMatch);
        return null;
    }

    private async Task HandleGetConsole(HttpListenerRequest request, HttpListenerResponse response)
    {
        var tabIdx = ResolveTabIndexFromQuery(request);
        await _context.InvokeOnTabAsync(tabIdx, async () =>
        {
            var entries = _context.Console.Entries;
            await WriteSuccess(response, new
            {
                count = entries.Count,
                activeTab = _context.GetActiveTabContext(),
                queriedTab = tabIdx ?? _context.GetActiveTabIndex(),
                entries = entries.Select(e => new
                {
                    id = e.Id,
                    level = e.Level.ToString().ToLower(),
                    message = e.Message,
                    timestamp = e.Timestamp
                }).ToList()
            });
            return true;
        });
    }

    private async Task HandleGetNetwork(HttpListenerRequest request, HttpListenerResponse response)
    {
        var tabIdx = ResolveTabIndexFromQuery(request);
        await _context.InvokeOnTabAsync(tabIdx, async () =>
        {
        IEnumerable<NetworkEntry> entries = _context.Network.Entries;

        // Apply filters from query params
        if (ApiQuery(request)["errors"] == "true")
        {
            entries = entries.Where(e => e.IsError);
            if (ApiQuery(request)["includeSynthetic"] != "true")
                entries = entries.Where(e => !e.IsTrowserGenerated);
        }
        if (ApiQuery(request)["url"] is string urlFilter && urlFilter.Length > 0)
            entries = entries.Where(e => e.Url.Contains(urlFilter, StringComparison.OrdinalIgnoreCase));
        if (ApiQuery(request)["method"] is string methodFilter && methodFilter.Length > 0)
            entries = entries.Where(e => e.Method.Equals(methodFilter, StringComparison.OrdinalIgnoreCase));
        if (ApiQuery(request)["statusRange"] is string rangeStr && rangeStr.Length > 0)
        {
            var dash = rangeStr.IndexOf('-');
            if (dash > 0 && int.TryParse(rangeStr[..dash], out var lo) &&
                int.TryParse(rangeStr[(dash + 1)..], out var hi))
                entries = entries.Where(e => e.StatusCode >= lo && e.StatusCode <= hi);
        }
        else if (ApiQuery(request)["status"] is string statusStr && int.TryParse(statusStr, out var statusFilter))
            entries = entries.Where(e => e.StatusCode == statusFilter);
        if (ApiQuery(request)["type"] is string typeFilter && typeFilter.Length > 0)
            entries = entries.Where(e => (e.ResourceType ?? "").Equals(typeFilter, StringComparison.OrdinalIgnoreCase));
        if (ApiQuery(request)["eventStream"] == "true")
            entries = entries.Where(e => e.IsEventStream);
        if (ApiQuery(request)["id"] is string idStr && int.TryParse(idStr, out var entryId))
            entries = entries.Where(e => e.Id == entryId);

        var list = entries.ToList();
        var responseBodyOffset = int.TryParse(ApiQuery(request)["responseBodyOffset"], out var rbo) && rbo >= 0 ? rbo : 0;
        var responseBodyLimit = int.TryParse(ApiQuery(request)["responseBodyLimit"], out var rbl) && rbl > 0 ? rbl : 0;
        var includeBody = ApiQuery(request)["includeBody"] == "true";
        var includeHeaders = ApiQuery(request)["includeHeaders"] == "true";
        // Agents: exclude data: URLs by default (huge base64 images blow context windows).
        var includeDataUrls = ApiQuery(request)["includeDataUrls"] == "true";
        var preferInteractive = ApiQuery(request)["preferInteractive"] != "false";
        var maxUrlChars = int.TryParse(ApiQuery(request)["maxUrlChars"], out var muc) ? muc : 500;

        if (!includeDataUrls)
            list = list.Where(e => !IsDataUrl(e.Url)).ToList();

        // MCP-aligned: ?limit=N or ?last=N → most recent N entries (default: all).
        var limitStr = ApiQuery(request)["limit"] ?? ApiQuery(request)["last"];
        int? limit = int.TryParse(limitStr, out var lim) && lim > 0 ? lim : null;
        var matchCountBeforeLimit = list.Count;

        if (limit is int takeLimit && list.Count > takeLimit)
        {
            // Latest N must be chronological — type-based ordering would surface stale OPTIONS preflights.
            list = list.OrderBy(e => e.Timestamp).TakeLast(takeLimit).ToList();
        }
        else if (preferInteractive
                 && ApiQuery(request)["type"] is not { Length: > 0 }
                 && ApiQuery(request)["errors"] != "true")
        {
            // Soft preference: Document/Fetch/XHR first when no explicit type filter.
            list = list
                .OrderBy(e => ResourceTypeRank(e.ResourceType, e.Method))
                .ThenBy(e => e.Timestamp)
                .ToList();
        }

        var totalCount = matchCountBeforeLimit;
        var errorCount = list.Count(e => e.IsError);

        // MCP-aligned: ?summary=true → compact one-line-per-request for all matches.
        if (ApiQuery(request)["summary"] == "true")
        {
            var summaryLines = list.Select(e =>
            {
                var status = e.StatusCode > 0 ? e.StatusCode.ToString() : "---";
                var err = e.IsError ? " [ERROR]" : "";
                var timing = e.DurationMs.HasValue ? $" {e.DurationMs.Value:F0}ms" : "";
                var cache = e.ServedFromCache ? " cache" : "";
                var reqLen = e.RequestBody?.Length ?? 0;
                var respLen = e.ResponseBody?.Length ?? 0;
                var respTrunc = NetworkCaptureLimits.IsResponseBodyTruncated(e) == true ? " respTruncCap" : "";
                var respMismatch = NetworkCaptureLimits.IsResponseBodySizeMismatch(e) == true ? " respLenMismatch" : "";
                return $"#{e.Id} {e.Method} {status}{err}{timing}{cache} reqLen={reqLen} respLenCaptured={respLen}{respTrunc}{respMismatch} {TruncateUrlForAgents(e.Url, maxUrlChars)}";
            }).ToList();

            await WriteSuccess(response, new
            {
                count = totalCount,
                errors = errorCount,
                activeTab = _context.GetActiveTabContext(),
                queriedTab = tabIdx ?? _context.GetActiveTabIndex(),
                entryLookup = NetworkEntryLookupHint,
                summary = summaryLines
            });
            return true;
        }

        var truncated = limit is int requested && matchCountBeforeLimit > requested;

        await WriteSuccess(response, new
        {
            count = totalCount,
            errors = errorCount,
            shown = list.Count,
            truncated,
            activeTab = _context.GetActiveTabContext(),
            queriedTab = tabIdx ?? _context.GetActiveTabIndex(),
            entryLookup = NetworkEntryLookupHint,
            entries = list.Select(e => BuildNetworkEntryPayload(
                e, includeBody, includeHeaders, responseBodyOffset, responseBodyLimit, maxUrlChars)).ToList()
        });
        return true;
        });
    }

    private const string NetworkEntryLookupHint =
        "GET /api/network/{id} returns that entry with request/response headers and any captured body. " +
        "responseBodyCapturedChars null means the log never stored a body; POST /api/fetch is a new request, not this capture.";

    private async Task HandleGetNetworkById(HttpListenerRequest request, HttpListenerResponse response, int id)
    {
        var tabIdx = ResolveTabIndexFromQuery(request);
        await _context.InvokeOnTabAsync(tabIdx, async () =>
        {
            var entry = _context.Network.Entries.FirstOrDefault(e => e.Id == id);
            if (entry == null)
            {
                await WriteError(response, 404, $"No network entry with id {id}.");
                return true;
            }

            var q = ApiQuery(request);
            var includeBody = !string.Equals(q["includeBody"], "false", StringComparison.OrdinalIgnoreCase);
            var includeHeaders = !string.Equals(q["includeHeaders"], "false", StringComparison.OrdinalIgnoreCase);
            var responseBodyOffset = int.TryParse(q["responseBodyOffset"], out var rbo) && rbo >= 0 ? rbo : 0;
            var responseBodyLimit = int.TryParse(q["responseBodyLimit"], out var rbl) && rbl > 0 ? rbl : 0;
            var maxUrlChars = int.TryParse(q["maxUrlChars"], out var muc) ? muc : 0;

            await WriteSuccess(response, new
            {
                activeTab = _context.GetActiveTabContext(),
                queriedTab = tabIdx ?? _context.GetActiveTabIndex(),
                entry = BuildNetworkEntryPayload(
                    entry, includeBody, includeHeaders, responseBodyOffset, responseBodyLimit, maxUrlChars)
            });
            return true;
        });
    }

    internal static bool IsNetworkEntryByIdPath(string path) =>
        TryParseNetworkEntryId(path, out _);

    internal static bool TryParseNetworkEntryId(string path, out int id)
    {
        id = 0;
        const string prefix = "/api/network/";
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;
        var rest = path[prefix.Length..];
        if (rest.Length == 0 || rest.Contains('/'))
            return false;
        return int.TryParse(rest, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out id)
               && id >= 0;
    }

    private static Dictionary<string, object?> BuildNetworkEntryPayload(
        NetworkEntry e,
        bool includeBody,
        bool includeHeaders,
        int responseBodyOffset,
        int responseBodyLimit,
        int maxUrlChars)
    {
        var entry = new Dictionary<string, object?>
        {
            ["id"] = e.Id,
            ["method"] = e.Method,
            ["url"] = TruncateUrlForAgents(e.Url, maxUrlChars),
            ["statusCode"] = e.StatusCode,
            ["resourceType"] = e.ResourceType,
            ["isEventStream"] = e.IsEventStream,
            ["isError"] = e.IsError,
            ["isTrowserGenerated"] = e.IsTrowserGenerated,
            ["timestamp"] = e.Timestamp,
            ["durationMs"] = e.DurationMs,
            ["servedFromCache"] = e.ServedFromCache,
            ["responseSource"] = e.ResponseSource,
            ["mockRuleKey"] = e.MockRuleKey,
            ["cdpFrameId"] = e.CdpFrameId,
            ["redirectedToUrl"] = e.RedirectedToUrl
        };
        foreach (var kv in NetworkCaptureLimits.ResponseBodyCaptureFields(e))
            entry[kv.Key] = kv.Value;
        if (e.ResponseBody == null && NetworkCaptureLimits.ShouldCaptureResponseBody(e.ResourceType, e.ContentType))
        {
            entry["responseBodyNote"] =
                "Body was not captured (cache, or the response stream was unavailable). " +
                "POST /api/fetch reads a new live response; it is not this log entry.";
        }
        if (includeBody)
        {
            if (e.RequestBody != null) entry["requestBody"] = e.RequestBody;
            if (e.ResponseBody != null)
            {
                entry["responseBody"] = responseBodyLimit > 0
                    ? NetworkCaptureLimits.SliceBody(e.ResponseBody, responseBodyOffset, responseBodyLimit)
                    : e.ResponseBody;
                if (responseBodyLimit > 0)
                {
                    entry["responseBodyOffset"] = responseBodyOffset;
                    entry["responseBodyLimit"] = responseBodyLimit;
                }
            }
        }
        if (includeHeaders)
        {
            entry["requestHeaders"] = e.RequestHeaders;
            entry["responseHeaders"] = e.ResponseHeaders;
        }
        return entry;
    }

    private static bool IsDataUrl(string? url) =>
        !string.IsNullOrEmpty(url) && url.StartsWith("data:", StringComparison.OrdinalIgnoreCase);

    private static int ResourceTypeRank(string? type, string? method = null)
    {
        if (method != null && method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
            return 90;
        return (type ?? "") switch
        {
            "Document" => 0,
            "Fetch" or "XHR" => 1,
            "Script" => 2,
            "Stylesheet" => 3,
            _ => 4
        };
    }

    private static string TruncateUrlForAgents(string url, int maxChars)
    {
        if (string.IsNullOrEmpty(url) || maxChars <= 0 || url.Length <= maxChars)
            return url;
        if (IsDataUrl(url))
        {
            var semi = url.IndexOf(',', StringComparison.Ordinal);
            var meta = semi > 0 ? url[..Math.Min(semi + 1, maxChars)] : url[..Math.Min(32, url.Length)];
            return $"{meta}…({url.Length} chars data-url omitted)";
        }

        return url[..maxChars] + "…";
    }

    private async Task HandleGetAssertions(HttpListenerResponse response)
    {
        await WriteSuccess(response, new
        {
            passed = _context.Assert.PassCount,
            failed = _context.Assert.FailCount,
            total = _context.Assert.TotalCount,
            allPassed = _context.Assert.AllPassed,
            results = _context.Assert.Results.Select(r => new
            {
                passed = r.Passed,
                description = r.Description,
                details = r.Details
            }).ToList()
        });
    }

    private async Task HandleGetInteractive(HttpListenerRequest request, HttpListenerResponse response)
    {
        var elements = await _context.GetInteractiveElements();
        _clientRefGeneration = _context.RefGeneration;

        // Visible filter: default true (hide ref:-1 elements). Pass ?visible=false to include hidden.
        var visibleParam = ApiQuery(request)["visible"];
        bool visibleOnly = visibleParam == null || visibleParam != "false";
        if (visibleOnly)
        {
            elements = elements.Where(e =>
            {
                if (!e.TryGetValue("ref", out var r)) return true;
                if (r is System.Text.Json.JsonElement je && je.ValueKind == System.Text.Json.JsonValueKind.Number)
                    return je.GetInt32() >= 0;
                return true;
            }).ToList();
        }

        await WriteSuccess(response, new { count = elements.Count, refGeneration = _context.RefGeneration, elements });
    }

    private async Task HandleGetPageText(HttpListenerResponse response)
    {
        var text = await _context.GetPageText();
        await WriteSuccess(response, new { text, length = text.Length });
    }

    private async Task HandleGetAllPageText(HttpListenerResponse response)
    {
        var text = await _context.GetAllPageText();
        await WriteSuccess(response, new { text, length = text.Length });
    }

    private async Task HandleGetScreenReaderTexts(HttpListenerResponse response)
    {
        var text = await _context.GetScreenReaderTexts();
        await WriteSuccess(response, new
        {
            text,
            length = text.Length,
            lineCount = string.IsNullOrEmpty(text) ? 0 : text.Split('\n').Length
        });
    }

    private async Task HandleGetSource(HttpListenerResponse response)
    {
        var html = await _context.GetPageSource();
        await WriteSuccess(response, new { html, length = html.Length });
    }

    #endregion
}
