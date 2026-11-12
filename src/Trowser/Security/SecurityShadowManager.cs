using System.Threading;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Laws;
using Trowser.MixedContent;
using Trowser.Security.Runtime;
using Trowser.XssAudit;

namespace Trowser.Security;

/// <summary>
/// Accumulated finding from Shadow's continuous monitoring.
/// Deduplicated by (Audit, Title, UrlHostPath).
/// </summary>
public class ShadowFinding
{
    private static int _nextId;

    public int Id { get; init; } = Interlocked.Increment(ref _nextId);
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public DateTime FirstSeen { get; set; }
    public string Url { get; init; } = "";
    public string Audit { get; init; } = "";
    public Severity Severity { get; init; }
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string? Recommendation { get; init; }
    public int Occurrences { get; set; } = 1;

    /// <summary>URLs where this finding was seen (populated when deduplication merges occurrences).</summary>
    public List<string> SeenOnUrls { get; set; } = [];

    /// <summary>
    /// Unique hosts from <see cref="SeenOnUrls"/>. Pages on the same host collapse so
    /// reports can show which services are affected without listing every path.
    /// </summary>
    public IReadOnlyList<string> SeenOnDomains => CollectSeenOnDomains(SeenOnUrls);

    /// <summary>Deduplication key: same audit + title (URL-independent so the same issue across pages is merged).</summary>
    public string DeduplicationKey => $"{Audit}|{Title}";

    internal static IReadOnlyList<string> CollectSeenOnDomains(IEnumerable<string> urls)
    {
        var domains = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var url in urls)
        {
            var domain = TryGetDomain(url);
            if (domain != null)
                domains.Add(domain);
        }
        return domains.Count == 0 ? [] : domains.ToList();
    }

    internal static string? TryGetDomain(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
            return null;
        return uri.Host;
    }

    /// <summary>Comma-separated unique domains, or null when none are known.</summary>
    public string? FormatSeenOnDomains()
    {
        var domains = SeenOnDomains;
        return domains.Count == 0 ? null : string.Join(", ", domains);
    }
}

/// <summary>
/// Proactive testing suggestion generated when Shadow detects patterns worth investigating.
/// </summary>
public class ShadowSuggestion
{
    private static int _nextId;

    public int Id { get; init; } = Interlocked.Increment(ref _nextId);
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public string Trigger { get; init; } = "";
    public string Suggestion { get; init; } = "";
    /// <summary>MCP tool the AI Assistant should call. Shown in the findings dialog.</summary>
    public string? McpTool { get; init; }
    /// <summary>REST equivalent, returned to API clients. The GUI prefers <see cref="McpTool"/>.</summary>
    public string? ApiMethod { get; init; }
    public string? ApiUrl { get; init; }
}

/// <summary>
/// Configuration for which audits Shadow runs on each navigation.
/// </summary>
public class ShadowConfig
{
    /// <summary>
    /// Factory default audits when the user turns Shadow on. Named pack <c>all</c> is separate:
    /// headers, cookies, xss, mixed-content, source-maps, storage, retire-js.
    /// WCAG is opt-in (powerful, but axe-core is too heavy for every navigation).
    /// </summary>
    public static readonly string[] DefaultAuditNames =
        ["xss", "retire-js", "security-headers", "network", "console"];

    /// <summary>1.3.12 factory set (on + WCAG, no headers). Untouched installs migrate once.</summary>
    public static readonly string[] PreviousFactoryAuditNames =
        ["xss", "retire-js", "wcag", "network", "console"];

    public static HashSet<string> CreateDefaultAudits() =>
        new(DefaultAuditNames, StringComparer.OrdinalIgnoreCase);

    public bool Enabled { get; set; }
    public HashSet<string> Audits { get; set; } = CreateDefaultAudits();
    public string Scope { get; set; } = "same-origin";
    public bool Suggestions { get; set; } = true;
    public bool Deduplication { get; set; } = true;
    public bool NotifyGui { get; set; } = true;
    public int MaxFindings { get; set; } = 500;

    /// <summary>
    /// Bumped when factory defaults change. Null/0 in old settings.json so untouched
    /// default-on installs can be migrated once without turning Shadow off again later.
    /// </summary>
    public const int CurrentFactoryGeneration = 4;
    public int? FactoryGeneration { get; set; }

    /// <summary>Run user Laws alongside built-in Shadow audits.</summary>
    public bool LawsEnabled { get; set; } = true;

    public HashSet<string> DisabledLaws { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Law source files active for Shadow in this session. Keys match <see cref="LawDefinition.SourceFile"/>
    /// (full paths for user files; <c>embedded:…</c> for bundled Laws). When null, every loaded file is active (legacy default).
    /// </summary>
    public HashSet<string>? ActiveLawSources { get; set; }

    /// <summary>Embedded quicktest leaf names (no path) to run in Shadow Light when @effects none.</summary>
    public HashSet<string> LightQuicktests { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Quicktest leaf names to run on Shadow Heavy.</summary>
    public HashSet<string> HeavyQuicktests { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public bool RunHeavyAfterQuicktest { get; set; }

    public bool SerendipityTimerEnabled { get; set; }
    public int SerendipityIntervalSeconds { get; set; } = 300;
    public bool SerendipityRandomize { get; set; } = true;

    /// <summary>Wall-clock budget for Law evaluation during Shadow Light.</summary>
    public int LightLawBudgetMs { get; set; } = 150;

    /// <summary>Passive Law mining from network observations.</summary>
    public bool LawsMiningEnabled { get; set; }

    /// <summary>
    /// Pre-default-on installs persisted Shadow as off with audits <c>all</c>.
    /// Those have not been customized — apply the current factory defaults once.
    /// </summary>
    public bool LooksLikeLegacyFactoryDefault()
    {
        if (Enabled)
            return false;
        if (!string.Equals(Scope, "same-origin", StringComparison.OrdinalIgnoreCase))
            return false;
        if (Audits == null || Audits.Count == 0)
            return true;
        return Audits.Count == 1 && Audits.Any(a => a.Equals("all", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Enabled install whose audit list is exactly the previous factory set (XSS, Retire.js, WCAG, Network, Console).
    /// </summary>
    public bool LooksLikePreviousFactoryDefault()
    {
        if (!Enabled)
            return false;
        if (!string.Equals(Scope, "same-origin", StringComparison.OrdinalIgnoreCase))
            return false;
        return SameAuditSet(Audits, PreviousFactoryAuditNames);
    }

    /// <summary>
    /// Enabled install whose audit list is exactly the current factory set — leftover from when Shadow shipped on.
    /// </summary>
    public bool LooksLikeCurrentOnFactoryDefault()
    {
        if (!Enabled)
            return false;
        if (!string.Equals(Scope, "same-origin", StringComparison.OrdinalIgnoreCase))
            return false;
        return SameAuditSet(Audits, DefaultAuditNames);
    }

    public bool ShouldApplyCurrentFactoryDefaults() =>
        (FactoryGeneration is null or < CurrentFactoryGeneration)
        && (LooksLikeLegacyFactoryDefault()
            || LooksLikePreviousFactoryDefault()
            || LooksLikeCurrentOnFactoryDefault());

    public void ApplyCurrentFactoryDefaults()
    {
        Enabled = false;
        Audits = CreateDefaultAudits();
        Scope = "same-origin";
        FactoryGeneration = CurrentFactoryGeneration;
    }

    internal static bool SameAuditSet(HashSet<string>? audits, string[] expected)
    {
        if (audits == null || expected.Length == 0 || audits.Count != expected.Length)
            return false;
        return expected.All(a => audits.Contains(a));
    }

    public static string? NormalizeLawSourceKey(string? sourceFile) =>
        LawRegistry.NormalizeSourcePath(sourceFile);

    public bool IsLawSourceActive(string? sourceFile)
    {
        if (string.IsNullOrWhiteSpace(sourceFile))
            return true;
        if (LawService.IsEphemeralScriptSource(sourceFile))
            return true;
        if (ActiveLawSources == null)
            return true;
        var key = NormalizeLawSourceKey(sourceFile) ?? sourceFile;
        return ActiveLawSources.Contains(key);
    }

    /// <summary>Turns legacy “all files on” into an explicit set before toggling one file.</summary>
    public void SetLawSourceActive(string sourceFile, bool active, IEnumerable<string> allKnownSources)
    {
        var key = NormalizeLawSourceKey(sourceFile) ?? sourceFile;
        ActiveLawSources ??= allKnownSources
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => NormalizeLawSourceKey(s) ?? s!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (active)
            ActiveLawSources.Add(key);
        else
            ActiveLawSources.Remove(key);
    }

    public void RemoveLawSourceKey(string? sourceFile)
    {
        if (ActiveLawSources == null || string.IsNullOrWhiteSpace(sourceFile))
            return;
        var key = NormalizeLawSourceKey(sourceFile) ?? sourceFile;
        ActiveLawSources.Remove(key);
    }

    public void EnsureLawSourceActive(string? sourceFile)
    {
        if (string.IsNullOrWhiteSpace(sourceFile) || LawService.IsEphemeralScriptSource(sourceFile))
            return;
        var key = NormalizeLawSourceKey(sourceFile) ?? sourceFile;
        if (ActiveLawSources == null)
            ActiveLawSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { key };
        else
            ActiveLawSources.Add(key);
    }
}

/// <summary>
/// Continuous ambient analysis that runs silently alongside normal browsing.
/// Hooks into navigation events and network log to detect issues in real time.
/// Factory default (off until the user turns it on): XSS, Retire.js, security-headers, Network, Console (errors only). Named pack `all` is headers,
/// cookies, XSS, mixed-content, source-maps, storage, and Retire.js — not WCAG / Network / Console.
/// WCAG is opt-in. A new navigation cancels the previous page's in-flight audit batch.
/// </summary>
public class SecurityShadowManager
{
    private readonly object _lock = new();
    private readonly List<ShadowFinding> _findings = [];
    private readonly List<ShadowSuggestion> _suggestions = [];
    private readonly Dictionary<string, ShadowFinding> _dedup = new();
    private int _pagesAudited;
    private int _lastPolledFindingId;

    /// <summary>Serializes shadow audits so navigations queue instead of being dropped while a batch runs.</summary>
    private readonly SemaphoreSlim _auditSequential = new(1, 1);

    /// <summary>Cancelled in <see cref="BeginPage"/> so leftover page audits stop when the document changes.</summary>
    private CancellationTokenSource _auditCts = new();

    /// <summary>
    /// XSS categories that are CSP / supply-chain hygiene, not exploit signals.
    /// Skipped in Shadow; still reported by <c>POST /api/security/xss</c> / <c>CheckXss</c>.
    /// </summary>
    internal static readonly HashSet<string> XssHygieneCategories = new(StringComparer.OrdinalIgnoreCase)
    {
        "cross-domain-script",
        "cross-domain-script-summary",
        "inline-script",
        "inline-handler",
        "dangerous-sink"
    };

    /// <summary>Hard cap for waiting on one navigation's audit batch. A new navigation cancels the previous batch.</summary>
    private static readonly TimeSpan AuditBatchTimeout = TimeSpan.FromSeconds(25);

    private const long OneMegabyte = 1024L * 1024;
    private const long TwoMegabytes = 2 * OneMegabyte;

    /// <summary>
    /// METHOD+URL keys that already counted as a network fetch on this navigation.
    /// Cache hits and static-asset 304s are not inserted, so a second disk-cache read does not flag.
    /// </summary>
    private readonly HashSet<string> _navRequestKeys = new(StringComparer.Ordinal);

    public ShadowConfig Config { get; } = new();

    /// <summary>Fired when new findings are discovered. Parameters: new finding count, highest severity.</summary>
    public event Action<int, Severity>? FindingsAdded;

    /// <summary>Fired when a suggestion is generated.</summary>
    public event Action<ShadowSuggestion>? SuggestionAdded;

    /// <summary>Fired after <see cref="Configure"/> changes enablement or options (GUI, API, MCP).</summary>
    public event Action? ConfigChanged;

    public bool Enabled => Config.Enabled;
    public int PagesAudited { get { lock (_lock) return _pagesAudited; } }
    public int FindingsCount { get { lock (_lock) return _findings.Count; } }

    public List<ShadowFinding> GetFindings(int? sinceId = null, Severity? minSeverity = null, string? category = null, string? urlFilter = null)
    {
        lock (_lock)
        {
            IEnumerable<ShadowFinding> q = _findings;
            if (sinceId.HasValue) q = q.Where(f => f.Id > sinceId.Value);
            if (minSeverity.HasValue) q = q.Where(f => f.Severity >= minSeverity.Value);
            if (category != null) q = q.Where(f => f.Audit.Equals(category, StringComparison.OrdinalIgnoreCase));
            if (urlFilter != null) q = q.Where(f => f.Url.Contains(urlFilter, StringComparison.OrdinalIgnoreCase));
            return q.ToList();
        }
    }

    public List<ShadowSuggestion> GetSuggestions(int? sinceId = null)
    {
        lock (_lock)
        {
            return sinceId.HasValue
                ? _suggestions.Where(s => s.Id > sinceId.Value).ToList()
                : [.. _suggestions];
        }
    }

    public int NewSinceLastPoll
    {
        get
        {
            lock (_lock)
            {
                return _findings.Count(f => f.Id > _lastPolledFindingId);
            }
        }
    }

    public void MarkPolled()
    {
        lock (_lock)
        {
            if (_findings.Count > 0)
                _lastPolledFindingId = _findings[^1].Id;
        }
    }

    /// <summary>
    /// Get a lightweight status summary for /api/state integration.
    /// </summary>
    public object? GetStateSummary()
    {
        if (!Config.Enabled) return null;
        lock (_lock)
        {
            var newCount = _findings.Count(f => f.Id > _lastPolledFindingId);
            var highCount = _findings.Count(f => f.Severity >= Severity.High);
            var latest = _findings.Count > 0 ? _findings[^1].Title : null;
            return new
            {
                enabled = true,
                newFindings = newCount,
                highSeverity = highCount,
                latestFinding = latest
            };
        }
    }

    /// <summary>Audits accepted by POST /api/security/shadow and navigation-time Shadow.</summary>
    public static readonly string[] LegalAuditNames =
    [
        "all", "xss", "retire-js", "security-headers", "cookies", "mixed-content",
        "source-maps", "storage", "network", "console", "wcag", "runtime", "smuggling"
    ];

    public static bool TryValidateAuditNames(IEnumerable<string> audits, out string? error)
    {
        var unknown = audits
            .Where(a => !LegalAuditNames.Contains(a, StringComparer.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (unknown.Count == 0)
        {
            error = null;
            return true;
        }

        error = $"Unknown shadow audit(s): {string.Join(", ", unknown)}. " +
                $"Legal values: {string.Join(", ", LegalAuditNames)}.";
        return false;
    }

    public void Configure(bool enabled, HashSet<string>? audits = null, string? scope = null,
        bool? suggestions = null, bool? deduplication = null, bool? notifyGui = null)
    {
        Config.Enabled = enabled;
        if (audits != null) Config.Audits = audits;
        if (scope != null) Config.Scope = scope;
        if (suggestions.HasValue) Config.Suggestions = suggestions.Value;
        if (deduplication.HasValue) Config.Deduplication = deduplication.Value;
        if (notifyGui.HasValue) Config.NotifyGui = notifyGui.Value;
        Config.FactoryGeneration = ShadowConfig.CurrentFactoryGeneration;
        ConfigChanged?.Invoke();
    }

    public void ClearFindings(string? category = null)
    {
        lock (_lock)
        {
            if (category != null)
            {
                _findings.RemoveAll(f => f.Audit.Equals(category, StringComparison.OrdinalIgnoreCase));
                var keysToRemove = _dedup.Where(kv => kv.Value.Audit.Equals(category, StringComparison.OrdinalIgnoreCase))
                    .Select(kv => kv.Key).ToList();
                foreach (var k in keysToRemove) _dedup.Remove(k);
            }
            else
            {
                _findings.Clear();
                _suggestions.Clear();
                _dedup.Clear();
                _pagesAudited = 0;
                _lastPolledFindingId = 0;
                _navRequestKeys.Clear();
            }
        }
    }

    /// <summary>
    /// Reset per-navigation Network state (duplicate-request keys) and cancel in-flight page audits.
    /// Call on NavigationStarting and on SPA soft navigations — the same moment console/network
    /// logs mark a page boundary. Pages you stay on still finish; bounce-through pages drop leftover work
    /// so axe/Retire poll loops do not keep hitting the new document.
    /// </summary>
    public void BeginPage()
    {
        lock (_lock)
            _navRequestKeys.Clear();
        CancelPendingAudits();
    }

    private void CancelPendingAudits()
    {
        var next = new CancellationTokenSource();
        var previous = Interlocked.Exchange(ref _auditCts, next);
        try { previous.Cancel(); }
        catch (ObjectDisposedException) { }
    }

    /// <summary>
    /// Called from NavigationCompleted. Runs configured audits asynchronously.
    /// </summary>
    public async Task OnNavigationCompletedAsync(WebView2 webView, string url, BrowserTab tab)
    {
        if (!Config.Enabled) return;
        if (!IsInScope(url)) return;

        var ct = _auditCts.Token;
        try
        {
            await _auditSequential.WaitAsync(ct);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        try
        {
            if (ct.IsCancellationRequested)
                return;

            Interlocked.Increment(ref _pagesAudited);

            var tasks = new List<Task>();

            if (ShouldRun("security-headers"))
                tasks.Add(RunHeadersAudit(url, tab, webView, ct));
            if (ShouldRun("cookies"))
                tasks.Add(RunCookieAudit(webView, url, tab, ct));
            if (ShouldRun("xss"))
                tasks.Add(RunXssAudit(webView, url, ct));
            if (ShouldRun("mixed-content"))
                tasks.Add(RunMixedContentAudit(webView, url, ct));
            if (ShouldRun("source-maps"))
                tasks.Add(RunSourceMapAudit(webView, url, ct));
            if (ShouldRun("storage"))
                tasks.Add(RunStorageAudit(webView, url, ct));
            if (ShouldRun("retire-js"))
                tasks.Add(RunRetireJsAudit(webView, url, ct));
            if (ShouldRun("wcag", partOfAll: false))
                tasks.Add(RunWcagAudit(webView, url, ct));
            if (ShouldRun("runtime", partOfAll: false))
                tasks.Add(RunRuntimeAudit(webView, url, tab, ct));

            if (tasks.Count == 0) return;

            try
            {
                await Task.WhenAll(tasks).WaitAsync(AuditBatchTimeout, ct);
            }
            catch (OperationCanceledException)
            {
                /* next navigation cancelled this batch */
            }
            catch (TimeoutException)
            {
                /* batch wait ended; cancelled token still stops poll loops */
            }
        }
        finally
        {
            _auditSequential.Release();
        }
    }

    /// <summary>
    /// Called for each new network entry. Heuristics honor the same <see cref="ShadowConfig.Audits"/>
    /// selection as navigation-time audits (Network, XSS, Mixed content).
    /// </summary>
    public void OnNetworkEntry(NetworkEntry entry, string pageUrl)
    {
        if (!Config.Enabled) return;
        if (!IsInScope(pageUrl)) return;

        var networkAudit = ShouldRun("network", partOfAll: false);
        var mixedContentAudit = ShouldRun("mixed-content");
        var xssAudit = ShouldRun("xss");

        if (networkAudit && !entry.IsTrowserGenerated)
            RunNetworkHygiene(entry);

        // Flag mixed content (HTTP resource on HTTPS page)
        if (mixedContentAudit
            && pageUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            && entry.Url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !entry.Url.StartsWith("http://localhost", StringComparison.OrdinalIgnoreCase))
        {
            AddFinding(new ShadowFinding
            {
                Url = entry.Url,
                Audit = "mixed-content",
                Severity = entry.ResourceType is "Script" or "Stylesheet" ? Severity.High : Severity.Medium,
                Title = $"Mixed content: {entry.ResourceType} loaded over HTTP",
                Description = $"HTTPS page loaded {entry.ResourceType.ToLowerInvariant()} over HTTP: {entry.Url}",
                Recommendation = "Serve all resources over HTTPS."
            });
        }

        // Flag sensitive data in URLs (query string tokens/emails)
        if (networkAudit && entry.Url.Contains('?'))
        {
            var query = entry.Url[(entry.Url.IndexOf('?') + 1)..];
            if (LooksLikeSensitiveQueryParam(query))
            {
                AddFinding(new ShadowFinding
                {
                    Url = entry.Url,
                    Audit = "network",
                    Severity = Severity.Medium,
                    Title = "Potentially sensitive data in URL query string",
                    Description = $"URL query string may contain tokens or credentials: {entry.Path}",
                    Recommendation = "Sensitive data should be sent in POST bodies or headers, not URL query parameters (logged in server logs, browser history, referrer headers)."
                });
            }
        }

        if (networkAudit
            && !string.IsNullOrWhiteSpace(entry.RequestBody)
            && entry.Method is "POST" or "PUT" or "PATCH")
        {
            var credHits = NetworkRequestCredentialHeuristics.DetectPlaintextCredentials(
                entry.Url, entry.Method, entry.RequestBody, entry.ContentType);
            foreach (var hit in credHits.Where(h => !h.IsHashed))
            {
                // Expected login/register/reset POSTs send passwords in the body over TLS —
                // that is normal app traffic, not a finding. Keep non-auth password fields.
                if (hit.IsAuthEndpoint)
                    continue;

                AddFinding(new ShadowFinding
                {
                    Url = entry.Url,
                    Audit = "network",
                    Severity = Severity.Medium,
                    Title = "Plaintext password in request body",
                    Description = $"{entry.Method} {entry.Path} sends password field '{hit.FieldName}' in the request body without client-side hashing.",
                    Recommendation = "Passwords should be hashed server-side with a strong algorithm (Argon2/bcrypt/scrypt). Client-side hashing before TLS is optional defense-in-depth, not a substitute for server-side protection."
                });
            }
        }

        // Passive response-body heuristics (bodies are already capped in the network log — keep regex work bounded)
        if (entry.ResponseBody != null
            && entry.ResourceType is "Fetch" or "XHR" or "Document"
            && (networkAudit || xssAudit))
        {
            var rb = entry.ResponseBody;
            if (networkAudit && ResponseBodySecurityHeuristics.DetectCaptchaAnswerLeakage(rb))
            {
                var confirmed = ResponseBodySecurityHeuristics.DetectCaptchaAnswerLeakageConfirmed(rb);
                AddFinding(new ShadowFinding
                {
                    Url = entry.Url,
                    Audit = "network",
                    // Heuristic co-occurrence stays low until a concrete answer value is present.
                    Severity = confirmed ? Severity.Medium : Severity.Info,
                    Title = confirmed
                        ? "CAPTCHA challenge and answer value in same response"
                        : "CAPTCHA challenge and answer-like fields in same response (heuristic)",
                    Description = confirmed
                        ? "Response exposes both a CAPTCHA challenge and a non-empty answer/solution value — verify this cannot be abused by clients."
                        : "Response may mention CAPTCHA alongside answer-like JSON fields. Heuristic only — confirm with an active probe before treating as high severity.",
                    Recommendation = "Never return captcha solutions in API responses; validate server-side only."
                });
            }

            var sqlHits = networkAudit
                ? ResponseBodySecurityHeuristics.DetectSqlErrorSignatures(rb)
                : [];
            if (sqlHits.Count > 0)
            {
                AddFinding(new ShadowFinding
                {
                    Url = entry.Url,
                    Audit = "network",
                    Severity = Severity.High,
                    Title = "SQL/database error pattern in response body",
                    Description = $"Detected {sqlHits.Count} SQL error signature(s) (e.g. {sqlHits[0].Engine}: {sqlHits[0].Pattern}).",
                    Recommendation = "Suppress verbose SQL errors in production; investigate possible SQL injection."
                });
            }

            if (xssAudit
                && (entry.ContentType.Contains("html", StringComparison.OrdinalIgnoreCase)
                    || entry.ResourceType == "Document"))
            {
                var storedXss = ResponseBodySecurityHeuristics.DetectStoredXssInHtml(rb);
                if (storedXss.Count > 0)
                {
                    AddFinding(new ShadowFinding
                    {
                        Url = entry.Url,
                        Audit = "xss",
                        Severity = Severity.Medium,
                        Title = "Stored XSS indicator in HTML response (passive recall)",
                        Description = $"Unencoded active content in captured response ({storedXss[0].Pattern}). Confirm with stored/DOM XSS probes before filing.",
                        Recommendation = "HTML-encode user-supplied content before rendering; deploy CSP; verify with active XSS scan."
                    });
                }
            }

            var credHits = networkAudit
                ? ResponseBodySecurityHeuristics.DetectCredentialExposure(
                    rb, suppressStandaloneHexFingerprints: true)
                : [];
            credHits = credHits
                .Where(h => h.Kind is not "email-address"
                    and not "md5-hex-like" and not "sha1-hex-like" and not "sha256-hex-like")
                .ToList();
            if (networkAudit && credHits.Count > 0)
            {
                var plaintextCred = credHits.Any(h =>
                    h.Kind.Contains("plaintext-password", StringComparison.OrdinalIgnoreCase)
                    || h.Kind.Contains("email-password-combo", StringComparison.OrdinalIgnoreCase));
                AddFinding(new ShadowFinding
                {
                    Url = entry.Url,
                    Audit = "network",
                    Severity = plaintextCred ? Severity.Critical : Severity.Medium,
                    Title = plaintextCred
                        ? "Plaintext password / email+password combo in API response"
                        : "Possible credential hash, API key pattern, or PII in response",
                    Description = $"Heuristic matches: {string.Join(", ", credHits.Take(4).Select(h => h.Kind))}.",
                    Recommendation = plaintextCred
                        ? "Never return plaintext passwords from APIs. Hash at rest and omit password fields from responses."
                        : "Ensure APIs do not return password hashes, long-lived secrets, or unnecessary PII."
                });
            }
        }
    }

    private void RunNetworkHygiene(NetworkEntry entry)
    {
        if (ScannerTrafficExclusion.ShouldIgnoreNetworkHygiene(entry))
            return;

        if (entry.StatusCode == 500)
        {
            AddFinding(new ShadowFinding
            {
                Url = entry.Url,
                Audit = "network",
                Severity = Severity.Medium,
                Title = $"HTTP 500 on {entry.Method} {entry.Path}",
                Description = $"{entry.Method} {entry.Url} returned 500 {entry.ReasonPhrase}.",
                Recommendation = "Investigate unexpected 500s outside active probing. Probe-induced errors belong in scanner traces."
            });
        }
        else if (entry.StatusCode == 404)
        {
            if (ScannerTrafficExclusion.ShouldIgnoreNetworkHygiene(entry))
                return;

            AddFinding(new ShadowFinding
            {
                Url = entry.Url,
                Audit = "network",
                Severity = Severity.Low,
                Title = $"HTTP 404 on {entry.Method} {entry.Path}",
                Description = $"{entry.Method} {entry.Url} returned 404 {entry.ReasonPhrase}.",
                Recommendation = "Confirm the client is not requesting missing assets or stale API paths."
            });
        }

        var size = entry.ContentLengthBytes;
        if (size >= TwoMegabytes)
        {
            AddFinding(new ShadowFinding
            {
                Url = entry.Url,
                Audit = "network",
                Severity = Severity.Info,
                Title = $"Very large response ({FormatMb(size.Value)}) from {entry.Path}",
                Description = $"{entry.Method} {entry.Url} declared Content-Length {size.Value} bytes (> 2 MB).",
                Recommendation = "Check whether the response returns more data than the client needs."
            });
        }
        else if (size >= OneMegabyte)
        {
            AddFinding(new ShadowFinding
            {
                Url = entry.Url,
                Audit = "network",
                Severity = Severity.Info,
                Title = $"Large response ({FormatMb(size.Value)}) from {entry.Path}",
                Description = $"{entry.Method} {entry.Url} declared Content-Length {size.Value} bytes (> 1 MB).",
                Recommendation = "Check whether the response returns more data than the client needs."
            });
        }

        if (!CountsTowardDuplicateFetch(entry))
            return;

        var dupKey = $"{entry.Method} {entry.Url}";
        bool duplicate;
        lock (_lock)
            duplicate = !_navRequestKeys.Add(dupKey);
        if (duplicate)
        {
            AddFinding(new ShadowFinding
            {
                Url = entry.Url,
                Audit = "network",
                Severity = Severity.Info,
                Title = $"Duplicate {entry.Method} {entry.Path} during this navigation",
                Description = $"The same request was fetched from the network more than once on this page: {entry.Method} {entry.Url}.",
                Recommendation = "Duplicate fetches often mean missing cache, React Strict Mode double-mount, or a retry loop."
            });
        }
    }

    /// <summary>
    /// A repeated URL counts only when this response actually left the machine.
    /// Disk, memory, prefetch, and service-worker hits do not. A 304 for a static asset
    /// is revalidation of that same double-request, so it does not count either.
    /// POST, PUT, PATCH, and DELETE always count.
    /// </summary>
    private static bool CountsTowardDuplicateFetch(NetworkEntry entry)
    {
        if (entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
            || entry.Method.Equals("PUT", StringComparison.OrdinalIgnoreCase)
            || entry.Method.Equals("PATCH", StringComparison.OrdinalIgnoreCase)
            || entry.Method.Equals("DELETE", StringComparison.OrdinalIgnoreCase))
            return true;

        if (entry.ServedFromCache)
            return false;

        if (entry.StatusCode == 304 && entry.ResourceType is "Script" or "Stylesheet" or "Image" or "Font")
            return false;

        return true;
    }

    /// <summary>
    /// Called for each captured console message when the Console audit is on.
    /// Errors are Medium; warnings, info, and log are ignored.
    /// </summary>
    public void OnConsoleEntry(ConsoleEntry entry, string pageUrl)
    {
        if (!Config.Enabled) return;
        if (!ShouldRun("console", partOfAll: false)) return;
        if (!IsInScope(pageUrl)) return;
        if (entry.Level != ConsoleLevel.Error) return;
        if (string.IsNullOrWhiteSpace(entry.Message)) return;
        if (entry.Message.Contains("__trowser", StringComparison.OrdinalIgnoreCase)) return;

        var oneLine = entry.Message.Replace('\r', ' ').Replace('\n', ' ').Trim();
        if (oneLine.Length > 160)
            oneLine = oneLine[..157] + "...";

        AddFinding(new ShadowFinding
        {
            Url = pageUrl,
            Audit = "console",
            Severity = Severity.Medium,
            Title = $"Console error: {oneLine}",
            Description = entry.Message.Length > 800 ? entry.Message[..797] + "..." : entry.Message,
            Recommendation = "Fix the script error or catch it; console errors often hide broken features."
        });
    }

    private static string FormatMb(long bytes) => $"{bytes / (1024.0 * 1024.0):0.0} MB";

    /// <summary>
    /// Public method allowing Watch Mode scripts or external callers to add custom findings.
    /// </summary>
    public void AddCustomFinding(Severity severity, string title, string description, string? recommendation = null, string? audit = null, string? url = null)
    {
        AddFinding(new ShadowFinding
        {
            Url = url ?? "",
            Audit = audit ?? "custom",
            Severity = severity,
            Title = title,
            Description = description,
            Recommendation = recommendation
        });
    }

    /// <summary>When a Law passes on a URL, drop that URL from the merged failure (other pages keep the finding).</summary>
    public void ClearLawFailureForUrl(string lawName, string? pageUrl)
    {
        if (string.IsNullOrWhiteSpace(lawName) || string.IsNullOrWhiteSpace(pageUrl))
            return;

        var title = $"Law: {lawName}";
        var key = $"laws|{title}";
        lock (_lock)
        {
            if (!_dedup.TryGetValue(key, out var existing))
                return;

            existing.SeenOnUrls.RemoveAll(u => u.Equals(pageUrl, StringComparison.OrdinalIgnoreCase));
            if (existing.SeenOnUrls.Count == 0)
            {
                _findings.RemoveAll(f =>
                    f.Audit.Equals("laws", StringComparison.OrdinalIgnoreCase)
                    && f.Title.Equals(title, StringComparison.Ordinal));
                _dedup.Remove(key);
            }
        }
    }

    #region Audit Runners

    /// <summary>
    /// Audit security headers from the navigation Document response already in the network log.
    /// Does not re-request the page (avoids CSRF/session side effects from HEAD/GET probes).
    /// </summary>
    private async Task RunHeadersAudit(string url, BrowserTab tab, WebView2 webView, CancellationToken ct)
    {
        try
        {
            var liveUrl = (await RunJsOnUiThread(webView, "location.href") ?? "").Trim().Trim('"');
            if (HeadersChecker.IsNonHttpDocumentUrl(liveUrl))
                return;

            var auditUrl = string.IsNullOrWhiteSpace(liveUrl) ? url : liveUrl;
            if (HeadersChecker.IsNonHttpDocumentUrl(auditUrl))
                return;

            var document = await WaitForNavigationDocumentAsync(tab, auditUrl, ct)
                           ?? await WaitForNavigationDocumentAsync(tab, url, ct);
            if (document == null)
                return;

            auditUrl = string.IsNullOrWhiteSpace(document.Url) ? auditUrl : document.Url;
            if (HeadersChecker.IsNonHttpDocumentUrl(auditUrl))
                return;

            var result = HeadersChecker.AnalyzeFromHeaders(auditUrl, document.ResponseHeaders);
            ct.ThrowIfCancellationRequested();
            if (!result.FetchSucceeded)
                return;

            foreach (var finding in result.Findings)
            {
                AddFinding(new ShadowFinding
                {
                    Url = auditUrl,
                    Audit = "security-headers",
                    Severity = finding.Severity,
                    Title = $"{finding.Header}: {finding.Description}",
                    Description = finding.Description,
                    Recommendation = finding.Recommendation
                });
            }

            if (Config.Suggestions && result.Findings.Any(f => f.Header.Contains("Content-Security-Policy", StringComparison.OrdinalIgnoreCase)))
            {
                AddSuggestion(new ShadowSuggestion
                {
                    Trigger = "Missing or weak CSP detected",
                    Suggestion = "Run browser_firewall_test with tests=['csp'] to verify whether the CSP actually blocks script injection, or browser_security_xss for DOM XSS analysis.",
                    McpTool = "browser_firewall_test",
                    ApiMethod = "POST",
                    ApiUrl = "/api/security/firewall-test"
                });
            }

            // Passive smuggling indicators from the same headers
            if (result.RawHeaders.Count > 0)
            {
                var httpVersion = result.RawHeaders.ContainsKey("via") ? "HTTP/1.1" : "HTTP/1.1";
                result.RawHeaders.TryGetValue("server", out var serverHeader);
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var kvp in result.RawHeaders)
                    headers[kvp.Key] = kvp.Value;

                var smugglingPassive = HttpRequestSmugglingScanner.AnalyzePassive(headers, httpVersion, serverHeader);
                if (!smugglingPassive.IsClean)
                {
                    var riskSeverity = smugglingPassive.Risk switch
                    {
                        "high" => Severity.High,
                        "medium" => Severity.Low,
                        _ => Severity.Info
                    };
                    foreach (var indicator in smugglingPassive.Indicators)
                    {
                        AddFinding(new ShadowFinding
                        {
                            Url = url,
                            Audit = "smuggling",
                            Severity = riskSeverity,
                            Title = indicator,
                            Description = indicator,
                            Recommendation = smugglingPassive.Recommendation
                        });
                    }

                    if (Config.Suggestions && smugglingPassive.Risk is "high" or "medium")
                    {
                        AddSuggestion(new ShadowSuggestion
                        {
                            Trigger = "HTTP request smuggling risk indicators detected",
                            Suggestion = "Run browser_security_smuggling with safetyMode: active for active CL-TE/TE-CL/TE-TE smuggling detection using timing-based probes.",
                            McpTool = "browser_security_smuggling",
                            ApiMethod = "POST",
                            ApiUrl = "/api/security/smuggling"
                        });
                    }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* audit failed — don't block navigation */ }
    }

    /// <summary>
    /// Wait briefly for the document response to land in the network log (async capture race).
    /// </summary>
    private static async Task<NetworkEntry?> WaitForNavigationDocumentAsync(
        BrowserTab tab, string url, CancellationToken ct)
    {
        const int maxAttempts = 10;
        for (var i = 0; i < maxAttempts; i++)
        {
            ct.ThrowIfCancellationRequested();
            var entry = HeadersChecker.FindNavigationDocumentEntry(tab.Network.PageEntries, url);
            if (entry != null)
                return entry;
            if (i < maxAttempts - 1)
                await Task.Delay(50, ct);
        }

        return null;
    }

    private async Task RunCookieAudit(WebView2 webView, string url, BrowserTab tab, CancellationToken ct)
    {
        try
        {
            var cookies = await GetCookiesForShadowAuditAsync(webView, url);
            ct.ThrowIfCancellationRequested();

            var reconciled = CookieAuditChecker.MergeNetworkSetCookies(url, cookies, tab.Network.Entries);
            var docCookieLine = await RunJsOnUiThread(webView, "document.cookie || ''");
            CookieAuditChecker.MergeDocumentCookieNames(url, cookies, docCookieLine);

            if (cookies.Count == 0) return;

            var result = new CookieAuditChecker().Run(url, cookies, reconciled);
            foreach (var finding in result.Findings)
            {
                AddFinding(new ShadowFinding
                {
                    Url = url,
                    Audit = "cookies",
                    Severity = finding.Severity,
                    Title = $"{finding.CookieName}: {finding.Category}",
                    Description = finding.Description,
                    Recommendation = finding.Recommendation
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private async Task RunXssAudit(WebView2 webView, string url, CancellationToken ct)
    {
        try
        {
            var checker = new XssAudit.XssChecker(webView);
            var result = await checker.RunAsync(ct);
            ct.ThrowIfCancellationRequested();

            var signalFindings = result.Findings
                .Where(f => !XssHygieneCategories.Contains(f.Category))
                .ToList();

            foreach (var finding in signalFindings)
            {
                AddFinding(new ShadowFinding
                {
                    Url = url,
                    Audit = "xss",
                    Severity = CapHeuristicXssSeverity(finding.Category, MapXssSeverity(finding.Severity)),
                    Title = finding.Category,
                    Description = finding.Description,
                    Recommendation = finding.Recommendation
                });
            }

            if (Config.Suggestions && signalFindings.Count > 0)
            {
                AddSuggestion(new ShadowSuggestion
                {
                    Trigger = $"{signalFindings.Count} DOM XSS indicators on {url}",
                    Suggestion = "Run browser_trace_input on input fields with XSS payloads to trace whether user input reaches dangerous sinks.",
                    McpTool = "browser_trace_input",
                    ApiMethod = "POST",
                    ApiUrl = "/api/security/trace-input"
                });
            }

            await RunTabnabbingCheckAsync(webView, url, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private async Task RunTabnabbingCheckAsync(WebView2 webView, string url, CancellationToken ct)
    {
        try
        {
            var jsonTask = await webView.Dispatcher.InvokeAsync(() =>
                webView.CoreWebView2.ExecuteScriptAsync(
                    """
                    (function(){
                        var n = 0;
                        document.querySelectorAll('a[target="_blank"]').forEach(function(a){
                            var rel = (a.getAttribute('rel')||'').toLowerCase();
                            if (rel.indexOf('noopener') < 0 && rel.indexOf('noreferrer') < 0) n++;
                        });
                        return String(n);
                    })()
                    """));
            var json = await jsonTask;
            ct.ThrowIfCancellationRequested();
            var raw = (json ?? "0").Trim().Trim('"');
            if (int.TryParse(raw, out var count) && count > 0)
            {
                AddFinding(new ShadowFinding
                {
                    Url = url,
                    Audit = "tabnabbing",
                    Severity = Severity.Low,
                    Title = "Reverse tabnabbing: target=_blank without noopener",
                    Description = $"{count} link(s) open in a new tab without rel=noopener/noreferrer, so the opened page can access window.opener.",
                    Recommendation = "Add rel=\"noopener noreferrer\" to target=_blank links."
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private async Task RunMixedContentAudit(WebView2 webView, string url, CancellationToken ct)
    {
        try
        {
            var checker = new MixedContent.MixedContentChecker(webView);
            var result = await checker.RunAsync(ct);
            ct.ThrowIfCancellationRequested();

            foreach (var finding in result.Findings)
            {
                var desc = $"<{finding.Tag} {finding.Attribute}=\"{finding.Url}\">";
                if (!string.IsNullOrEmpty(finding.Context))
                    desc += $" ({finding.Context})";

                AddFinding(new ShadowFinding
                {
                    Url = url,
                    Audit = "mixed-content",
                    Severity = MapMixedContentSeverity(finding.Severity),
                    Title = $"Mixed content: {finding.Tag} loaded over HTTP",
                    Description = desc,
                    Recommendation = "Serve all resources over HTTPS to prevent mixed content issues."
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private async Task RunSourceMapAudit(WebView2 webView, string url, CancellationToken ct)
    {
        try
        {
            var checker = new SourceMapChecker(webView);
            var result = await checker.RunAsync(ct);
            ct.ThrowIfCancellationRequested();

            foreach (var finding in result.Findings)
            {
                AddFinding(new ShadowFinding
                {
                    Url = url,
                    Audit = "source-maps",
                    Severity = finding.Severity,
                    Title = finding.Description,
                    Description = finding.Detail ?? finding.Description,
                    Recommendation = finding.Recommendation ?? SourceMapChecker.SourceMapAccessRecommendation
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private async Task RunStorageAudit(WebView2 webView, string url, CancellationToken ct)
    {
        try
        {
            var localJson = await RunJsOnUiThread(webView,
                "JSON.stringify(Object.entries(localStorage).map(([k,v])=>({key:k,value:v})))");
            var sessionJson = await RunJsOnUiThread(webView,
                "JSON.stringify(Object.entries(sessionStorage).map(([k,v])=>({key:k,value:v})))");
            ct.ThrowIfCancellationRequested();

            var local = DeserializeStorageItems(localJson);
            var session = DeserializeStorageItems(sessionJson);

            var result = new StorageAuditChecker().Run(url, local, session);
            foreach (var finding in result.Findings)
            {
                AddFinding(new ShadowFinding
                {
                    Url = url,
                    Audit = "storage",
                    Severity = finding.Severity,
                    Title = $"{finding.StorageType}.{finding.Key}: {finding.Category}",
                    Description = finding.Description,
                    Recommendation = finding.Recommendation
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private async Task RunRetireJsAudit(WebView2 webView, string url, CancellationToken ct)
    {
        try
        {
            var result = await new SecurityChecker(webView).RunAsync(ct, includeFileContent: false);
            ct.ThrowIfCancellationRequested();

            foreach (var lib in result.Vulnerable)
            {
                var vulns = lib.Vulnerabilities.OrderByDescending(v => v.Severity).ToList();
                var top = vulns.FirstOrDefault();
                var cves = vulns.SelectMany(v => v.CVEs).Distinct().Take(6).ToList();
                var cveText = cves.Count > 0 ? string.Join(", ", cves) : "(no CVE)";
                var extra = vulns.Count > 1 ? $" (+{vulns.Count - 1} more)" : "";

                AddFinding(new ShadowFinding
                {
                    Url = url,
                    Audit = "retire-js",
                    Severity = lib.HighestSeverity ?? Severity.Medium,
                    Title = $"Vulnerable library: {lib.Name} {lib.Version}",
                    Description = $"{lib.Name} {lib.Version} ({cveText}{extra}). Detected via {lib.DetectionMethod}."
                        + (top != null && !string.IsNullOrEmpty(top.Summary) ? $" {top.Summary}" : ""),
                    Recommendation = $"Upgrade {lib.Name} to a version that is not affected"
                        + (top?.Below != null ? $" (fixed in {top.Below}+)." : ".")
                });
            }

            if (Config.Suggestions && result.VulnerableCount > 0)
            {
                AddSuggestion(new ShadowSuggestion
                {
                    Trigger = $"{result.VulnerableCount} vulnerable JavaScript librar{(result.VulnerableCount == 1 ? "y" : "ies")} on {url}",
                    Suggestion = "Run browser_security_js_libraries (Retire.js) or browser_security_supply_chain_scan for CVE details and OSV cross-check.",
                    McpTool = "browser_security_js_libraries",
                    ApiMethod = "POST",
                    ApiUrl = "/api/security/js-libraries"
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private async Task RunWcagAudit(WebView2 webView, string url, CancellationToken ct)
    {
        try
        {
            var result = await new AccessibilityChecker(webView).RunAsync("AA", cancellationToken: ct);
            ct.ThrowIfCancellationRequested();

            foreach (var v in result.Violations)
            {
                var example = v.Nodes.Count > 0 && v.Nodes[0].Target.Count > 0
                    ? v.Nodes[0].Target[0]
                    : "";
                AddFinding(new ShadowFinding
                {
                    Url = url,
                    Audit = "wcag",
                    Severity = MapAxeImpact(v.Impact),
                    Title = $"{v.RuleId}: {v.Help}",
                    Description = $"{v.Description} ({v.Count} element(s))"
                        + (example.Length > 0 ? $" e.g. {example}" : ""),
                    Recommendation = string.IsNullOrEmpty(v.HelpUrl) ? v.Help : v.HelpUrl
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    /// <summary>
    /// Ambient client-side sensor: install hooks and turn sink/listener events into findings/suggestions.
    /// Opt-in via audits including <c>runtime</c> (not part of pack <c>all</c>).
    /// </summary>
    private async Task RunRuntimeAudit(WebView2 webView, string url, BrowserTab tab, CancellationToken ct)
    {
        try
        {
            await await webView.Dispatcher.InvokeAsync(async () =>
            {
                try
                {
                    if (string.IsNullOrEmpty(tab.RuntimeEvents.DocumentScriptId))
                    {
                        var id = await webView.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(
                            RuntimeSensorScript.Build(RuntimeSensorProfile.Ambient));
                        tab.RuntimeEvents.DocumentScriptId = id;
                    }
                    await webView.CoreWebView2.ExecuteScriptAsync(
                        RuntimeSensorScript.Build(RuntimeSensorProfile.Ambient));
                    tab.RuntimeEvents.Installed = true;
                }
                catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }
            });
            ct.ThrowIfCancellationRequested();

            var events = tab.RuntimeEvents.All();
            var sinkHits = events.Where(e => e.Kind.Equals("sink", StringComparison.OrdinalIgnoreCase)).ToList();
            var interestingSinks = sinkHits
                .Where(e => e.Name is "eval" or "Function" or "innerHTML" or "outerHTML"
                    or "insertAdjacentHTML" or "document.write" or "document.writeln"
                    or "setAttribute" or "location.assign" or "location.replace")
                .GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                .Take(12);

            foreach (var g in interestingSinks)
            {
                var sample = g.First();
                var sourceHint = InferSourceHint(events, sample);
                var isCodeExec = g.Key is "eval" or "Function";
                if (!isCodeExec && sourceHint == null)
                    continue;

                AddFinding(new ShadowFinding
                {
                    Url = url,
                    Audit = "runtime",
                    Severity = isCodeExec ? Severity.High : Severity.Medium,
                    Title = $"Runtime sink: {g.Key} ({g.Count()} call(s))",
                    Description = $"Dangerous sink '{g.Key}' fired during browsing."
                        + (sourceHint != null ? $" Nearby source read: {sourceHint}." : "")
                        + (string.IsNullOrEmpty(sample.Data) ? "" : $" Sample: {Truncate(sample.Data, 160)}"),
                    Recommendation = "Run browser_client_surface then browser_trace_input with monitorSinks:true to confirm source→sink flow."
                });
            }

            var messageListeners = events
                .Where(e => e.Kind.Equals("listener", StringComparison.OrdinalIgnoreCase)
                            && e.Name.Equals("message", StringComparison.OrdinalIgnoreCase))
                .Take(8)
                .ToList();

            if (Config.Suggestions && messageListeners.Count > 0)
            {
                AddSuggestion(new ShadowSuggestion
                {
                    Trigger = $"{messageListeners.Count} postMessage listener(s) registered on {url}",
                    Suggestion = "Run browser_postmessage_audit to grade origin checks and fuzz foreign origins.",
                    McpTool = "browser_postmessage_audit",
                    ApiMethod = "POST",
                    ApiUrl = "/api/security/postmessage"
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private static string? InferSourceHint(IReadOnlyList<RuntimeEvent> events, RuntimeEvent sink)
    {
        var nearby = events
            .Where(e => e.Kind.Equals("source", StringComparison.OrdinalIgnoreCase)
                        && Math.Abs((e.Timestamp - sink.Timestamp).TotalMilliseconds) < 2_000)
            .Select(e => e.Name)
            .FirstOrDefault();
        return nearby;
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max];

    #endregion

    #region Helpers

    private bool ShouldRun(string auditName, bool partOfAll = true) =>
        (partOfAll && Config.Audits.Contains("all")) || Config.Audits.Contains(auditName);

    private bool IsInScope(string url)
    {
        if (string.IsNullOrEmpty(url) || url.StartsWith("data:") || url.StartsWith("about:")) return false;

        if (Config.Scope == "all") return true;

        // HTTP(S) document URLs only — follows the current page host per call (no "first site wins" pinning).
        if (Config.Scope == "same-origin")
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return false;
            return uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                || uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        }

        // Treat scope as a URL substring/regex pattern
        try
        {
            return System.Text.RegularExpressions.Regex.IsMatch(url, Config.Scope, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }
        catch
        {
            return url.Contains(Config.Scope, StringComparison.OrdinalIgnoreCase);
        }
    }

    private void AddFinding(ShadowFinding finding)
    {
        int newCount;
        lock (_lock)
        {
            if (Config.Deduplication)
            {
                var key = finding.DeduplicationKey;
                if (_dedup.TryGetValue(key, out var existing))
                {
                    existing.Timestamp = DateTime.UtcNow;
                    if (!string.IsNullOrEmpty(finding.Url)
                        && !existing.SeenOnUrls.Contains(finding.Url, StringComparer.OrdinalIgnoreCase))
                    {
                        existing.SeenOnUrls.Add(finding.Url);
                        existing.Occurrences++;
                    }
                    return;
                }
                finding.FirstSeen = finding.Timestamp;
                if (!string.IsNullOrEmpty(finding.Url))
                    finding.SeenOnUrls = [finding.Url];
                _dedup[key] = finding;
            }
            else
            {
                finding.FirstSeen = finding.Timestamp;
            }

            _findings.Add(finding);

            // FIFO eviction of lowest-severity findings when over cap
            if (_findings.Count > Config.MaxFindings)
            {
                var lowest = _findings.OrderBy(f => f.Severity).ThenBy(f => f.Timestamp).First();
                _findings.Remove(lowest);
                _dedup.Remove(lowest.DeduplicationKey);
            }

            newCount = _findings.Count(f => f.Id > _lastPolledFindingId);
        }

        FindingsAdded?.Invoke(newCount, finding.Severity);
    }

    private void AddSuggestion(ShadowSuggestion suggestion)
    {
        lock (_lock)
        {
            // Deduplicate suggestions by API URL
            if (suggestion.ApiUrl != null && _suggestions.Any(s => s.ApiUrl == suggestion.ApiUrl))
                return;
            _suggestions.Add(suggestion);
        }
        SuggestionAdded?.Invoke(suggestion);
    }

    private static bool LooksLikeSensitiveQueryParam(string query)
    {
        var sensitivePatterns = new[] { "token=", "key=", "api_key=", "apikey=", "password=", "secret=", "access_token=", "auth=", "jwt=" };
        return sensitivePatterns.Any(p => query.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<List<Dictionary<string, object>>> GetCookiesForShadowAuditAsync(WebView2 webView, string url)
    {
        try
        {
            var json = System.Text.Json.JsonSerializer.Serialize(new { urls = new[] { url } });
            var resultJson = await await webView.Dispatcher.InvokeAsync(async () =>
                await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Network.getCookies", json));

            using var doc = System.Text.Json.JsonDocument.Parse(resultJson);
            var cookies = new List<Dictionary<string, object>>();
            if (!doc.RootElement.TryGetProperty("cookies", out var cookiesArray))
                return cookies;

            foreach (var c in cookiesArray.EnumerateArray())
            {
                var name = c.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                var value = c.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
                var domain = c.TryGetProperty("domain", out var d) ? d.GetString() ?? "" : "";
                var path = c.TryGetProperty("path", out var p) ? p.GetString() ?? "/" : "/";
                var secure = c.TryGetProperty("secure", out var s) && s.GetBoolean();
                var httpOnly = c.TryGetProperty("httpOnly", out var h) && h.GetBoolean();
                var sameSite = c.TryGetProperty("sameSite", out var ss) ? ss.GetString()?.ToLower() ?? "lax" : "lax";
                var expires = c.TryGetProperty("expires", out var exp) ? exp.GetDouble() : -1;
                var isSession = expires <= 0;

                var row = new Dictionary<string, object>
                {
                    ["name"] = name, ["value"] = value, ["domain"] = domain, ["path"] = path,
                    ["secure"] = secure, ["httpOnly"] = httpOnly, ["sameSite"] = sameSite, ["session"] = isSession
                };
                if (!isSession)
                {
                    var dt = DateTimeOffset.FromUnixTimeSeconds((long)expires).UtcDateTime;
                    row["expires"] = dt.ToString("O");
                }
                cookies.Add(row);
            }

            return cookies;
        }
        catch
        {
            return new List<Dictionary<string, object>>();
        }
    }

    private static async Task<string> RunJsOnUiThread(WebView2 webView, string script)
    {
        return await await webView.Dispatcher.InvokeAsync(async () =>
        {
            var raw = await webView.CoreWebView2.ExecuteScriptAsync(script);
            if (raw.StartsWith('"') && raw.EndsWith('"'))
                return System.Text.Json.JsonSerializer.Deserialize<string>(raw) ?? "";
            return raw == "null" ? "" : raw;
        });
    }

    private static Severity MapAxeImpact(Impact impact) => impact switch
    {
        Impact.Critical => Severity.High,
        Impact.Serious => Severity.Medium,
        Impact.Moderate => Severity.Low,
        _ => Severity.Info
    };

    private static Severity MapXssSeverity(XssSeverity xss) => xss switch
    {
        XssSeverity.High => Severity.High,
        XssSeverity.Medium => Severity.Medium,
        XssSeverity.Low => Severity.Low,
        _ => Severity.Low // Info maps to Low
    };

    /// <summary>
    /// Heuristic-only XSS categories (source↔sink proximity, no taint proof) stay info/low
    /// until confirmed by active tools (trace-input / xss-scan).
    /// </summary>
    private static Severity CapHeuristicXssSeverity(string? category, Severity mapped)
    {
        if (string.Equals(category, "dom-xss-flow", StringComparison.OrdinalIgnoreCase))
            return Severity.Info;
        if (string.Equals(category, "dangerous-sink", StringComparison.OrdinalIgnoreCase)
            && mapped > Severity.Low)
            return Severity.Low;
        return mapped;
    }

    private static Severity MapMixedContentSeverity(MixedContentSeverity mc) => mc switch
    {
        MixedContentSeverity.High => Severity.High,
        MixedContentSeverity.Medium => Severity.Medium,
        MixedContentSeverity.Low => Severity.Low,
        _ => Severity.Low
    };

    private static Dictionary<string, string> DeserializeStorageItems(string json)
    {
        if (string.IsNullOrEmpty(json) || json == "[]" || json == "null")
            return new();
        try
        {
            var items = System.Text.Json.JsonSerializer.Deserialize<List<Dictionary<string, string>>>(json);
            if (items == null) return new();
            var result = new Dictionary<string, string>();
            foreach (var item in items)
            {
                if (item.TryGetValue("key", out var key) && item.TryGetValue("value", out var value))
                    result[key] = value;
            }
            return result;
        }
        catch { return new(); }
    }

    /// <summary>Format findings for LLM/text consumption.</summary>
    public string FormatFindings()
    {
        List<ShadowFinding> findings;
        List<ShadowSuggestion> suggestions;
        lock (_lock)
        {
            findings = [.. _findings];
            suggestions = [.. _suggestions];
        }

        if (findings.Count == 0 && suggestions.Count == 0)
            return $"Shadow: {_pagesAudited} page(s) audited, no findings.";

        var lines = new List<string>
        {
            $"=== Shadow Report ===",
            $"Pages audited: {_pagesAudited}",
            $"Findings: {findings.Count}",
            ""
        };

        var grouped = findings.GroupBy(f => f.Audit).OrderByDescending(g => g.Max(f => f.Severity));
        foreach (var group in grouped)
        {
            lines.Add($"--- {group.Key} ({group.Count()}) ---");
            foreach (var f in group.OrderByDescending(f => f.Severity))
            {
                lines.Add($"  [{f.Severity}] {f.Title}");
                if (f.Occurrences > 1) lines.Add($"    Occurrences: {f.Occurrences}");
                if (f.Occurrences > 1 && f.FormatSeenOnDomains() is { } domains)
                    lines.Add($"    Domains: {domains}");
                lines.Add($"    {f.Description}");
                if (f.Recommendation != null) lines.Add($"    Recommendation: {f.Recommendation}");
            }
            lines.Add("");
        }

        if (suggestions.Count > 0)
        {
            lines.Add("--- Suggestions ---");
            foreach (var s in suggestions)
            {
                lines.Add($"  Trigger: {s.Trigger}");
                lines.Add($"  -> {s.Suggestion}");
                if (s.McpTool != null) lines.Add($"     MCP: {s.McpTool}");
                else if (s.ApiUrl != null) lines.Add($"     API: {s.ApiMethod} {s.ApiUrl}");
                lines.Add("");
            }
        }

        return string.Join(Environment.NewLine, lines);
    }

    #endregion

    private readonly HashSet<string> _cswshTestedUrls = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Ambient CSWSH probe when shadow is enabled and a WebSocket connection is observed.</summary>
    public void OnWebSocketConnection(WebSocket.WebSocketConnection conn, AutomationContext ctx)
    {
        if (!Config.Enabled) return;
        if (!Config.Audits.Contains("all") && !Config.Audits.Contains("websocket") && !Config.Audits.Contains("cswsh"))
            return;

        var normalized = WebSocket.WebSocketAuditor.NormalizeConnectionUrl(conn.Url);
        lock (_lock)
        {
            if (!_cswshTestedUrls.Add(normalized))
                return;
        }

        _ = Task.Run(() => RunAmbientCswshAsync(conn, ctx));
    }

    private async Task RunAmbientCswshAsync(WebSocket.WebSocketConnection conn, AutomationContext ctx)
    {
        try
        {
            var cookieHeader = await ctx.GetCookieHeaderForUrl(conn.Url);
            Dictionary<string, string>? cookies = null;
            if (!string.IsNullOrEmpty(cookieHeader))
            {
                cookies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var part in cookieHeader.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var eq = part.IndexOf('=');
                    if (eq > 0)
                        cookies[part[..eq].Trim()] = part[(eq + 1)..].Trim();
                }
            }

            var sendAfter = conn.Url.Contains("graphql", StringComparison.OrdinalIgnoreCase)
                ? WebSocket.WebSocketJsBridge.GraphqlWsConnectionInit()
                : null;

            var result = await WebSocket.CswshTester.TestAsync(new WebSocket.CswshTester.CswshOptions
            {
                TargetUrl = conn.Url,
                AttackerOrigin = "https://evil.example.com",
                Cookies = cookies,
                SendAfterConnect = sendAfter,
                MonitorMs = 3000,
                TimeoutMs = 8000
            });

            if (result.Vulnerable)
            {
                AddCustomFinding(
                    result.Severity == "critical" ? Severity.Critical : Severity.High,
                    "Cross-Site WebSocket Hijacking (CSWSH)",
                    result.Detail,
                    "Validate the Origin header on WebSocket upgrade requests.",
                    "cswsh-auto",
                    conn.Url);
            }
        }
        catch
        {
            // ambient probe — best effort
        }
    }
}
