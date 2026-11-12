using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.EndpointProbe;

namespace Trowser.Security;

/// <summary>
/// Identifies which cookies, headers, and token fields actually gate a captured request
/// by replaying a baseline then omitting / one-character-tampering each candidate.
/// </summary>
public sealed class AuthControlIdentifier
{
    private static readonly HashSet<string> HopByHopHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Content-Length", "Connection", "Transfer-Encoding", "Keep-Alive",
        "Proxy-Connection", "TE", "Trailer", "Upgrade"
    };

    private static readonly HashSet<string> ExactInterestHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Proxy-Authorization", "RequestVerificationToken",
        "__RequestVerificationToken", "X-CSRF-Token", "X-XSRF-TOKEN", "X-CSRFToken",
        "X-Access-Token", "X-Auth-Token", "X-Api-Key", "Api-Key", "API-Key"
    };

    private static readonly string[] NameInterestMarkers =
    [
        "token", "auth", "csrf", "xsrf", "jwt", "session", "bearer",
        "apikey", "api-key", "api_key", "credential", "nonce", "verification"
    ];

    private static readonly AuthzBodyMatchOptions BodyMatchOptions = new()
    {
        Strategy = AuthzBodyMatchStrategy.NormalizedJson
    };

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public AuthControlIdentifier(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class ProbeOptions
    {
        public required IReadOnlyList<EndpointProbeItem> Endpoints { get; init; }
        public bool AllHeaders { get; init; }
        public int TimeoutMs { get; init; } = 12_000;
        public bool IncludeBodyFields { get; init; } = true;
        public bool IncludeQueryFields { get; init; } = true;
    }

    public enum CandidateKind
    {
        Cookie,
        Header,
        /// <summary>Cookie and header with matching token names and identical values (e.g. X-XSRF-TOKEN).</summary>
        CookieHeaderPair,
        Body,
        Query
    }

    public enum MutationKind
    {
        Omit,
        Tamper
    }

    /// <summary>Combined leave-one-out classification for one candidate.</summary>
    public enum ControlVerdict
    {
        /// <summary>Baseline was not a success response — cannot classify.</summary>
        Inconclusive,
        /// <summary>Sent but neither omit nor tamper changed the response.</summary>
        Ignored,
        /// <summary>Omit changes response; tamper does not — existence check only.</summary>
        PresenceOnly,
        /// <summary>Both omit and tamper change the response — value is enforced.</summary>
        Enforced,
        /// <summary>Tamper changes response but omit does not (rare).</summary>
        ValueCheckedButOptional
    }

    public sealed class Candidate
    {
        public CandidateKind Kind { get; init; }
        public string Name { get; init; } = "";
        public string OriginalValue { get; init; } = "";
        /// <summary>When <see cref="Kind"/> is <see cref="CandidateKind.CookieHeaderPair"/>.</summary>
        public string? PairedCookieName { get; init; }
        /// <summary>When <see cref="Kind"/> is <see cref="CandidateKind.CookieHeaderPair"/>.</summary>
        public string? PairedHeaderName { get; init; }
    }

    public sealed class MutationResult
    {
        public MutationKind Mutation { get; init; }
        public int Status { get; init; }
        public string Body { get; init; } = "";
        public bool BodiesMatchBaseline { get; init; }
        public bool ResponseChanged { get; init; }
        public string? TamperedValue { get; init; }
    }

    public sealed class CandidateResult
    {
        public string Method { get; init; } = "";
        public string Url { get; init; } = "";
        public Candidate Candidate { get; init; } = new();
        public ControlVerdict Verdict { get; init; }
        public MutationResult? Omit { get; init; }
        public MutationResult? Tamper { get; init; }
        public Dictionary<string, string> BaselineHeaders { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string? BaselineBody { get; init; }
        /// <summary>When an enforced cookie lacks HttpOnly, Secure, or SameSite≥Lax.</summary>
        public string? CookieFlagWarning { get; init; }
    }

    public sealed class ResultRow
    {
        public string Method { get; init; } = "";
        public string Url { get; init; } = "";
        public string Kind { get; init; } = "";
        public string Name { get; init; } = "";
        public string Mutation { get; init; } = "";
        public int BaselineStatus { get; init; }
        public int ProbeStatus { get; init; }
        public bool BodiesMatch { get; init; }
        public bool ResponseChanged { get; init; }
        public string Verdict { get; init; } = "";
        public string? OriginalValue { get; init; }
        public string? MutatedValue { get; init; }
        /// <summary>Warning glyph for the Flags column (empty when none).</summary>
        public string FlagWarningIcon { get; init; } = "";
        public string? CookieFlagWarning { get; init; }

        /// <summary>Headers for Request Editor open (omit or tampered variant).</summary>
        public Dictionary<string, string> MutatedHeaders { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string? MutatedBody { get; init; }
        public string MutatedUrl { get; init; } = "";
    }

    public sealed class ConsistencyEntry
    {
        public string Kind { get; init; } = "";
        public string Name { get; init; } = "";
        public string Verdict { get; init; } = "";
        public int EndpointCount { get; init; }
        public int MatchingCount { get; init; }
        public string Summary { get; init; } = "";
    }

    public sealed class EndpointProbeSummary
    {
        public string Method { get; init; } = "";
        public string Url { get; init; } = "";
        public int CandidatesTested { get; init; }
        public bool Inconclusive { get; init; }
        public string? Warning { get; init; }
    }

    public sealed class ScanResult
    {
        public List<CandidateResult> Candidates { get; init; } = [];
        public List<ResultRow> Rows { get; init; } = [];
        public List<ConsistencyEntry> Consistency { get; init; } = [];
        public List<EndpointProbeSummary> EndpointSummaries { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public int EndpointsProbed { get; init; }
        public int CandidatesTested { get; init; }
        public int RequestsSent { get; init; }
    }

    public async Task<ScanResult> RunAsync(ProbeOptions options, CancellationToken ct = default)
    {
        var candidates = new List<CandidateResult>();
        var rows = new List<ResultRow>();
        var endpointSummaries = new List<EndpointProbeSummary>();
        var requestsSent = 0;
        var endpointsProbed = 0;

        var cookieJar = await LoadCookieJarAsync();

        foreach (var endpoint in options.Endpoints)
        {
            ct.ThrowIfCancellationRequested();
            endpointsProbed++;

            var body = endpoint.RequestBody;
            var method = string.IsNullOrWhiteSpace(endpoint.Method) ? "GET" : endpoint.Method.Trim().ToUpperInvariant();
            var url = endpoint.Url;
            var templateHadCookie = endpoint.RequestHeaders.ContainsKey("Cookie");
            var headers = FilterReplayHeaders(endpoint.RequestHeaders);
            headers = MergeSessionCookiesFromJar(url, headers, cookieJar);

            _log($"AuthControlIdentifier: {method} {url}", "#569CD6");

            var baseline = await SecurityProbeHttp.FetchAsync(
                _ctx, url, method, headers, body, options.TimeoutMs,
                includeBrowserCookies: false, ct);
            requestsSent++;

            var baselineOk = ExceptionalConditionHeuristics.IsSuccessStatus(baseline.Status);
            if (!baselineOk)
            {
                _log($"  Baseline HTTP {baseline.Status} — classifications may be inconclusive", "#CCA700");
            }
            else
            {
                _log($"  Baseline HTTP {baseline.Status}", "#888888");
            }

            var probeCandidates = CollectCandidates(url, headers, body, options);
            if (probeCandidates.Count == 0)
            {
                _log("  No auth-related candidates found", "#CCA700");
                if (!templateHadCookie && JarHasSessionCookiesForUrl(cookieJar, url))
                {
                    endpointSummaries.Add(new EndpointProbeSummary
                    {
                        Method = method,
                        Url = url,
                        CandidatesTested = 0,
                        Inconclusive = true,
                        Warning = "session-cookie-not-in-baseline"
                    });
                    _log("  Warning: session cookies exist in jar but Cookie header was missing from the replay template", "#CCA700");
                }
                continue;
            }

            _log($"  Testing {probeCandidates.Count} candidate(s)", "#888888");

            foreach (var candidate in probeCandidates)
            {
                ct.ThrowIfCancellationRequested();

                MutationResult? omitResult = null;
                MutationResult? tamperResult = null;
                Dictionary<string, string>? omitHeaders = null;
                string? omitBody = null;
                string omitUrl = url;
                Dictionary<string, string>? tamperHeaders = null;
                string? tamperBody = null;
                string tamperUrl = url;

                // Omit
                {
                    ApplyMutation(url, headers, body, candidate, MutationKind.Omit, out omitUrl, out omitHeaders, out omitBody, out _);
                    var resp = await SecurityProbeHttp.FetchAsync(
                        _ctx, omitUrl, method, omitHeaders, omitBody, options.TimeoutMs,
                        includeBrowserCookies: false, ct);
                    requestsSent++;
                    omitResult = BuildMutationResult(MutationKind.Omit, baseline, resp, null);
                }

                // Tamper (skip empty values)
                if (!string.IsNullOrEmpty(candidate.OriginalValue))
                {
                    ApplyMutation(url, headers, body, candidate, MutationKind.Tamper, out tamperUrl, out tamperHeaders, out tamperBody, out var tamperedValue);
                    var resp = await SecurityProbeHttp.FetchAsync(
                        _ctx, tamperUrl, method, tamperHeaders, tamperBody, options.TimeoutMs,
                        includeBrowserCookies: false, ct);
                    requestsSent++;
                    tamperResult = BuildMutationResult(MutationKind.Tamper, baseline, resp, tamperedValue);
                }

                var verdict = Classify(baselineOk, omitResult, tamperResult);
                string? cookieFlagWarning = null;
                if (verdict == ControlVerdict.Enforced &&
                    (candidate.Kind == CandidateKind.Cookie ||
                     candidate.Kind == CandidateKind.CookieHeaderPair))
                {
                    var cookieName = candidate.Kind == CandidateKind.CookieHeaderPair
                        ? candidate.PairedCookieName ?? candidate.Name
                        : candidate.Name;
                    cookieFlagWarning = EvaluateEnforcedCookieFlags(cookieName, cookieJar, url);
                    if (cookieFlagWarning != null)
                        _log($"  ⚠ {candidate.Name}: {cookieFlagWarning}", "#CCA700");
                }

                var candidateResult = new CandidateResult
                {
                    Method = method,
                    Url = url,
                    Candidate = candidate,
                    Verdict = verdict,
                    Omit = omitResult,
                    Tamper = tamperResult,
                    BaselineHeaders = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase),
                    BaselineBody = body,
                    CookieFlagWarning = cookieFlagWarning
                };
                candidates.Add(candidateResult);

                var verdictLabel = ToVerdictLabel(verdict);
                var color = VerdictColor(verdict);
                _log($"  {KindToLabel(candidate.Kind)} {candidate.Name}: {verdictLabel}" +
                     $" (omit={(omitResult?.ResponseChanged == true ? "changed" : "same")}" +
                     $", tamper={(tamperResult == null ? "n/a" : tamperResult.ResponseChanged ? "changed" : "same")})",
                    color);

                if (omitResult != null && omitHeaders != null)
                {
                    rows.Add(MakeRow(method, url, candidate, "omit", baseline.Status, omitResult,
                        verdictLabel, null, omitHeaders, omitBody, omitUrl, cookieFlagWarning));
                }

                if (tamperResult != null && tamperHeaders != null)
                {
                    rows.Add(MakeRow(method, url, candidate, "tamper", baseline.Status, tamperResult,
                        verdictLabel, tamperResult.TamperedValue, tamperHeaders, tamperBody, tamperUrl, cookieFlagWarning));
                }
            }
        }

        var consistency = BuildConsistency(candidates);
        var summary = BuildSummary(candidates, endpointsProbed, requestsSent, consistency);

        foreach (var line in summary)
            _log(line, "#CCCCCC");

        return new ScanResult
        {
            Candidates = candidates,
            Rows = rows,
            Consistency = consistency,
            EndpointSummaries = endpointSummaries,
            Summary = summary,
            EndpointsProbed = endpointsProbed,
            CandidatesTested = candidates.Count,
            RequestsSent = requestsSent
        };
    }

    internal static Dictionary<string, string> MergeSessionCookiesFromJar(
        string url,
        Dictionary<string, string> headers,
        IReadOnlyList<Dictionary<string, object>> cookieJar)
    {
        if (headers.ContainsKey("Cookie"))
            return headers;

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return headers;

        var pairs = new List<string>();
        foreach (var c in cookieJar)
        {
            var name = GetStr(c, "name");
            var value = GetStr(c, "value");
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(value)) continue;
            if (!SessionCookieDetector.IsSessionCookieName(name)) continue;
            if (!CookieAppliesToHost(c, uri.Host)) continue;
            pairs.Add($"{name}={value}");
        }

        if (pairs.Count == 0)
            return headers;

        var merged = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
        {
            ["Cookie"] = string.Join("; ", pairs)
        };
        return merged;
    }

    private static bool JarHasSessionCookiesForUrl(
        IReadOnlyList<Dictionary<string, object>> cookieJar,
        string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        return cookieJar.Any(c =>
        {
            var name = GetStr(c, "name");
            var value = GetStr(c, "value");
            return !string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(value)
                   && SessionCookieDetector.IsSessionCookieName(name)
                   && CookieAppliesToHost(c, uri.Host);
        });
    }

    private static bool CookieAppliesToHost(Dictionary<string, object> cookie, string host)
    {
        var domain = GetStr(cookie, "domain").TrimStart('.');
        if (string.IsNullOrEmpty(domain))
            return true;
        return host.Equals(domain, StringComparison.OrdinalIgnoreCase)
               || host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
    }

    private static ResultRow MakeRow(
        string method,
        string url,
        Candidate candidate,
        string mutation,
        int baselineStatus,
        MutationResult probe,
        string verdictLabel,
        string? mutatedValue,
        Dictionary<string, string> mutatedHeaders,
        string? mutatedBody,
        string mutatedUrl,
        string? cookieFlagWarning) => new()
    {
        Method = method,
        Url = url,
        Kind = KindToLabel(candidate.Kind),
        Name = candidate.Name,
        Mutation = mutation,
        BaselineStatus = baselineStatus,
        ProbeStatus = probe.Status,
        BodiesMatch = probe.BodiesMatchBaseline,
        ResponseChanged = probe.ResponseChanged,
        Verdict = verdictLabel,
        OriginalValue = TruncateValue(candidate.OriginalValue),
        MutatedValue = TruncateValue(mutatedValue),
        FlagWarningIcon = string.IsNullOrEmpty(cookieFlagWarning) ? "" : "⚠",
        CookieFlagWarning = cookieFlagWarning,
        MutatedHeaders = mutatedHeaders,
        MutatedBody = mutatedBody,
        MutatedUrl = mutatedUrl
    };

    public static void LogMarkdownTable(Action<string, string> log, ScanResult result)
    {
        log("", "#CCCCCC");
        log("### Auth Control Identifier results", "#569CD6");
        log("| Endpoint | Kind | Name | Mutation | Baseline | Probe | Bodies match | Verdict | Flags |", "#888888");
        log("|---|---|---|---|---|---|---|---|---|", "#888888");
        foreach (var row in result.Rows)
        {
            var endpoint = $"{row.Method} {Truncate(row.Url, 60)}";
            var flags = string.IsNullOrEmpty(row.FlagWarningIcon) ? "" : "⚠";
            log($"| {endpoint} | {row.Kind} | {row.Name} | {row.Mutation} | {row.BaselineStatus} | {row.ProbeStatus} | {row.BodiesMatch} | {row.Verdict} | {flags} |",
                VerdictColorFromLabel(row.Verdict));
            if (!string.IsNullOrEmpty(row.CookieFlagWarning) && row.Mutation == "omit")
                log($"  ⚠ {row.Name}: {row.CookieFlagWarning}", "#CCA700");
        }

        if (result.Consistency.Count > 0)
        {
            log("", "#CCCCCC");
            log("### Consistency across endpoints", "#569CD6");
            foreach (var c in result.Consistency)
                log($"  {c.Summary}", "#CCCCCC");
        }
    }

    /// <summary>
    /// For an enforced auth cookie, return a warning when HttpOnly, Secure, or SameSite≥Lax is missing.
    /// Returns null when flags are adequate or the cookie is not in the jar.
    /// </summary>
    internal static string? EvaluateEnforcedCookieFlags(
        string cookieName,
        IReadOnlyList<Dictionary<string, object>> cookieJar,
        string? requestUrl = null)
    {
        var match = FindCookieInJar(cookieName, cookieJar, requestUrl);
        if (match == null)
            return null; // cannot assess — jar may be empty offline

        var missing = new List<string>();
        if (!GetBool(match, "httpOnly"))
            missing.Add("HttpOnly");
        if (!GetBool(match, "secure"))
            missing.Add("Secure");

        var sameSite = GetStr(match, "sameSite");
        if (!IsSameSiteAtLeastLax(sameSite))
            missing.Add($"SameSite≥Lax (is {FormatSameSite(sameSite)})");

        if (missing.Count == 0)
            return null;

        return $"Auth cookie lacks {string.Join(", ", missing)}. " +
               "XSS or cross-site requests may steal or attach this session cookie.";
    }

    internal static bool IsSameSiteAtLeastLax(string? sameSite)
    {
        var s = (sameSite ?? "").Trim().ToLowerInvariant();
        return s is "lax" or "strict";
    }

    private static string FormatSameSite(string? sameSite)
    {
        var s = (sameSite ?? "").Trim();
        if (string.IsNullOrEmpty(s)) return "unset";
        return s;
    }

    private static Dictionary<string, object>? FindCookieInJar(
        string cookieName,
        IReadOnlyList<Dictionary<string, object>> cookieJar,
        string? requestUrl)
    {
        string? host = null;
        if (!string.IsNullOrEmpty(requestUrl) && Uri.TryCreate(requestUrl, UriKind.Absolute, out var uri))
            host = uri.Host;

        var matches = cookieJar
            .Where(c => string.Equals(GetStr(c, "name"), cookieName, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (matches.Count == 0)
            return null;
        if (host == null || matches.Count == 1)
            return matches[0];

        var hostMatch = matches.FirstOrDefault(c =>
        {
            var domain = GetStr(c, "domain").TrimStart('.');
            return !string.IsNullOrEmpty(domain)
                   && (host.Equals(domain, StringComparison.OrdinalIgnoreCase)
                       || host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
        });
        return hostMatch ?? matches[0];
    }

    private static bool GetBool(Dictionary<string, object> cookie, string key)
    {
        if (!cookie.TryGetValue(key, out var val) || val == null)
            return false;
        return val switch
        {
            bool b => b,
            string s => bool.TryParse(s, out var p) && p,
            JsonElement je when je.ValueKind == JsonValueKind.True => true,
            JsonElement je when je.ValueKind == JsonValueKind.False => false,
            _ => false
        };
    }

    private static string GetStr(Dictionary<string, object> cookie, string key)
    {
        if (!cookie.TryGetValue(key, out var val) || val == null)
            return "";
        return val switch
        {
            string s => s,
            JsonElement je when je.ValueKind == JsonValueKind.String => je.GetString() ?? "",
            _ => val.ToString() ?? ""
        };
    }

    private async Task<List<Dictionary<string, object>>> LoadCookieJarAsync()
    {
        try
        {
            var cookies = await _ctx.GetCookies();
            try
            {
                var pageUrl = await _ctx.GetCurrentUrl();
                if (!string.IsNullOrEmpty(pageUrl))
                    CookieAuditChecker.MergeNetworkSetCookies(pageUrl, cookies, _ctx.GetNetworkLog());
            }
            catch
            {
                // Network merge is best-effort
            }
            return cookies;
        }
        catch
        {
            return [];
        }
    }

    internal static List<Candidate> CollectCandidates(
        string url,
        Dictionary<string, string> headers,
        string? body,
        ProbeOptions options)
    {
        var list = new List<Candidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Cookies — always all, individually
        if (headers.TryGetValue("Cookie", out var cookieHeader) && !string.IsNullOrWhiteSpace(cookieHeader))
        {
            foreach (var (name, value) in ParseCookieHeader(cookieHeader))
            {
                var key = $"cookie:{name}";
                if (!seen.Add(key)) continue;
                list.Add(new Candidate { Kind = CandidateKind.Cookie, Name = name, OriginalValue = value });
            }
        }

        // Headers
        foreach (var kv in headers)
        {
            if (kv.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
                continue;
            if (HopByHopHeaders.Contains(kv.Key))
                continue;
            if (!options.AllHeaders && !IsInterestingHeaderName(kv.Key))
                continue;

            var key = $"header:{kv.Key}";
            if (!seen.Add(key)) continue;
            list.Add(new Candidate { Kind = CandidateKind.Header, Name = kv.Key, OriginalValue = kv.Value ?? "" });
        }

        // Query fields
        if (options.IncludeQueryFields && Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var query = ParseQueryString(uri.Query);
            foreach (var kv in query)
            {
                if (!IsInterestingFieldName(kv.Key))
                    continue;
                var key = $"query:{kv.Key}";
                if (!seen.Add(key)) continue;
                list.Add(new Candidate { Kind = CandidateKind.Query, Name = kv.Key, OriginalValue = kv.Value ?? "" });
            }
        }

        // Body fields
        if (options.IncludeBodyFields && !string.IsNullOrEmpty(body))
        {
            foreach (var (name, value) in ParseBodyFields(body, headers))
            {
                if (!IsInterestingFieldName(name))
                    continue;
                var key = $"body:{name}";
                if (!seen.Add(key)) continue;
                list.Add(new Candidate { Kind = CandidateKind.Body, Name = name, OriginalValue = value });
            }
        }

        AddCookieHeaderPairCandidates(headers, list, seen);

        return list;
    }

    /// <summary>
    /// Optional leading <c>X-</c> on either side (e.g. header <c>X-XSRF-TOKEN</c> vs cookie <c>XSRF-TOKEN</c>).
    /// </summary>
    private static readonly Regex TokenPairNameCore = new(
        @"^(?:X-)?(?<core>.+)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    internal static string NormalizeTokenPairName(string name)
    {
        var trimmed = name.Trim();
        var m = TokenPairNameCore.Match(trimmed);
        return m.Success ? m.Groups["core"].Value : trimmed;
    }

    internal static bool CookieHeaderPairNamesMatch(string cookieName, string headerName)
    {
        if (cookieName.Equals(headerName, StringComparison.OrdinalIgnoreCase))
            return true;

        var cookieCore = NormalizeTokenPairName(cookieName);
        var headerCore = NormalizeTokenPairName(headerName);
        return cookieCore.Equals(headerCore, StringComparison.OrdinalIgnoreCase);
    }

    private static void AddCookieHeaderPairCandidates(
        Dictionary<string, string> headers,
        List<Candidate> list,
        HashSet<string> seen)
    {
        if (!headers.TryGetValue("Cookie", out var cookieHeader) || string.IsNullOrWhiteSpace(cookieHeader))
            return;

        var cookies = ParseCookieHeader(cookieHeader).ToList();
        if (cookies.Count == 0)
            return;

        var headerEntries = headers
            .Where(kv => !kv.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase)
                         && !HopByHopHeaders.Contains(kv.Key))
            .ToList();

        foreach (var (cookieName, cookieValue) in cookies)
        {
            if (string.IsNullOrEmpty(cookieValue))
                continue;

            foreach (var (headerName, headerValue) in headerEntries)
            {
                if (string.IsNullOrEmpty(headerValue))
                    continue;
                if (!CookieHeaderPairNamesMatch(cookieName, headerName))
                    continue;
                if (!string.Equals(cookieValue, headerValue, StringComparison.Ordinal))
                    continue;

                var headerInteresting = IsInterestingHeaderName(headerName);
                var cookieInteresting = IsInterestingFieldName(cookieName)
                                        || SessionCookieDetector.IsSessionCookieName(cookieName);
                if (!headerInteresting && !cookieInteresting)
                    continue;

                var pairKey = $"pair:{NormalizeTokenPairName(cookieName)}";
                if (!seen.Add(pairKey))
                    continue;

                var displayName = cookieName.Equals(headerName, StringComparison.OrdinalIgnoreCase)
                    ? cookieName
                    : $"{cookieName} + {headerName}";

                list.Add(new Candidate
                {
                    Kind = CandidateKind.CookieHeaderPair,
                    Name = displayName,
                    OriginalValue = cookieValue,
                    PairedCookieName = cookieName,
                    PairedHeaderName = headerName
                });
            }
        }
    }

    internal static string KindToLabel(CandidateKind kind) => kind switch
    {
        CandidateKind.CookieHeaderPair => "cookie+header",
        _ => kind.ToString().ToLowerInvariant()
    };

    internal static bool IsInterestingHeaderName(string name)
    {
        if (ExactInterestHeaders.Contains(name))
            return true;
        if (CsrfTokenHeuristics.IsCsrfHeaderName(name))
            return true;

        var lower = name.ToLowerInvariant();
        foreach (var marker in NameInterestMarkers)
        {
            if (lower.Contains(marker, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    internal static bool IsInterestingFieldName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;
        if (CsrfTokenHeuristics.IsKnownCsrfFieldName(name))
            return true;
        if (ExactInterestHeaders.Contains(name))
            return true;

        var lower = name.ToLowerInvariant();
        foreach (var marker in NameInterestMarkers)
        {
            if (lower.Contains(marker, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Flip one alphanumeric character near the middle of the value.
    /// Edge flips (first/last) are too weak for many cookies: base64 padding,
    /// ignored prefixes/suffixes, or truncated compares can leave edge changes accepted.
    /// </summary>
    internal static string TamperOneChar(string value)
    {
        if (string.IsNullOrEmpty(value))
            return value + "X";

        var alnumIndexes = new List<int>();
        for (var i = 0; i < value.Length; i++)
        {
            if (char.IsLetterOrDigit(value[i]))
                alnumIndexes.Add(i);
        }

        if (alnumIndexes.Count == 0)
            return value + "X";

        var target = alnumIndexes[alnumIndexes.Count / 2];
        var chars = value.ToCharArray();
        chars[target] = FlipAlnum(chars[target]);
        return new string(chars);
    }

    internal static ControlVerdict Classify(bool baselineOk, MutationResult? omit, MutationResult? tamper)
    {
        if (!baselineOk)
            return ControlVerdict.Inconclusive;

        var omitChanged = omit?.ResponseChanged == true;
        // No tamper possible (empty value) — classify from omit only
        if (tamper == null)
        {
            return omitChanged ? ControlVerdict.Enforced : ControlVerdict.Ignored;
        }

        var tamperChanged = tamper.ResponseChanged;
        return (omitChanged, tamperChanged) switch
        {
            (false, false) => ControlVerdict.Ignored,
            (true, false) => ControlVerdict.PresenceOnly,
            (true, true) => ControlVerdict.Enforced,
            (false, true) => ControlVerdict.ValueCheckedButOptional
        };
    }

    internal static Dictionary<string, string> FilterReplayHeaders(IReadOnlyDictionary<string, string>? headers)
    {
        var filtered = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (headers == null) return filtered;

        foreach (var kv in headers)
        {
            if (HopByHopHeaders.Contains(kv.Key))
                continue;
            filtered[kv.Key] = kv.Value;
        }
        return filtered;
    }

    private static MutationResult BuildMutationResult(
        MutationKind mutation,
        SecurityProbeHttp.FetchResult baseline,
        SecurityProbeHttp.FetchResult probe,
        string? tamperedValue)
    {
        var bodiesMatch = AuthzBodyMatcher.BodiesMatch(baseline.Body ?? "", probe.Body ?? "", BodyMatchOptions);
        var statusSame = baseline.Status == probe.Status;
        // Auth denial is always a change even if body somehow matches
        var denyFlip = ExceptionalConditionHeuristics.IsSuccessStatus(baseline.Status)
                       && ExceptionalConditionHeuristics.IsDenyStatus(probe.Status);
        var changed = denyFlip || !statusSame || !bodiesMatch;

        return new MutationResult
        {
            Mutation = mutation,
            Status = probe.Status,
            Body = probe.Body ?? "",
            BodiesMatchBaseline = bodiesMatch && statusSame && !denyFlip,
            ResponseChanged = changed,
            TamperedValue = tamperedValue
        };
    }

    internal static void ApplyMutation(
        string url,
        Dictionary<string, string> headers,
        string? body,
        Candidate candidate,
        MutationKind mutation,
        out string newUrl,
        out Dictionary<string, string> newHeaders,
        out string? newBody,
        out string? mutatedValue)
    {
        newUrl = url;
        newHeaders = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);
        newBody = body;
        mutatedValue = null;

        switch (candidate.Kind)
        {
            case CandidateKind.Cookie:
            {
                if (!newHeaders.TryGetValue("Cookie", out var cookieHeader))
                    break;
                var cookies = ParseCookieHeader(cookieHeader).ToList();
                if (mutation == MutationKind.Omit)
                {
                    cookies.RemoveAll(c => c.Name.Equals(candidate.Name, StringComparison.OrdinalIgnoreCase));
                }
                else
                {
                    for (var i = 0; i < cookies.Count; i++)
                    {
                        if (!cookies[i].Name.Equals(candidate.Name, StringComparison.OrdinalIgnoreCase))
                            continue;
                        mutatedValue = TamperOneChar(cookies[i].Value);
                        cookies[i] = (cookies[i].Name, mutatedValue);
                    }
                }

                if (cookies.Count == 0)
                    newHeaders.Remove("Cookie");
                else
                    newHeaders["Cookie"] = string.Join("; ", cookies.Select(c => $"{c.Name}={c.Value}"));
                break;
            }
            case CandidateKind.Header:
            {
                if (mutation == MutationKind.Omit)
                {
                    newHeaders.Remove(candidate.Name);
                }
                else
                {
                    mutatedValue = TamperOneChar(candidate.OriginalValue);
                    newHeaders[candidate.Name] = mutatedValue;
                }
                break;
            }
            case CandidateKind.CookieHeaderPair:
            {
                var cookieName = candidate.PairedCookieName ?? candidate.Name;
                var headerName = candidate.PairedHeaderName ?? candidate.Name;

                if (mutation == MutationKind.Tamper)
                    mutatedValue = TamperOneChar(candidate.OriginalValue);

                if (newHeaders.TryGetValue("Cookie", out var pairCookieHeader))
                {
                    var cookies = ParseCookieHeader(pairCookieHeader).ToList();
                    if (mutation == MutationKind.Omit)
                    {
                        cookies.RemoveAll(c => c.Name.Equals(cookieName, StringComparison.OrdinalIgnoreCase));
                    }
                    else if (mutatedValue != null)
                    {
                        for (var i = 0; i < cookies.Count; i++)
                        {
                            if (!cookies[i].Name.Equals(cookieName, StringComparison.OrdinalIgnoreCase))
                                continue;
                            cookies[i] = (cookies[i].Name, mutatedValue);
                        }
                    }

                    if (cookies.Count == 0)
                        newHeaders.Remove("Cookie");
                    else
                        newHeaders["Cookie"] = string.Join("; ", cookies.Select(c => $"{c.Name}={c.Value}"));
                }

                if (mutation == MutationKind.Omit)
                    newHeaders.Remove(headerName);
                else if (mutatedValue != null && newHeaders.ContainsKey(headerName))
                    newHeaders[headerName] = mutatedValue;

                break;
            }
            case CandidateKind.Query:
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                    break;
                var query = ParseQueryString(uri.Query);
                if (mutation == MutationKind.Omit)
                {
                    query.Remove(candidate.Name);
                }
                else
                {
                    mutatedValue = TamperOneChar(candidate.OriginalValue);
                    query[candidate.Name] = mutatedValue;
                }
                newUrl = RebuildUrl(uri, query);
                break;
            }
            case CandidateKind.Body:
            {
                newBody = MutateBodyField(body, headers, candidate.Name, mutation, candidate.OriginalValue, out mutatedValue);
                break;
            }
        }
    }

    private static string? MutateBodyField(
        string? body,
        Dictionary<string, string> headers,
        string fieldName,
        MutationKind mutation,
        string originalValue,
        out string? mutatedValue)
    {
        mutatedValue = null;
        if (string.IsNullOrEmpty(body))
            return body;

        var contentType = headers.GetValueOrDefault("Content-Type") ?? "";
        var trimmed = body.TrimStart();

        if (trimmed.StartsWith('{') || contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                    return body;

                using var stream = new MemoryStream();
                using (var writer = new Utf8JsonWriter(stream))
                {
                    writer.WriteStartObject();
                    foreach (var prop in doc.RootElement.EnumerateObject())
                    {
                        if (prop.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase))
                        {
                            if (mutation == MutationKind.Omit)
                                continue;
                            mutatedValue = TamperOneChar(originalValue);
                            writer.WriteString(prop.Name, mutatedValue);
                        }
                        else
                        {
                            prop.WriteTo(writer);
                        }
                    }
                    writer.WriteEndObject();
                }
                return Encoding.UTF8.GetString(stream.ToArray());
            }
            catch (JsonException)
            {
                // fall through to form parsing
            }
        }

        // form-urlencoded
        var pairs = ParseFormUrlEncoded(body);
        if (mutation == MutationKind.Omit)
        {
            pairs.RemoveAll(p => p.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            for (var i = 0; i < pairs.Count; i++)
            {
                if (!pairs[i].Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase))
                    continue;
                mutatedValue = TamperOneChar(pairs[i].Value);
                pairs[i] = (pairs[i].Name, mutatedValue);
            }
        }
        return string.Join("&", pairs.Select(p =>
            $"{Uri.EscapeDataString(p.Name)}={Uri.EscapeDataString(p.Value)}"));
    }

    private static IEnumerable<(string Name, string Value)> ParseBodyFields(string body, Dictionary<string, string> headers)
    {
        var contentType = headers.GetValueOrDefault("Content-Type") ?? "";
        var trimmed = body.TrimStart();

        if (trimmed.StartsWith('{') || contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            List<(string, string)>? jsonFields = null;
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    jsonFields = [];
                    foreach (var prop in doc.RootElement.EnumerateObject())
                    {
                        var value = prop.Value.ValueKind switch
                        {
                            JsonValueKind.String => prop.Value.GetString() ?? "",
                            JsonValueKind.Number => prop.Value.GetRawText(),
                            JsonValueKind.True => "true",
                            JsonValueKind.False => "false",
                            JsonValueKind.Null => "",
                            _ => prop.Value.GetRawText()
                        };
                        jsonFields.Add((prop.Name, value));
                    }
                }
            }
            catch (JsonException)
            {
                jsonFields = null;
            }

            if (jsonFields != null)
            {
                foreach (var f in jsonFields)
                    yield return f;
                yield break;
            }
        }

        foreach (var pair in ParseFormUrlEncoded(body))
            yield return pair;
    }

    private static List<(string Name, string Value)> ParseFormUrlEncoded(string body)
    {
        var result = new List<(string, string)>();
        foreach (var part in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0)
            {
                result.Add((Uri.UnescapeDataString(part.Replace('+', ' ')), ""));
                continue;
            }
            var name = Uri.UnescapeDataString(part[..eq].Replace('+', ' '));
            var value = Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' '));
            result.Add((name, value));
        }
        return result;
    }

    private static IEnumerable<(string Name, string Value)> ParseCookieHeader(string cookieHeader)
    {
        foreach (var part in cookieHeader.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var name = part[..eq].Trim();
            var value = part[(eq + 1)..].Trim();
            if (name.Length == 0) continue;
            yield return (name, value);
        }
    }

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query))
            return result;

        var q = query.StartsWith('?') ? query[1..] : query;
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0)
            {
                result[Uri.UnescapeDataString(part.Replace('+', ' '))] = "";
                continue;
            }
            var name = Uri.UnescapeDataString(part[..eq].Replace('+', ' '));
            var value = Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' '));
            result[name] = value;
        }
        return result;
    }

    private static string RebuildUrl(Uri uri, Dictionary<string, string> query)
    {
        var builder = new UriBuilder(uri) { Query = "" };
        if (query.Count == 0)
            return builder.Uri.ToString();

        var qs = string.Join("&", query.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value ?? "")}"));
        builder.Query = qs;
        return builder.Uri.ToString();
    }

    private static char FlipAlnum(char c)
    {
        if (c is >= '0' and <= '9')
            return c == '9' ? '0' : (char)(c + 1);
        if (c is >= 'a' and <= 'z')
            return c == 'z' ? 'a' : (char)(c + 1);
        if (c is >= 'A' and <= 'Z')
            return c == 'Z' ? 'A' : (char)(c + 1);
        return c;
    }

    private static List<ConsistencyEntry> BuildConsistency(List<CandidateResult> candidates)
    {
        var groups = candidates
            .Where(c => c.Verdict != ControlVerdict.Inconclusive)
            .GroupBy(c => $"{c.Candidate.Kind}:{c.Candidate.Name}", StringComparer.OrdinalIgnoreCase);

        var result = new List<ConsistencyEntry>();
        foreach (var g in groups)
        {
            var list = g.ToList();
            if (list.Count < 2) continue;

            var byVerdict = list.GroupBy(c => c.Verdict).OrderByDescending(x => x.Count()).First();
            var top = byVerdict.Key;
            var matching = byVerdict.Count();
            result.Add(new ConsistencyEntry
            {
                Kind = KindToLabel(list[0].Candidate.Kind),
                Name = list[0].Candidate.Name,
                Verdict = ToVerdictLabel(top),
                EndpointCount = list.Count,
                MatchingCount = matching,
                Summary = $"`{list[0].Candidate.Name}` ({list[0].Candidate.Kind.ToString().ToLowerInvariant()}) " +
                          $"{ToVerdictLabel(top)} on {matching}/{list.Count} endpoints"
            });
        }
        return result.OrderByDescending(c => c.EndpointCount).ToList();
    }

    private static List<string> BuildSummary(
        List<CandidateResult> candidates,
        int endpointsProbed,
        int requestsSent,
        List<ConsistencyEntry> consistency)
    {
        var summary = new List<string>
        {
            $"Auth Control Identifier: {endpointsProbed} endpoint(s), {candidates.Count} candidate(s), {requestsSent} request(s)."
        };

        var enforced = candidates.Count(c => c.Verdict == ControlVerdict.Enforced);
        var presence = candidates.Count(c => c.Verdict == ControlVerdict.PresenceOnly);
        var ignored = candidates.Count(c => c.Verdict == ControlVerdict.Ignored);
        var optional = candidates.Count(c => c.Verdict == ControlVerdict.ValueCheckedButOptional);
        var inconclusive = candidates.Count(c => c.Verdict == ControlVerdict.Inconclusive);
        var flagWarnings = candidates.Count(c => !string.IsNullOrEmpty(c.CookieFlagWarning));

        summary.Add($"  enforced={enforced}, presence-only={presence}, ignored={ignored}, " +
                    $"value-checked-but-optional={optional}, inconclusive={inconclusive}");
        if (flagWarnings > 0)
            summary.Add($"  ⚠ {flagWarnings} enforced cookie(s) missing HttpOnly, Secure, and/or SameSite≥Lax.");

        foreach (var c in consistency)
            summary.Add($"  Consistency: {c.Summary}");

        return summary;
    }

    public static string ToVerdictLabel(ControlVerdict verdict) => verdict switch
    {
        ControlVerdict.Enforced => "enforced",
        ControlVerdict.PresenceOnly => "presence-only",
        ControlVerdict.Ignored => "ignored",
        ControlVerdict.ValueCheckedButOptional => "value-checked-but-optional",
        _ => "inconclusive"
    };

    private static string VerdictColor(ControlVerdict verdict) => verdict switch
    {
        ControlVerdict.Enforced => "#4EC9B0",
        ControlVerdict.PresenceOnly => "#CCA700",
        ControlVerdict.Ignored => "#F44747",
        ControlVerdict.ValueCheckedButOptional => "#CE9178",
        _ => "#888888"
    };

    private static string VerdictColorFromLabel(string label) => label switch
    {
        "enforced" => "#4EC9B0",
        "presence-only" => "#CCA700",
        "ignored" => "#F44747",
        "value-checked-but-optional" => "#CE9178",
        _ => "#888888"
    };

    private static string TruncateValue(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= 48 ? value : value[..45] + "...";
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..(max - 3)] + "...";
}
