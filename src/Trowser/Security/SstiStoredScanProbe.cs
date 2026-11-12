using System.Diagnostics;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Stored SSTI: POST template expressions to profile-shaped fields, then GET readback for evaluated marker.
/// Requires marker absent from baseline; POST-echo alone is high, confirmed separate readback is critical.
/// Inspired by OWASP WSTG-INPV-18 and PortSwigger SSTI; also influenced by pentest-ai <c>web.ssti_stored</c>.
/// Mutates profile fields when run — use only with intentional active safetyMode / test accounts.
/// </summary>
public sealed class SstiStoredScanProbe
{
    public const string Marker = "13289";
    public const string PayloadJinja = "{{137*97}}";
    public const string PayloadVelocity = "${137*97}";
    public const string PayloadErb = "<%=137*97%>";

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public SstiStoredScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class SstiStoredScanOptions
    {
        public int MaxCandidates { get; set; } = 10;
        public int TimeoutMs { get; set; } = 15000;
        public bool IncludeScaffold { get; set; } = true;
        public bool IncludeBrowserCookies { get; set; } = true;
        public List<string>? ProfileUrls { get; set; }
    }

    public sealed class SstiStoredFinding
    {
        public string Category { get; init; } = "ssti-stored";
        public string Severity { get; init; } = "critical";
        public string PostUrl { get; init; } = "";
        public string ReadUrl { get; init; } = "";
        public string FieldName { get; init; } = "";
        public string Syntax { get; init; } = "";
        public string Detail { get; init; } = "";
        public string Evidence { get; init; } = "";
        public string Source { get; init; } = "scaffold";
    }

    public sealed class SstiStoredScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ElapsedMs { get; init; }
        public List<SstiStoredFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public static readonly string[] DefaultCandidatePaths =
    [
        "/profile/update",
        "/profile",
        "/api/profile",
        "/api/users/me",
        "/me",
        "/account",
        "/settings/profile",
        "/users/me"
    ];

    public static readonly string[] ProfileFields =
    [
        "bio", "about", "description", "signature", "notes", "profile"
    ];

    private static readonly (string Syntax, string Payload)[] PayloadsBySyntax =
    [
        ("jinja2", PayloadJinja),
        ("velocity", PayloadVelocity),
        ("erb", PayloadErb)
    ];

    private static readonly int[] OkPostStatuses = [200, 201, 302];

    private static readonly string[] ReadbackSuffixes = ["", "/1", "/2", "/3"];

    public async Task<SstiStoredScanResult> RunAsync(
        SstiStoredScanOptions options,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running ssti-stored-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var candidates = BuildCandidateUrls(origin, options);
        var findings = new List<SstiStoredFinding>();
        var probed = 0;
        var seen = new HashSet<(string, string)>();

        foreach (var postUrl in candidates.Take(options.MaxCandidates))
        {
            ct.ThrowIfCancellationRequested();
            probed++;
            var firedHere = false;

            // Baseline must prove Marker absent before any mutation / flag.
            var cleanBaselines = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var dirtyBaselines = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var baselineUrl in BuildReadbackUrls(postUrl, parsed: null))
            {
                ct.ThrowIfCancellationRequested();
                var baseline = await LoginInjectionHelpers.SendAsync(
                    _ctx, baselineUrl, "GET", null, null, options.TimeoutMs,
                    followRedirects: true, options.IncludeBrowserCookies, ct);
                if (baseline.Status == 0)
                    continue;
                if (baseline.Body.Contains(Marker, StringComparison.Ordinal))
                    dirtyBaselines.Add(baselineUrl);
                else
                    cleanBaselines.Add(baselineUrl);
            }

            if (cleanBaselines.Count == 0)
            {
                // Fall back to a clean POST baseline when GETs are absent/unusable.
                var cleanBody = new Dictionary<string, string> { [ProfileFields[0]] = "trowser-ssti-baseline" };
                var cleanPost = await LoginInjectionHelpers.PostJsonAsync(
                    _ctx, postUrl, cleanBody, null, options.TimeoutMs,
                    followRedirects: true, options.IncludeBrowserCookies, ct);
                if (cleanPost.Status == 0 || cleanPost.Body.Contains(Marker, StringComparison.Ordinal))
                    continue;
                cleanBaselines.Add(postUrl);
            }
            else if (!cleanBaselines.Contains(postUrl) && !dirtyBaselines.Contains(postUrl))
            {
                // Write URL itself may not have been GET-able; prove absence via clean POST.
                var cleanBody = new Dictionary<string, string> { [ProfileFields[0]] = "trowser-ssti-baseline" };
                var cleanPost = await LoginInjectionHelpers.PostJsonAsync(
                    _ctx, postUrl, cleanBody, null, options.TimeoutMs,
                    followRedirects: true, options.IncludeBrowserCookies, ct);
                if (cleanPost.Status != 0 && !cleanPost.Body.Contains(Marker, StringComparison.Ordinal))
                    cleanBaselines.Add(postUrl);
                else if (cleanPost.Body.Contains(Marker, StringComparison.Ordinal))
                    dirtyBaselines.Add(postUrl);
            }

            if (dirtyBaselines.Contains(postUrl) && !cleanBaselines.Contains(postUrl))
                continue;

            foreach (var (syntax, payload) in PayloadsBySyntax)
            {
                if (firedHere)
                    break;

                foreach (var fieldName in ProfileFields)
                {
                    if (firedHere)
                        break;

                    var body = new Dictionary<string, string> { [fieldName] = payload };

                    var formResp = await LoginInjectionHelpers.PostFormAsync(
                        _ctx, postUrl, body, null, options.TimeoutMs,
                        followRedirects: true, options.IncludeBrowserCookies, ct);
                    if (OkPostStatuses.Contains(formResp.Status) && formResp.Body.Contains(Marker, StringComparison.Ordinal)
                        && cleanBaselines.Contains(postUrl))
                    {
                        AddFinding(findings, seen, postUrl, postUrl, fieldName, syntax, formResp.Body, options,
                            severity: "high",
                            detail: $"Field '{fieldName}' evaluated as {syntax} in POST echo (not confirmed via separate read).");
                        firedHere = true;
                        continue;
                    }

                    var jsonResp = await LoginInjectionHelpers.PostJsonAsync(
                        _ctx, postUrl, body, null, options.TimeoutMs,
                        followRedirects: true, options.IncludeBrowserCookies, ct);
                    JsonDocument? parsed = null;
                    try
                    {
                        if (!string.IsNullOrWhiteSpace(jsonResp.Body))
                            parsed = JsonDocument.Parse(jsonResp.Body);
                    }
                    catch (JsonException)
                    {
                        /* not JSON */
                    }

                    if (OkPostStatuses.Contains(jsonResp.Status) && jsonResp.Body.Contains(Marker, StringComparison.Ordinal)
                        && cleanBaselines.Contains(postUrl))
                    {
                        AddFinding(findings, seen, postUrl, postUrl, fieldName, syntax, jsonResp.Body, options,
                            severity: "high",
                            detail: $"Field '{fieldName}' evaluated as {syntax} in POST echo (not confirmed via separate read).");
                        firedHere = true;
                        continue;
                    }

                    if (!OkPostStatuses.Contains(formResp.Status) && !OkPostStatuses.Contains(jsonResp.Status))
                        continue;

                    foreach (var readUrl in BuildReadbackUrls(postUrl, parsed))
                    {
                        var key = (readUrl, fieldName);
                        if (seen.Contains(key))
                            continue;

                        // Require pre-mutation absence on this URL, or on the post URL family for new ids.
                        var baselineClean = cleanBaselines.Contains(readUrl)
                            || (!dirtyBaselines.Contains(readUrl) && cleanBaselines.Contains(postUrl));
                        if (!baselineClean)
                            continue;

                        var read = await LoginInjectionHelpers.SendAsync(
                            _ctx, readUrl, "GET", null, null, options.TimeoutMs,
                            followRedirects: true, options.IncludeBrowserCookies, ct);
                        if (read.Status != 200 || string.IsNullOrEmpty(read.Body))
                            continue;
                        if (!read.Body.Contains(Marker, StringComparison.Ordinal))
                            continue;

                        seen.Add(key);
                        findings.Add(MakeFinding(readUrl, postUrl, fieldName, syntax, read.Body, options,
                            severity: "critical",
                            detail: $"Field '{fieldName}' evaluated as {syntax} template on separate GET read-back."));
                        _log($"  FLAG stored SSTI: {fieldName} on {readUrl} ({syntax})", "#F44747");
                        firedHere = true;
                        break;
                    }
                }
            }
        }

        return new SstiStoredScanResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} stored SSTI finding(s) across {probed} candidate(s)."
                : $"No stored SSTI indicators across {probed} candidate(s).",
            CandidatesProbed = probed,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private void AddFinding(
        List<SstiStoredFinding> findings,
        HashSet<(string, string)> seen,
        string readUrl,
        string postUrl,
        string fieldName,
        string syntax,
        string body,
        SstiStoredScanOptions options,
        string severity,
        string detail)
    {
        var key = (readUrl, fieldName);
        if (!seen.Add(key))
            return;
        findings.Add(MakeFinding(readUrl, postUrl, fieldName, syntax, body, options, severity, detail));
        _log($"  FLAG stored SSTI: {fieldName} on {readUrl} ({syntax})", "#F44747");
    }

    private static SstiStoredFinding MakeFinding(
        string readUrl,
        string postUrl,
        string fieldName,
        string syntax,
        string body,
        SstiStoredScanOptions options,
        string severity,
        string detail) =>
        new()
        {
            Severity = severity,
            PostUrl = postUrl,
            ReadUrl = readUrl,
            FieldName = fieldName,
            Syntax = syntax,
            Detail = detail,
            Evidence = body.Length <= 512 ? body : body[..512],
            Source = options.ProfileUrls?.Contains(postUrl) == true ? "explicit" : "scaffold"
        };

    private static List<string> BuildReadbackUrls(string postUrl, JsonDocument? parsed)
    {
        var baseUrl = postUrl.EndsWith("/update", StringComparison.OrdinalIgnoreCase)
            ? postUrl[..^"/update".Length]
            : postUrl;

        var urls = new List<string> { postUrl, baseUrl };
        foreach (var suffix in ReadbackSuffixes)
        {
            if (!string.IsNullOrEmpty(suffix))
                urls.Add(baseUrl + suffix);
        }

        var recordId = ExtractId(parsed);
        if (recordId != null)
            urls.Add($"{baseUrl.TrimEnd('/')}/{recordId}");

        return urls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string? ExtractId(JsonDocument? doc)
    {
        if (doc == null)
            return null;
        foreach (var key in new[] { "id", "_id", "uuid" })
        {
            var found = WalkForField(doc.RootElement, key);
            if (found != null)
                return found;
        }

        return null;
    }

    private static string? WalkForField(JsonElement element, string key)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                {
                    if (prop.Name.Equals(key, StringComparison.OrdinalIgnoreCase)
                        && prop.Value.ValueKind is JsonValueKind.String or JsonValueKind.Number)
                        return prop.Value.ToString();
                    var nested = WalkForField(prop.Value, key);
                    if (nested != null)
                        return nested;
                }

                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    var nested = WalkForField(item, key);
                    if (nested != null)
                        return nested;
                }

                break;
        }

        return null;
    }

    private List<string> BuildCandidateUrls(string origin, SstiStoredScanOptions options)
    {
        var urls = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (options.ProfileUrls is { Count: > 0 })
        {
            foreach (var u in options.ProfileUrls)
            {
                if (seen.Add(u))
                    urls.Add(u);
            }
        }

        foreach (var entry in _ctx.Network.Entries)
        {
            if (!entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                && !entry.Method.Equals("PUT", StringComparison.OrdinalIgnoreCase)
                && !entry.Method.Equals("PATCH", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
                continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;
            var path = uri.AbsolutePath.ToLowerInvariant();
            if (!path.Contains("profile", StringComparison.Ordinal)
                && !path.Contains("account", StringComparison.Ordinal)
                && !path.Contains("/me", StringComparison.Ordinal)
                && !path.Contains("settings", StringComparison.Ordinal))
                continue;
            if (seen.Add(entry.Url))
                urls.Add(entry.Url);
        }

        if (options.IncludeScaffold)
        {
            foreach (var path in DefaultCandidatePaths)
            {
                var url = path.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? path
                    : origin.TrimEnd('/') + (path.StartsWith('/') ? path : "/" + path);
                if (seen.Add(url))
                    urls.Add(url);
            }
        }

        return urls;
    }
}
