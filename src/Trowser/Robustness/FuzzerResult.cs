using Trowser.Security;

namespace Trowser.Robustness;

/// <summary>
/// Configuration for a Request Fuzzer test run.
/// </summary>
public class FuzzerOptions
{
    /// <summary>Request template: url, method, headers, body/json with §MARKER§ or {{MARKER}} injection points.</summary>
    public FuzzerRequestTemplate Request { get; init; } = new();

    /// <summary>
    /// Map of injection point names to their payload set configuration.
    /// Key = marker name (without § or {{}}), Value = payload set config.
    /// </summary>
    public Dictionary<string, FuzzerInjectionPoint> InjectionPoints { get; init; } = new();

    /// <summary>
    /// Payload set definitions. Key = set name, Value = list of payloads or ["built-in"] to use the built-in set.
    /// When a value list contains the single element "built-in", the named built-in set is used instead.
    /// </summary>
    public Dictionary<string, List<string>> PayloadSets { get; init; } = new();

    /// <summary>
    /// Payload generators for programmatic payload creation (range, pattern, combine).
    /// Key = payload set name to extend. Generators add payloads to the existing set.
    /// </summary>
    public Dictionary<string, List<FuzzerPayloadGenerator>> PayloadGenerators { get; init; } = new();

    /// <summary>
    /// Attack strategy: sniper (one point at a time), battering-ram (same payload everywhere),
    /// pitchfork (parallel iteration), cluster-bomb (all combinations).
    /// </summary>
    public FuzzerAttackType AttackType { get; init; } = FuzzerAttackType.Sniper;

    /// <summary>Maximum concurrent requests (default 5, clamped to 1-20).</summary>
    public int MaxConcurrency { get; init; } = 5;

    /// <summary>When true, requests run as browser fetch() with real cookies and session state.</summary>
    public bool UseBrowserCookies { get; init; } = true;

    /// <summary>Stop fuzzing when any of these status codes are encountered (early termination).</summary>
    public List<int>? StopOnStatus { get; init; }

    /// <summary>
    /// HTTP status codes that do not trigger <see cref="FuzzFlag.StatusAnomaly"/> or <see cref="FuzzFlag.LengthAnomaly"/>
    /// when the fuzzed response differs from the baseline (e.g. 400 validation, 403 auth, 412 precondition).
    /// Null or empty = treat any status/length change vs baseline as potentially anomalous (legacy behaviour).
    /// Server errors (5xx) and reflection/error-pattern detection are unchanged.
    /// </summary>
    public List<int>? AcceptableResponseStatuses { get; init; }

    /// <summary>Maximum number of requests to send (safety cap, default 1000).</summary>
    public int MaxRequests { get; init; } = 1000;

    /// <summary>Timeout per request in milliseconds (default 10000).</summary>
    public int TimeoutMs { get; init; } = 10000;

    /// <summary>Delay in milliseconds between request batches (default 0 = no delay).</summary>
    public int DelayMs { get; init; }

    /// <summary>Maximum body snippet length in results (default 500). Set to 0 to exclude bodies.</summary>
    public int BodySnippetLength { get; init; } = 500;

    /// <summary>
    /// Max characters of each response body stored on each result (default 131072). Set to 0 to omit the <see cref="FuzzRequestResult.Body"/> field.
    /// </summary>
    public int MaxResponseBodyLength { get; init; } = 131072;

    /// <summary>
    /// Fetch redirect mode: <c>follow</c> (default) or <c>manual</c> to capture 3xx Location headers
    /// without following off-site redirects (required for open-redirect fuzzing).
    /// </summary>
    public string? Redirect { get; init; }

    /// <summary>Payload corpus breadth for built-in payload sets (default small — current behavior).</summary>
    public PayloadProfile PayloadProfile { get; init; } = PayloadProfile.Small;
}

/// <summary>
/// Request template with injection point markers (§NAME§ or {{NAME}}).
/// </summary>
public class FuzzerRequestTemplate
{
    public string Url { get; init; } = "";
    public string Method { get; init; } = "GET";
    public Dictionary<string, string>? Headers { get; init; }
    public string? Body { get; init; }
    public object? Json { get; init; }
}

/// <summary>
/// Configuration for a single injection point.
/// </summary>
public class FuzzerInjectionPoint
{
    /// <summary>Name of the payload set to use (references key in PayloadSets or a built-in name).</summary>
    public string PayloadSet { get; init; } = "";
}

/// <summary>
/// E3: Payload generator for programmatic payload creation.
/// </summary>
public class FuzzerPayloadGenerator
{
    /// <summary>Generator type: "range", "pattern", or "combine".</summary>
    public string? Type { get; init; }

    /// <summary>Range/pattern start value (inclusive).</summary>
    public int From { get; init; }

    /// <summary>Range/pattern end value (inclusive).</summary>
    public int To { get; init; }

    /// <summary>Step increment for range generators (default 1).</summary>
    public int Step { get; init; } = 1;

    /// <summary>Template string for pattern generators. Use {N} for the counter.</summary>
    public string? Template { get; init; }

    /// <summary>Base payload set name for combine generators.</summary>
    public string? BaseSet { get; init; }

    /// <summary>Encoding transforms for combine generators: url-encode, double-url-encode, base64, html-entity, unicode, hex.</summary>
    public List<string>? Encodings { get; init; }
}

/// <summary>
/// Attack strategy for multi-point fuzzing.
/// </summary>
public enum FuzzerAttackType
{
    /// <summary>One injection point at a time; others use original values. Tests each point independently.</summary>
    Sniper,
    /// <summary>Same payload in all injection points simultaneously.</summary>
    BatteringRam,
    /// <summary>Parallel iteration: payload sets advance in lockstep (payload1[i], payload2[i]).</summary>
    Pitchfork,
    /// <summary>All combinations: Cartesian product of all payload sets.</summary>
    ClusterBomb,
}

/// <summary>
/// Flags indicating why a fuzz result was marked as interesting.
/// </summary>
[Flags]
public enum FuzzFlag
{
    None = 0,
    ServerError = 1,
    StatusAnomaly = 2,
    Reflection = 4,
    ErrorPattern = 8,
    TimingAnomaly = 16,
    LengthAnomaly = 32,
    OpenRedirect = 64,
}

/// <summary>
/// A payload combination: values and their indices within the resolved payload sets.
/// </summary>
public record FuzzCombination(Dictionary<string, string> Payloads, Dictionary<string, int> Indices);

/// <summary>
/// Result of a single fuzz request.
/// </summary>
public class FuzzRequestResult
{
    public int Index { get; init; }
    public Dictionary<string, string> Payloads { get; init; } = new();
    public Dictionary<string, int> PayloadIndices { get; init; } = new();

    /// <summary>
    /// Active fuzz payload value(s) for this request (injection points with payload index ≥ 0), deduplicated.
    /// Matches the common single-marker case as one string for API field <c>payload</c>.
    /// Control characters, lone surrogates, and noncharacters are escaped so the value is safe for
    /// JSON serialization, HTML rendering, and clipboard copy.
    /// </summary>
    public string Payload =>
        FuzzText.Clean(FormatActivePayloads(Payloads, PayloadIndices));

    public int Status { get; init; }
    public string? StatusText { get; init; }
    public int DurationMs { get; init; }
    public int ResponseLength { get; init; }

    /// <summary>Response body text (capped by fuzzer options). Null when omitted or empty.</summary>
    public string? Body { get; init; }

    public string? BodySnippet { get; init; }
    public FuzzFlag Flags { get; init; }
    public List<string> FlagDetails { get; init; } = new();
    public string? Error { get; init; }

    /// <summary>E2: The final URL after marker substitution (for debugging injection).</summary>
    public string? InjectedUrl { get; init; }

    /// <summary>E2: The final request body after marker substitution (for debugging injection).</summary>
    public string? InjectedBody { get; init; }

    /// <summary>Location header when redirect mode is manual.</summary>
    public string? Location { get; init; }

    public bool Flagged => Flags != FuzzFlag.None;

    private static string FormatActivePayloads(Dictionary<string, string> payloads, Dictionary<string, int> indices)
    {
        var active = payloads
            .Where(kv => indices.TryGetValue(kv.Key, out var idx) && idx >= 0)
            .Select(kv => kv.Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return active.Count == 0 ? "" : string.Join(" | ", active);
    }
}

/// <summary>
/// Overall result of a fuzzer test run.
/// </summary>
public class FuzzerResult
{
    public DateTime Timestamp { get; init; }
    public double DurationSeconds { get; init; }
    public FuzzerAttackType AttackType { get; init; }
    public int TotalRequests { get; init; }
    public int Completed { get; init; }
    public int Errors { get; init; }
    public int Flagged { get; init; }
    public bool StoppedEarly { get; init; }
    public string? StopReason { get; init; }

    public Dictionary<int, int> StatusDistribution { get; init; } = new();
    public FuzzerTimingStats? Timing { get; init; }
    public List<FuzzRequestResult> Results { get; init; } = new();
    public FuzzerOptions Options { get; init; } = new();

    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== Request Fuzzer Report ===");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add($"Duration: {DurationSeconds:F1}s | Requests: {TotalRequests} | Attack: {AttackType}");
        lines.Add($"Completed: {Completed} | Errors: {Errors} | Flagged: {Flagged}");
        if (StoppedEarly)
            lines.Add($"STOPPED EARLY: {StopReason}");
        lines.Add("");

        if (StatusDistribution.Count > 0)
        {
            lines.Add("STATUS DISTRIBUTION:");
            foreach (var kv in StatusDistribution.OrderBy(kv => kv.Key))
                lines.Add($"  {kv.Key}: {kv.Value} response(s)");
            lines.Add("");
        }

        if (Timing != null)
        {
            lines.Add("TIMING:");
            lines.Add($"  Avg: {Timing.AvgMs}ms | Min: {Timing.MinMs}ms | Max: {Timing.MaxMs}ms | P95: {Timing.P95Ms}ms");
            lines.Add("");
        }

        var flaggedResults = Results.Where(r => r.Flagged).ToList();
        if (flaggedResults.Count > 0 && includeDetails)
        {
            lines.Add($"FLAGGED RESULTS ({flaggedResults.Count}):");
            foreach (var r in flaggedResults.Take(50))
            {
                var payloadStr = string.Join(", ", r.Payloads.Select(kv => $"{kv.Key}={Truncate(FuzzText.Clean(kv.Value), 60)}"));
                lines.Add($"  [{r.Index}] {r.Status} {r.StatusText} ({r.DurationMs}ms, {r.ResponseLength}b)");
                lines.Add($"       Payloads: {payloadStr}");
                foreach (var detail in r.FlagDetails)
                    lines.Add($"       {detail}");
                if (r.InjectedUrl != null)
                    lines.Add($"       URL: {Truncate(FuzzText.Clean(r.InjectedUrl), 120)}");
                if (r.InjectedBody != null)
                    lines.Add($"       Body: {Truncate(FuzzText.Clean(r.InjectedBody), 120)}");
                else if (r.BodySnippet != null && r.BodySnippet.Length > 0)
                    lines.Add($"       Response: {Truncate(FuzzText.Clean(r.BodySnippet), 120)}");
                lines.Add("");
            }
            if (flaggedResults.Count > 50)
                lines.Add($"  ... and {flaggedResults.Count - 50} more flagged result(s)");
        }
        else if (flaggedResults.Count == 0)
        {
            lines.Add("NO FLAGS — All responses appear normal.");
        }

        lines.Add("=================================");
        return string.Join(Environment.NewLine, lines);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..(max - 3)] + "...";
}

/// <summary>
/// Timing statistics for a fuzzer run.
/// </summary>
public class FuzzerTimingStats
{
    public int AvgMs { get; init; }
    public int MinMs { get; init; }
    public int MaxMs { get; init; }
    public int P95Ms { get; init; }
}

/// <summary>
/// Text sanitizer for fuzz payload/response values that appear in reports, logs, and API responses.
/// Fuzz payloads intentionally contain nasty bytes (NUL, control chars, lone UTF-16 surrogates,
/// Unicode noncharacters, zero-width/bidi marks). Emitting these raw breaks JSON serialization,
/// "Show as HTML" rendering, and clipboard copy, so we escape them to a visible <c>\uXXXX</c> form.
/// </summary>
public static class FuzzText
{
    /// <summary>Escape control chars, lone surrogates, noncharacters, and zero-width/bidi marks to a single-line-safe form.</summary>
    public static string Clean(string? s)
    {
        if (string.IsNullOrEmpty(s)) return s ?? "";

        var sb = new System.Text.StringBuilder(s.Length);
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];

            // C0/C1 control characters (includes NUL, CR, LF, TAB — kept single-line on purpose).
            if (c < 0x20 || (c >= 0x7F && c <= 0x9F))
            {
                sb.Append("\\u").Append(((int)c).ToString("x4"));
                continue;
            }

            // Surrogate pairs: keep valid pairs, escape unpaired halves (invalid UTF-16 → breaks serializers).
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                {
                    sb.Append(c).Append(s[i + 1]);
                    i++;
                    continue;
                }
                sb.Append("\\u").Append(((int)c).ToString("x4"));
                continue;
            }
            if (char.IsLowSurrogate(c))
            {
                sb.Append("\\u").Append(((int)c).ToString("x4"));
                continue;
            }

            // Unicode noncharacters and rendering-hostile marks (BOM, zero-width, bidi overrides, line/para separators).
            if (c is '\uFFFE' or '\uFFFF'
                || (c >= '\uFDD0' && c <= '\uFDEF')
                || c is '\uFEFF' or '\u200B' or '\u200C' or '\u200D' or '\u200E' or '\u200F'
                || (c >= '\u202A' && c <= '\u202E')
                || c is '\u2028' or '\u2029')
            {
                sb.Append("\\u").Append(((int)c).ToString("x4"));
                continue;
            }

            sb.Append(c);
        }
        return sb.ToString();
    }
}
