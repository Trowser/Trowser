using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security.Orchestration;

namespace Trowser.Security;

/// <summary>
/// Per-operation Swaggering lanes (smoke, auth delta, errors, cost edge, injection hints).
/// </summary>
public sealed class SwaggeringProbe
{
    private static readonly Regex SqlErrorHint = new(
        @"(SQL syntax|mysql_|ORA-\d|PostgreSQL|sqlite_|Unclosed quotation)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public SwaggeringProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class SwaggeringFinding
    {
        public string Category { get; init; } = "swaggering-server-error";
        public string Severity { get; init; } = "medium";
        public string Phase { get; init; } = "smoke";
        public string Title { get; init; } = "";
        public string Detail { get; init; } = "";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public int Status { get; init; }
        public string? Variant { get; init; }
        public string? SpecUrl { get; init; }
        public string? Evidence { get; init; }
        public string Confidence { get; init; } = "observed";
    }

    public sealed class OperationResult
    {
        public string Method { get; init; } = "GET";
        public string Path { get; init; } = "";
        public string? OperationId { get; init; }
        public bool RequiresSecurity { get; init; }
        public string Outcome { get; init; } = "not-probed";
        public int? Status { get; init; }
        public string? Url { get; init; }
        public string? SkipReason { get; init; }
    }

    public sealed class CoverageSummary
    {
        public int Probed { get; init; }
        public int Skipped { get; init; }
        public int NotProbed { get; init; }
        public int NotReached { get; init; }
        public int Http2xx { get; init; }
        public int Http4xx { get; init; }
        public int Http5xx { get; init; }
    }

    public sealed class ProbeRunResult
    {
        public List<SwaggeringFinding> Findings { get; init; } = [];
        public List<OperationResult> Operations { get; init; } = [];
        public int OperationsExamined { get; init; }
        public int RequestsSent { get; init; }
        public int RequestsSkipped { get; init; }
        public List<string> PhasesRun { get; init; } = [];
    }

    public async Task<ProbeRunResult> RunAsync(
        IReadOnlyList<OpenApiOperationCatalog.OpenApiOperation> operations,
        SwaggeringDepthProfile.Resolved depth,
        SafetyMode safetyMode,
        int timeoutMs,
        bool includeBrowserCookies,
        IReadOnlyDictionary<string, (Dictionary<string, string> Headers, string? Body)>? replayHeaders,
        CancellationToken ct,
        Func<bool>? budgetExhausted = null)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<SwaggeringFinding>();
        var outcomes = new List<OperationResult>();
        var requestsSent = 0;
        var skipped = 0;
        var phases = new List<string> { "smoke" };
        var seenFindingKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var serverErrorSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sensitiveSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var cap = Math.Clamp(depth.MaxOperations, 1, 500);
        var ops = operations.Take(cap).ToList();
        _log($"Swaggering: {ops.Count} operation(s) queued", "#888888");

        var stop = false;
        foreach (var op in ops)
        {
            if (stop || budgetExhausted?.Invoke() == true || requestsSent >= depth.MaxRequestsTotal)
            {
                outcomes.Add(Outcome(op, "not-reached", skipReason: "budget exhausted"));
                stop = true;
                continue;
            }
            ct.ThrowIfCancellationRequested();

            if (!MethodAllowed(op.Method, safetyMode))
            {
                skipped++;
                outcomes.Add(Outcome(op, "skipped", skipReason: "method not allowed for safetyMode"));
                continue;
            }

            int? smokeStatus = null;
            string? smokeUrl = null;
            var sentForOp = false;
            var variants = BuildVariants(op, depth, safetyMode);
            foreach (var variant in variants)
            {
                if (budgetExhausted?.Invoke() == true || requestsSent >= depth.MaxRequestsTotal)
                {
                    stop = true;
                    break;
                }

                var built = OpenApiOperationCatalog.BuildRequest(op, variant.Key, variant.OmitField);
                if (built == null) continue;

                MergeReplayHeaders(built, replayHeaders);

                if (depth.InterRequestDelayMs > 0 && requestsSent > 0)
                    await Task.Delay(depth.InterRequestDelayMs, ct).ConfigureAwait(false);

                var timed = await SecurityProbeHttp.FetchTimedAsync(
                    _ctx, built.Url, built.Method, built.Headers, built.Body,
                    timeoutMs, includeBrowserCookies, ct).ConfigureAwait(false);
                requestsSent++;
                sentForOp = true;
                if (smokeStatus == null)
                {
                    smokeStatus = timed.Result.Status;
                    smokeUrl = built.Url;
                }

                EmitFromResponse(findings, seenFindingKeys, serverErrorSeen, sensitiveSeen, built, timed.Result,
                    timed.ElapsedSeconds * 1000, depth.SlowThresholdMs, phase: variant.Phase);

                if (depth.IncludeInjectionMicro && safetyMode.AllowsProbes())
                {
                    foreach (var inj in BuildInjectionProbes(built))
                    {
                        if (budgetExhausted?.Invoke() == true || requestsSent >= depth.MaxRequestsTotal)
                            break;
                        if (depth.InterRequestDelayMs > 0)
                            await Task.Delay(depth.InterRequestDelayMs, ct).ConfigureAwait(false);
                        var injTimed = await SecurityProbeHttp.FetchTimedAsync(
                            _ctx, inj.Url, inj.Method, inj.Headers, inj.Body,
                            timeoutMs, includeBrowserCookies, ct).ConfigureAwait(false);
                        requestsSent++;
                        if (SqlErrorHint.IsMatch(injTimed.Result.Body ?? ""))
                        {
                            AddFinding(findings, seenFindingKeys, new SwaggeringFinding
                            {
                                Category = "swaggering-injection-hint",
                                Severity = "high",
                                Phase = "injection-micro",
                                Title = "SQL error signature in string parameter probe",
                                Detail = $"param probe on {op.PathTemplate}",
                                Url = inj.Url,
                                Method = inj.Method,
                                Status = injTimed.Result.Status,
                                Variant = "sqli-hint",
                                SpecUrl = op.SpecUrl,
                                Evidence = ResponseExcerpt(injTimed.Result.Body)
                            });
                        }
                    }
                }

                if (depth.IncludeAuthDelta && op.RequiresSecurity && safetyMode.AllowsProbes())
                {
                    phases.Add("auth-delta");
                    if (depth.InterRequestDelayMs > 0)
                        await Task.Delay(depth.InterRequestDelayMs, ct).ConfigureAwait(false);
                    var anon = await SecurityProbeHttp.FetchAsync(
                        _ctx, built.Url, built.Method, built.Headers, built.Body,
                        timeoutMs, includeBrowserCookies: false, ct).ConfigureAwait(false);
                    requestsSent++;
                    if (anon.Status is >= 200 and < 300 && built.Method is not "GET" and not "HEAD" and not "OPTIONS")
                    {
                        AddFinding(findings, seenFindingKeys, new SwaggeringFinding
                        {
                            Category = "swaggering-auth-anomaly",
                            Severity = "high",
                            Phase = "auth-delta",
                            Title = "Secured operation returned success without session cookies",
                            Detail = $"{built.Method} {op.PathTemplate} — spec declares security; anonymous {anon.Status}",
                            Url = built.Url,
                            Method = built.Method,
                            Status = anon.Status,
                            SpecUrl = op.SpecUrl
                        });
                    }
                }
            }

            if (!sentForOp && stop)
                outcomes.Add(Outcome(op, "not-reached", skipReason: "budget exhausted"));
            else if (!sentForOp)
                outcomes.Add(Outcome(op, "skipped", skipReason: "could not build a request"));
            else
                outcomes.Add(Outcome(op, "probed", smokeStatus, smokeUrl));
        }

        foreach (var op in operations.Skip(cap))
            outcomes.Add(Outcome(op, "not-reached", skipReason: "depth operation cap"));

        _log($"Swaggering probe: {findings.Count} finding(s), {requestsSent} request(s), {sw.ElapsedMilliseconds}ms", "#888888");

        return new ProbeRunResult
        {
            Findings = findings,
            Operations = outcomes,
            OperationsExamined = ops.Count,
            RequestsSent = requestsSent,
            RequestsSkipped = skipped,
            PhasesRun = phases.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    private static bool MethodAllowed(string method, SafetyMode mode)
    {
        if (method is "GET" or "HEAD" or "OPTIONS") return mode.AllowsProbes();
        return mode.AllowsWriteVerbs();
    }

    private sealed class VariantPlan
    {
        public OpenApiOperationCatalog.RequestVariant Key { get; init; }
        public string Phase { get; init; } = "smoke";
        public string? OmitField { get; init; }
    }

    private static List<VariantPlan> BuildVariants(
        OpenApiOperationCatalog.OpenApiOperation op,
        SwaggeringDepthProfile.Resolved depth,
        SafetyMode safetyMode)
    {
        var list = new List<VariantPlan>
        {
            new() { Key = OpenApiOperationCatalog.RequestVariant.Minimal, Phase = "smoke" }
        };

        if (op.RequestBody?.ExampleJson != null)
            list.Add(new() { Key = OpenApiOperationCatalog.RequestVariant.Example, Phase = "smoke" });

        if (depth.IncludeCostEdge && safetyMode.AllowsProbes())
            list.Add(new() { Key = OpenApiOperationCatalog.RequestVariant.Edge, Phase = "cost-edge" });

        if (depth.IncludeForcedError && safetyMode.AllowsWriteVerbs() && op.Method is "POST" or "PUT" or "PATCH")
            list.Add(new() { Key = OpenApiOperationCatalog.RequestVariant.Malformed, Phase = "forced-error" });

        if (depth.IncludeMissingField && safetyMode.AllowsWriteVerbs() && op.RequestBody != null)
        {
            var fields = OpenApiOperationCatalog.ToAttackSurfaceEndpoint(op).Parameters.Body;
            foreach (var field in fields.Take(8))
                list.Add(new()
                {
                    Key = OpenApiOperationCatalog.RequestVariant.OmitField,
                    Phase = "missing-field",
                    OmitField = field
                });
        }

        return list;
    }

    private static void MergeReplayHeaders(
        OpenApiOperationCatalog.BuiltRequest built,
        IReadOnlyDictionary<string, (Dictionary<string, string> Headers, string? Body)>? replay)
    {
        if (replay == null || replay.Count == 0) return;
        var pathKey = new Uri(built.Url).AbsolutePath;
        foreach (var kv in replay)
        {
            if (!pathKey.Contains(kv.Key, StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var h in kv.Value.Headers)
            {
                if (h.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase)) continue;
                built.Headers[h.Key] = h.Value;
            }
        }
    }

    private static IEnumerable<OpenApiOperationCatalog.BuiltRequest> BuildInjectionProbes(
        OpenApiOperationCatalog.BuiltRequest baseline)
    {
        if (baseline.Operation.Parameters.All(p => !string.Equals(p.In, "query", StringComparison.OrdinalIgnoreCase)))
            yield break;

        foreach (var p in baseline.Operation.Parameters.Where(p =>
                     string.Equals(p.In, "query", StringComparison.OrdinalIgnoreCase)
                     && (string.IsNullOrEmpty(p.SchemaType) || p.SchemaType == "string")))
        {
            var probe = OpenApiOperationCatalog.BuildRequest(baseline.Operation,
                OpenApiOperationCatalog.RequestVariant.Minimal);
            if (probe == null) continue;
            var uri = new UriBuilder(probe.Url) { Query = $"{p.Name}=' OR '1'='1" };
            yield return new OpenApiOperationCatalog.BuiltRequest
            {
                Url = uri.ToString(),
                Method = probe.Method,
                Headers = probe.Headers,
                Body = probe.Body,
                Variant = "injection-micro",
                Operation = baseline.Operation
            };
            yield break;
        }
    }

    private static void EmitFromResponse(
        List<SwaggeringFinding> findings,
        HashSet<string> seen,
        HashSet<string> serverErrorSeen,
        HashSet<string> sensitiveSeen,
        OpenApiOperationCatalog.BuiltRequest built,
        SecurityProbeHttp.FetchResult response,
        double elapsedMs,
        int slowThresholdMs,
        string phase)
    {
        var body = response.Body ?? "";
        if (response.Status is >= 500 and <= 599)
        {
            var dedupe = $"server|{built.Method}|{built.Operation.PathTemplate}|{response.Status}";
            if (serverErrorSeen.Add(dedupe))
            {
                AddFinding(findings, seen, new SwaggeringFinding
                {
                    Category = "swaggering-server-error",
                    Severity = "high",
                    Phase = phase,
                    Title = $"Server error {response.Status} on documented operation",
                    Detail = $"{built.Variant} {built.Operation.PathTemplate}",
                    Url = built.Url,
                    Method = built.Method,
                    Status = response.Status,
                    Variant = built.Variant,
                    SpecUrl = built.Operation.SpecUrl,
                    Evidence = ResponseExcerpt(body)
                });
            }
        }

        var trace = StackTraceHeuristics.ClassifyRelativeToBaseline(body, "");
        if (trace != null && phase is "forced-error" or "missing-field" or "smoke")
        {
            AddFinding(findings, seen, new SwaggeringFinding
            {
                Category = "swaggering-verbose-error",
                Severity = trace.Value.Item1 == "critical" ? "critical" : "medium",
                Phase = phase,
                Title = "Verbose error / stack trace on documented operation",
                Detail = trace.Value.Item2,
                Url = built.Url,
                Method = built.Method,
                Status = response.Status,
                Variant = built.Variant,
                SpecUrl = built.Operation.SpecUrl,
                Evidence = ResponseExcerpt(body)
            });
        }

        if (response.Status is >= 200 and < 300
            && sensitiveSeen.Add($"{built.Method}|{built.Operation.PathTemplate}"))
        {
            var names = FindSensitiveJsonProperties(body);
            if (names.Count > 0)
            {
                var high = names.Any(n => n.Contains("password", StringComparison.OrdinalIgnoreCase)
                                          || n.Contains("secret", StringComparison.OrdinalIgnoreCase)
                                          || n.Contains("private", StringComparison.OrdinalIgnoreCase));
                AddFinding(findings, seen, new SwaggeringFinding
                {
                    Category = "swaggering-sensitive-data",
                    Severity = high ? "high" : "medium",
                    Phase = phase,
                    Title = "Documented response includes sensitive fields",
                    Detail = $"{built.Method} {built.Operation.PathTemplate} JSON includes {string.Join(", ", names)}",
                    Url = built.Url,
                    Method = built.Method,
                    Status = response.Status,
                    Variant = built.Variant,
                    SpecUrl = built.Operation.SpecUrl,
                    Evidence = "fields: " + string.Join(", ", names)
                });
            }
        }

        if (elapsedMs >= slowThresholdMs && built.Method is "GET" or "POST")
        {
            AddFinding(findings, seen, new SwaggeringFinding
            {
                Category = "swaggering-slow",
                Severity = "medium",
                Phase = phase,
                Title = $"Slow response ({elapsedMs:F0}ms) on documented operation",
                Detail = built.Operation.PathTemplate,
                Url = built.Url,
                Method = built.Method,
                Status = response.Status,
                Variant = built.Variant,
                SpecUrl = built.Operation.SpecUrl,
                Confidence = "observed"
            });
        }
    }

    private static OperationResult Outcome(
        OpenApiOperationCatalog.OpenApiOperation op,
        string outcome,
        int? status = null,
        string? url = null,
        string? skipReason = null) => new()
    {
        Method = op.Method,
        Path = op.PathTemplate,
        OperationId = op.OperationId,
        RequiresSecurity = op.RequiresSecurity,
        Outcome = outcome,
        Status = status,
        Url = url,
        SkipReason = skipReason
    };

    public static string? ResponseExcerpt(string? body, int max = 240)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        var s = Whitespace.Replace(body.Trim(), " ");
        return s.Length <= max ? s : s[..max] + "…";
    }

    /// <summary>
    /// Property names in a JSON body whose values look like live secrets (password, token, api key).
    /// Values are not returned.
    /// </summary>
    public static IReadOnlyList<string> FindSensitiveJsonProperties(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return [];
        var trim = body.TrimStart();
        if (!trim.StartsWith('{') && !trim.StartsWith('[')) return [];

        try
        {
            using var doc = JsonDocument.Parse(body);
            var found = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            WalkSensitive(doc.RootElement, found, seen, depth: 0, nodes: new int[1]);
            return found;
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static readonly Regex Whitespace = new(@"\s+", RegexOptions.Compiled);

    private static readonly HashSet<string> SensitiveNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "passwd", "pwd", "secret", "apisecret", "apikey", "apitoken",
        "accesstoken", "refreshtoken", "clientsecret", "privatekey", "sessiontoken"
    };

    private static readonly HashSet<string> PlaceholderValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "string", "password", "secret", "todo", "changeme", "null", "none", "redacted",
        "test", "example", "xxx", "your-password", "***", "********"
    };

    private static void WalkSensitive(JsonElement element, List<string> found, HashSet<string> seen, int depth, int[] nodes)
    {
        if (depth > 6 || nodes[0] > 400) return;
        nodes[0]++;
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                {
                    if (nodes[0] > 400) return;
                    var key = new string(prop.Name.Where(char.IsLetterOrDigit).ToArray());
                    if (SensitiveNames.Contains(key) && ValueLooksLive(prop.Value) && seen.Add(prop.Name))
                        found.Add(prop.Name);
                    WalkSensitive(prop.Value, found, seen, depth + 1, nodes);
                }
                break;
            case JsonValueKind.Array:
                var n = 0;
                foreach (var item in element.EnumerateArray())
                {
                    if (n++ >= 20 || nodes[0] > 400) return;
                    WalkSensitive(item, found, seen, depth + 1, nodes);
                }
                break;
        }
    }

    private static bool ValueLooksLive(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => IsLiveSecret(value.GetString()),
        JsonValueKind.Object or JsonValueKind.Array => true,
        _ => false
    };

    private static bool IsLiveSecret(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 4) return false;
        return !PlaceholderValues.Contains(value.Trim());
    }

    private static void AddFinding(List<SwaggeringFinding> list, HashSet<string> seen, SwaggeringFinding f)
    {
        var key = $"{f.Category}|{f.Url}|{f.Method}|{f.Variant}|{f.Phase}";
        if (!seen.Add(key)) return;
        list.Add(f);
    }
}
