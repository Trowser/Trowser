using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security;

namespace Trowser.Robustness;

/// <summary>
/// Browser-context request fuzzer (Intruder-style). Takes a request template with
/// §MARKER§ (or {{MARKER}}) injection points, iterates through payload sets using
/// configurable attack strategies, and flags anomalous responses.
///
/// Unlike Burp Intruder, this runs fetch() inside the WebView2 — with real cookies,
/// CSRF tokens, and session state. Trowser's killer differentiator for authenticated fuzzing.
/// </summary>
public class RequestFuzzer
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    // B3 + E1: Support both §MARKER§ and {{MARKER}} syntaxes (\u00A7 = §; avoid source-encoding mojibake)
    private static readonly Regex MarkerRegex = new(@"\u00A7(\w+)\u00A7|\{\{(\w+)\}\}", RegexOptions.Compiled);

    private static readonly string[] ErrorPatterns =
    [
        "stack trace", "stacktrace", "at System.", "at Microsoft.",
        "NullReferenceException", "ArgumentException", "InvalidOperationException",
        "System.Exception", "Unhandled exception", "Internal Server Error",
        "SQLSTATE", "SQL syntax", "mysql_", "pg_query", "ORA-",
        "sqlite3.", "SQLITE_ERROR", "syntax error",
        "django.core.exceptions", "Traceback (most recent call last)",
        "PHP Fatal error", "PHP Warning", "PHP Notice",
        "java.lang.", "javax.", "org.springframework",
        "TypeError:", "ReferenceError:", "SyntaxError:",
        "ECONNREFUSED", "ENOTFOUND", "ETIMEDOUT",
    ];

    public RequestFuzzer(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<FuzzerResult> RunAsync(FuzzerOptions options)
    {
        var startTime = DateTime.UtcNow;
        var concurrency = Math.Clamp(options.MaxConcurrency, 1, 20);
        var maxRequests = Math.Clamp(options.MaxRequests, 1, 10000);

        // Auto-substitute {{CALLBACK}} / §CALLBACK§ with the live callback URL (docs contract).
        // CALLBACK is a substitution marker, not a fuzz injection point.
        options.InjectionPoints.Remove("CALLBACK");

        var resolvedPayloads = ResolvePayloadSets(options);
        var combinations = GenerateCombinations(options, resolvedPayloads);

        if (combinations.Count > maxRequests)
        {
            _log($"RequestFuzzer: capping {combinations.Count} combinations to {maxRequests}", "#CCCC00");
            combinations = combinations.Take(maxRequests).ToList();
        }

        _log($"RequestFuzzer: {combinations.Count} request(s), concurrency={concurrency}, attack={options.AttackType}", "#888888");

        var template = SerializeTemplate(options.Request);
        template = ApplyCallbackMarkerSubstitution(template);

        // B1 FIX: Use ConcurrentBag to eliminate race condition at concurrency > 1
        var results = new ConcurrentBag<FuzzRequestResult>();
        var semaphore = new SemaphoreSlim(concurrency, concurrency);
        var stoppedEarly = false;
        string? stopReason = null;
        var stopLock = new object();
        var completedCount = 0;

        var baseline = await SendBaselineRequest(options, template);
        _log($"  Baseline: {baseline.Status} ({baseline.DurationMs}ms, {baseline.ResponseLength}b)", "#888888");

        var tasks = new List<Task>();
        for (int i = 0; i < combinations.Count; i++)
        {
            bool shouldStop;
            lock (stopLock) { shouldStop = stoppedEarly; }
            if (shouldStop) break;

            var index = i;
            var combo = combinations[i];

            await semaphore.WaitAsync();

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    bool localStop;
                    lock (stopLock) { localStop = stoppedEarly; }
                    if (localStop) return;

                    var result = await SendFuzzRequest(options, template, combo, index, baseline);
                    results.Add(result);
                    var count = Interlocked.Increment(ref completedCount);

                    if (result.Flagged)
                    {
                        var payloadStr = string.Join(", ", combo.Payloads.Select(kv => $"{kv.Key}={Truncate(FuzzText.Clean(kv.Value), 40)}"));
                        _log($"  [{index}] {result.Status} FLAGGED: {string.Join("|", result.FlagDetails.Take(2))} — {payloadStr}", "#CCCC00");
                    }
                    else if (count % 50 == 0)
                    {
                        _log($"  Progress: {count}/{combinations.Count}", "#888888");
                    }

                    if (options.StopOnStatus != null && options.StopOnStatus.Contains(result.Status))
                    {
                        lock (stopLock)
                        {
                            if (!stoppedEarly)
                            {
                                stoppedEarly = true;
                                stopReason = $"Status {result.Status} matched stopOnStatus trigger";
                                _log($"  STOP: {stopReason}", "#F44747");
                            }
                        }
                    }

                    if (options.DelayMs > 0)
                        await Task.Delay(options.DelayMs);
                }
                finally
                {
                    semaphore.Release();
                }
            }));
        }

        await Task.WhenAll(tasks);

        var elapsed = (DateTime.UtcNow - startTime).TotalSeconds;

        // B1 FIX: Snapshot the bag into a sorted list after all tasks complete — no concurrent reads
        var orderedResults = results.OrderBy(r => r.Index).ToList();

        var timings = orderedResults.Where(r => r.Error == null).Select(r => r.DurationMs).OrderBy(t => t).ToArray();
        FuzzerTimingStats? timing = null;
        if (timings.Length > 0)
        {
            timing = new FuzzerTimingStats
            {
                AvgMs = (int)timings.Average(),
                MinMs = timings[0],
                MaxMs = timings[^1],
                P95Ms = timings[(int)(timings.Length * 0.95)],
            };
        }

        var statusDist = orderedResults
            .Where(r => r.Status > 0)
            .GroupBy(r => r.Status)
            .ToDictionary(g => g.Key, g => g.Count());

        return new FuzzerResult
        {
            Timestamp = startTime,
            DurationSeconds = elapsed,
            AttackType = options.AttackType,
            TotalRequests = combinations.Count,
            Completed = orderedResults.Count,
            Errors = orderedResults.Count(r => r.Error != null),
            Flagged = orderedResults.Count(r => r.Flagged),
            StoppedEarly = stoppedEarly,
            StopReason = stopReason,
            StatusDistribution = statusDist,
            Timing = timing,
            Results = orderedResults,
            Options = options,
        };
    }

    /// <summary>
    /// Resolve payload set references to concrete payload arrays.
    /// Handles "built-in" keyword, custom payload lists, and generators (range, pattern, combine).
    /// </summary>
    private FuzzerTemplateData ApplyCallbackMarkerSubstitution(FuzzerTemplateData template)
    {
        var detector = _ctx.CallbackDetector;
        if (detector == null) return template;

        var hasMarker = CallbackDetector.ContainsCallbackMarker(template.Url)
            || CallbackDetector.ContainsCallbackMarker(template.Body)
            || template.Headers.Values.Any(CallbackDetector.ContainsCallbackMarker);
        if (!hasMarker) return template;

        if (!detector.Active)
            detector.Start();

        var headers = new Dictionary<string, string>(template.Headers, StringComparer.OrdinalIgnoreCase);
        foreach (var key in headers.Keys.ToList())
            headers[key] = detector.SubstituteMarkers(headers[key]);

        _log($"RequestFuzzer: substituted CALLBACK → {detector.CallbackUrl}", "#888888");
        return new FuzzerTemplateData
        {
            Url = detector.SubstituteMarkers(template.Url),
            Method = template.Method,
            Headers = headers,
            Body = template.Body != null ? detector.SubstituteMarkers(template.Body) : null,
            HasJson = template.HasJson
        };
    }

    private static Dictionary<string, string[]> ResolvePayloadSets(FuzzerOptions options)
    {
        var resolved = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        foreach (var ip in options.InjectionPoints)
        {
            var setName = ip.Value.PayloadSet;
            if (resolved.ContainsKey(setName)) continue;

            if (options.PayloadSets.TryGetValue(setName, out var customSet))
            {
                if (customSet.Count == 1 && customSet[0].Equals("built-in", StringComparison.OrdinalIgnoreCase))
                {
                    var builtIn = FuzzerPayloads.Resolve(setName, options.PayloadProfile);
                    resolved[setName] = builtIn ?? throw new ArgumentException(
                        $"Unknown built-in payload set '{setName}'. Available: {string.Join(", ", FuzzerPayloads.AvailableNames)}");
                }
                else
                {
                    resolved[setName] = customSet.ToArray();
                }
            }
            else
            {
                var builtIn = FuzzerPayloads.Resolve(setName, options.PayloadProfile);
                resolved[setName] = builtIn ?? throw new ArgumentException(
                    $"Payload set '{setName}' not found. Define it in payloadSets or use a built-in: {string.Join(", ", FuzzerPayloads.AvailableNames)}");
            }

            // E3: Apply generators if configured
            if (options.PayloadGenerators.TryGetValue(setName, out var generators))
            {
                var generated = new List<string>(resolved[setName]);
                foreach (var gen in generators)
                    generated.AddRange(GeneratePayloads(gen, options.PayloadProfile));
                resolved[setName] = generated.ToArray();
            }
        }

        return resolved;
    }

    /// <summary>
    /// E3: Generate payloads from a generator definition (range, pattern, combine).
    /// </summary>
    private static IEnumerable<string> GeneratePayloads(FuzzerPayloadGenerator gen, PayloadProfile payloadProfile = PayloadProfile.Small)
    {
        switch (gen.Type?.ToLowerInvariant())
        {
            case "range":
            {
                var from = gen.From;
                var to = Math.Min(gen.To, from + 100000);
                var step = Math.Max(gen.Step, 1);
                for (var i = from; i <= to; i += step)
                    yield return i.ToString();
                break;
            }
            case "pattern":
            {
                var template = gen.Template ?? "value{N}";
                var rangeFrom = gen.From;
                var rangeTo = Math.Min(gen.To, rangeFrom + 100000);
                for (var i = rangeFrom; i <= rangeTo; i++)
                    yield return template.Replace("{N}", i.ToString());
                break;
            }
            case "combine":
            {
                var baseSet = gen.BaseSet ?? "";
                var basePl = FuzzerPayloads.Resolve(baseSet, payloadProfile) ?? [];
                var encodings = gen.Encodings ?? ["url-encode"];
                foreach (var payload in basePl)
                    foreach (var encoding in encodings)
                        yield return ApplyEncoding(payload, encoding);
                break;
            }
        }
    }

    /// <summary>Apply encoding transforms to a payload string.</summary>
    private static string ApplyEncoding(string payload, string encoding)
    {
        return encoding.ToLowerInvariant() switch
        {
            "url-encode" or "urlencode" => Uri.EscapeDataString(payload),
            "double-url-encode" or "doubleurlencode" => Uri.EscapeDataString(Uri.EscapeDataString(payload)),
            "base64" => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(payload)),
            "html-entity" or "htmlentity" => System.Net.WebUtility.HtmlEncode(payload),
            "unicode" => string.Concat(payload.Select(c => $"\\u{(int)c:x4}")),
            "hex" => string.Concat(System.Text.Encoding.UTF8.GetBytes(payload).Select(b => $"%{b:x2}")),
            _ => payload,
        };
    }

    /// <summary>
    /// Generate all payload combinations based on the attack type.
    /// </summary>
    private static List<FuzzCombination> GenerateCombinations(
        FuzzerOptions options, Dictionary<string, string[]> resolvedPayloads)
    {
        var points = options.InjectionPoints.ToList();
        if (points.Count == 0)
        {
            // Infer from markers already present in the request template.
            var template = SerializeTemplate(options.Request);
            foreach (var marker in RequestMarkerSubstitute.ListMarkers(
                         template.Url, template.Body, template.Headers))
            {
                // CALLBACK is an OOB URL substitution marker, not a fuzz payload slot.
                if (marker.Equals("CALLBACK", StringComparison.OrdinalIgnoreCase))
                    continue;
                options.InjectionPoints[marker] = new FuzzerInjectionPoint { PayloadSet = "sqli-basic" };
            }
            points = options.InjectionPoints.ToList();
        }

        if (points.Count == 0)
            throw new ArgumentException(InjectionRequestErrors.WithRequestExample(
                "No injection points defined. Use §MARKER§ (or {{MARKER}}) in request.url, body, or headers; " +
                "injectionPoints is optional when markers are present (defaults to each marker name → payloadSet)."));

        return options.AttackType switch
        {
            FuzzerAttackType.Sniper => GenerateSniper(points, resolvedPayloads),
            FuzzerAttackType.BatteringRam => GenerateBatteringRam(points, resolvedPayloads),
            FuzzerAttackType.Pitchfork => GeneratePitchfork(points, resolvedPayloads),
            FuzzerAttackType.ClusterBomb => GenerateClusterBomb(points, resolvedPayloads),
            _ => throw new ArgumentException($"Unknown attack type: {options.AttackType}")
        };
    }

    private static List<FuzzCombination> GenerateSniper(
        List<KeyValuePair<string, FuzzerInjectionPoint>> points,
        Dictionary<string, string[]> payloads)
    {
        var combos = new List<FuzzCombination>();
        foreach (var activePoint in points)
        {
            var payloadArr = payloads[activePoint.Value.PayloadSet];
            for (int pi = 0; pi < payloadArr.Length; pi++)
            {
                var combo = new Dictionary<string, string>();
                var indices = new Dictionary<string, int>();
                foreach (var point in points)
                {
                    combo[point.Key] = point.Key == activePoint.Key ? payloadArr[pi] : $"§{point.Key}§";
                    indices[point.Key] = point.Key == activePoint.Key ? pi : -1;
                }
                combos.Add(new FuzzCombination(combo, indices));
            }
        }
        return combos;
    }

    private static List<FuzzCombination> GenerateBatteringRam(
        List<KeyValuePair<string, FuzzerInjectionPoint>> points,
        Dictionary<string, string[]> payloads)
    {
        var payloadArr = payloads[points[0].Value.PayloadSet];
        var combos = new List<FuzzCombination>();
        for (int pi = 0; pi < payloadArr.Length; pi++)
        {
            var combo = new Dictionary<string, string>();
            var indices = new Dictionary<string, int>();
            foreach (var point in points)
            {
                combo[point.Key] = payloadArr[pi];
                indices[point.Key] = pi;
            }
            combos.Add(new FuzzCombination(combo, indices));
        }
        return combos;
    }

    private static List<FuzzCombination> GeneratePitchfork(
        List<KeyValuePair<string, FuzzerInjectionPoint>> points,
        Dictionary<string, string[]> payloads)
    {
        var minLen = points.Min(p => payloads[p.Value.PayloadSet].Length);
        var combos = new List<FuzzCombination>();
        for (int i = 0; i < minLen; i++)
        {
            var combo = new Dictionary<string, string>();
            var indices = new Dictionary<string, int>();
            foreach (var point in points)
            {
                combo[point.Key] = payloads[point.Value.PayloadSet][i];
                indices[point.Key] = i;
            }
            combos.Add(new FuzzCombination(combo, indices));
        }
        return combos;
    }

    private static List<FuzzCombination> GenerateClusterBomb(
        List<KeyValuePair<string, FuzzerInjectionPoint>> points,
        Dictionary<string, string[]> payloads)
    {
        var sets = points.Select(p => payloads[p.Value.PayloadSet]).ToList();
        var names = points.Select(p => p.Key).ToList();
        var combos = new List<FuzzCombination>();
        var idxArr = new int[sets.Count];

        while (true)
        {
            var combo = new Dictionary<string, string>();
            var indices = new Dictionary<string, int>();
            for (int i = 0; i < names.Count; i++)
            {
                combo[names[i]] = sets[i][idxArr[i]];
                indices[names[i]] = idxArr[i];
            }
            combos.Add(new FuzzCombination(combo, indices));

            int carry = sets.Count - 1;
            while (carry >= 0)
            {
                idxArr[carry]++;
                if (idxArr[carry] < sets[carry].Length) break;
                idxArr[carry] = 0;
                carry--;
            }
            if (carry < 0) break;
        }
        return combos;
    }

    private static FuzzerTemplateData SerializeTemplate(FuzzerRequestTemplate template)
    {
        string? bodyStr = template.Body;
        if (bodyStr == null && template.Json != null)
        {
            bodyStr = template.Json is JsonElement je
                ? je.GetRawText()
                : JsonSerializer.Serialize(template.Json);
        }

        return new FuzzerTemplateData
        {
            Url = template.Url,
            Method = template.Method,
            Headers = template.Headers ?? new Dictionary<string, string>(),
            Body = bodyStr,
            HasJson = template.Json != null && template.Body == null,
        };
    }

    private async Task<BaselineData> SendBaselineRequest(FuzzerOptions options, FuzzerTemplateData template)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var cleanUrl = SubstituteMarkersWithDefault(template.Url, "test");
            var cleanMethod = SubstituteMarkersWithDefault(template.Method, "GET");
            var cleanBody = template.Body != null ? SubstituteMarkersWithDefault(template.Body, "test") : null;
            var cleanHeaders = new Dictionary<string, string>();
            foreach (var kv in template.Headers)
                cleanHeaders[kv.Key] = SubstituteMarkersWithDefault(kv.Value, "test");

            if (template.HasJson && cleanBody != null)
                cleanHeaders.TryAdd("Content-Type", "application/json");

            var responseJson = await _ctx.Fetch(cleanUrl, cleanMethod, cleanHeaders, cleanBody, options.TimeoutMs, options.Redirect);
            sw.Stop();

            using var doc = JsonDocument.Parse(responseJson);
            var root = doc.RootElement;
            var status = root.GetProperty("status").GetInt32();
            var body = ReadFetchBody(root);

            return new BaselineData
            {
                Status = status,
                DurationMs = (int)sw.ElapsedMilliseconds,
                ResponseLength = body.Length,
                BodyHash = body.GetHashCode(),
            };
        }
        catch
        {
            sw.Stop();
            return new BaselineData { Status = 0, DurationMs = (int)sw.ElapsedMilliseconds };
        }
    }

    private async Task<FuzzRequestResult> SendFuzzRequest(
        FuzzerOptions options, FuzzerTemplateData template,
        FuzzCombination combo, int index, BaselineData baseline)
    {
        var payloads = combo.Payloads;
        var sw = Stopwatch.StartNew();
        try
        {
            var url = SubstituteMarkers(template.Url, payloads);
            var method = SubstituteMarkers(template.Method, payloads);
            var body = template.Body != null ? SubstituteMarkers(template.Body, payloads) : null;
            var headers = new Dictionary<string, string>();
            foreach (var kv in template.Headers)
                headers[kv.Key] = SubstituteMarkers(kv.Value, payloads);

            if (template.HasJson && body != null)
                headers.TryAdd("Content-Type", "application/json");

            var responseJson = await _ctx.Fetch(url, method, headers, body, options.TimeoutMs, options.Redirect);
            sw.Stop();

            using var doc = JsonDocument.Parse(responseJson);
            var root = doc.RootElement;
            var status = root.GetProperty("status").GetInt32();
            var statusText = root.GetProperty("statusText").GetString();
            var responseBody = ReadFetchBody(root);
            var location = RedirectAnalysis.TryGetLocationFromFetchJson(responseJson);

            var (flags, flagDetails) = AnalyzeResponse(status, statusText, responseBody, location, url,
                (int)sw.ElapsedMilliseconds, payloads, baseline, options);

            var snippetLen = options.BodySnippetLength;
            var snippet = snippetLen > 0 && responseBody.Length > 0
                ? SanitizeSnippet(responseBody.Length > snippetLen ? responseBody[..snippetLen] + "..." : responseBody)
                : null;

            var maxBody = options.MaxResponseBodyLength;
            var bodyField = maxBody > 0 && responseBody.Length > 0
                ? PrepareResultBody(responseBody, maxBody)
                : null;

            return new FuzzRequestResult
            {
                Index = index,
                Payloads = payloads,
                PayloadIndices = combo.Indices,
                Status = status,
                StatusText = statusText,
                DurationMs = (int)sw.ElapsedMilliseconds,
                ResponseLength = responseBody.Length,
                Body = bodyField,
                BodySnippet = snippet,
                Flags = flags,
                FlagDetails = flagDetails,
                InjectedUrl = url,
                InjectedBody = body,
                Location = location,
            };
        }
        catch (Exception ex)
        {
            sw.Stop();
            // A thrown fetch is a CLIENT-side failure (illegal header value, non-ISO-8859-1 header,
            // request aborted/timed out, network/CORS error) — the request usually never reached the
            // server, so it is NOT a server bug. Record it as an error (counted in Errors) but do not
            // raise a flag; flagging these produced noisy false positives. Real server errors come back
            // as a normal response with status >= 500 and are flagged in AnalyzeResponse.
            return new FuzzRequestResult
            {
                Index = index,
                Payloads = payloads,
                PayloadIndices = combo.Indices,
                DurationMs = (int)sw.ElapsedMilliseconds,
                Error = ex.Message,
                Flags = FuzzFlag.None,
                FlagDetails = [],
            };
        }
    }

    private static (FuzzFlag flags, List<string> details) AnalyzeResponse(
        int status, string? statusText, string body, string? location, string requestUrl,
        int durationMs, Dictionary<string, string> payloads, BaselineData baseline,
        FuzzerOptions options)
    {
        var flags = FuzzFlag.None;
        var details = new List<string>();
        var acceptableResponseStatuses = options.AcceptableResponseStatuses;

        var acceptable = acceptableResponseStatuses is { Count: > 0 }
            ? new HashSet<int>(acceptableResponseStatuses)
            : null;

        // When the server returns e.g. 400/403/412 for bad input, status and body size often differ from baseline — usually expected, not an anomaly.
        bool IsAcceptableFuzzStatus() => acceptable != null && acceptable.Contains(status);

        if (status >= 500)
        {
            flags |= FuzzFlag.ServerError;
            details.Add($"Server error: {status} {statusText}");
        }

        if (options.Redirect is "manual" && RedirectAnalysis.IsRedirectStatus(status) &&
            !string.IsNullOrEmpty(location) && Uri.TryCreate(requestUrl, UriKind.Absolute, out var reqUri))
        {
            var probeHost = RedirectAnalysis.DefaultProbeHost;
            if (RedirectAnalysis.IsExternalRedirect(reqUri, location, probeHost) ||
                RedirectAnalysis.IsDangerousRedirectScheme(location))
            {
                flags |= FuzzFlag.OpenRedirect;
                details.Add($"Open redirect: HTTP {status} Location: {Truncate(location, 120)}");
            }
        }

        if (baseline.Status > 0 && status != baseline.Status)
        {
            if (!IsAcceptableFuzzStatus())
            {
                flags |= FuzzFlag.StatusAnomaly;
                details.Add($"Status changed: baseline {baseline.Status} → {status}");
            }
        }

        foreach (var kv in payloads)
        {
            if (kv.Value.Length >= 4 && body.Contains(kv.Value, StringComparison.OrdinalIgnoreCase))
            {
                flags |= FuzzFlag.Reflection;
                details.Add($"Payload reflected in response: {kv.Key}={Truncate(FuzzText.Clean(kv.Value), 50)}");
                var contextNote = XssReflectionAnalyzer.GetFuzzerReflectionContextNote(kv.Value, body);
                if (contextNote != null)
                    details.Add(contextNote);
                break;
            }
        }

        var bodyLower = body.ToLowerInvariant();
        foreach (var pattern in ErrorPatterns)
        {
            if (bodyLower.Contains(pattern.ToLowerInvariant()))
            {
                flags |= FuzzFlag.ErrorPattern;
                details.Add($"Error pattern detected: \"{pattern}\"");
                break;
            }
        }

        if (baseline.DurationMs > 0 && durationMs > Math.Max(baseline.DurationMs * 3, 1000))
        {
            flags |= FuzzFlag.TimingAnomaly;
            details.Add($"Slow response: {durationMs}ms (baseline: {baseline.DurationMs}ms)");
        }

        if (baseline.ResponseLength > 100)
        {
            var ratio = (double)body.Length / baseline.ResponseLength;
            if (ratio < 0.3 || ratio > 3.0)
            {
                if (!IsAcceptableFuzzStatus())
                {
                    flags |= FuzzFlag.LengthAnomaly;
                    details.Add($"Response length anomaly: {body.Length}b (baseline: {baseline.ResponseLength}b)");
                }
            }
        }

        return (flags, details);
    }

    /// <summary>
    /// Extract the marker name from a match that can be either §NAME§ or {{NAME}}.
    /// </summary>
    private static string GetMarkerName(Match match) =>
        match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;

    /// <summary>
    /// Replace §MARKER§ and {{MARKER}} patterns with corresponding payload values.
    /// </summary>
    private static string SubstituteMarkers(string input, Dictionary<string, string> payloads)
    {
        return MarkerRegex.Replace(input, match =>
        {
            var name = GetMarkerName(match);
            return payloads.TryGetValue(name, out var val) ? val : match.Value;
        });
    }

    /// <summary>
    /// Replace all markers with a default value (used for baseline requests).
    /// </summary>
    private static string SubstituteMarkersWithDefault(string input, string defaultValue)
    {
        return MarkerRegex.Replace(input, defaultValue);
    }

    /// <summary>Read fetch() JSON <c>body</c> whether encoded as string, null, or unexpected kind.</summary>
    private static string ReadFetchBody(JsonElement root)
    {
        if (!root.TryGetProperty("body", out var b))
            return "";
        return b.ValueKind switch
        {
            JsonValueKind.String => b.GetString() ?? "",
            JsonValueKind.Null => "",
            _ => b.GetRawText()
        };
    }

    /// <summary>Truncate and strip NULs so large/binary fragments do not break JSON APIs.</summary>
    private static string PrepareResultBody(string responseBody, int maxLen)
    {
        var s = responseBody.Length <= maxLen ? responseBody : responseBody[..maxLen];
        if (s.IndexOf('\0') >= 0)
            s = s.Replace("\0", "", StringComparison.Ordinal);
        return s;
    }

    /// <summary>
    /// Replace control characters (U+0000–U+001F except \t \n \r) with Unicode escapes
    /// so the snippet is safe for all JSON parsers including PowerShell's ConvertFrom-Json.
    /// </summary>
    private static string SanitizeSnippet(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c < ' ' && c != '\t' && c != '\n' && c != '\r')
                sb.Append($"\\u{(int)c:x4}");
            else if (c == '\n')
                sb.Append("\\n");
            else if (c == '\r')
                sb.Append("\\r");
            else if (c == '\t')
                sb.Append("\\t");
            else
                sb.Append(c);
        }
        return sb.ToString();
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..(max - 3)] + "...";

    private class FuzzerTemplateData
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public Dictionary<string, string> Headers { get; init; } = new();
        public string? Body { get; init; }
        public bool HasJson { get; init; }
    }

    private class BaselineData
    {
        public int Status { get; init; }
        public int DurationMs { get; init; }
        public int ResponseLength { get; init; }
        public int BodyHash { get; init; }
    }
}
