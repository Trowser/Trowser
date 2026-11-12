using System.Text.Json;
using Trowser.Automation;
using Trowser.Robustness;
using Trowser.Security;
using Trowser.Security.Orchestration;

namespace Trowser.EndpointProbe;

/// <summary>Runs endpoint-scoped playbooks and non-playbook probes.</summary>
public static class EndpointProbeRunner
{
    public sealed class RunOptions
    {
        public required IReadOnlyList<EndpointProbeItem> Endpoints { get; init; }
        public required IReadOnlyList<string> ProbeIds { get; init; }
        public SafetyMode SafetyMode { get; init; } = SafetyMode.Active;
        public string Depth { get; init; } = "standard";
        public bool UseCapturedHeadersBody { get; init; } = true;
        public bool ReplayOnceBeforeScan { get; init; }
        /// <summary>When true, Auth Control Identifier tests every non-hop-by-hop header.</summary>
        public bool AuthControlAllHeaders { get; init; }
    }

    public sealed class RunResult
    {
        public AuthControlIdentifier.ScanResult? AuthControl { get; init; }
    }

    /// <summary>
    /// Effectively no wall-clock/request cap — endpoint probe uses depth to control thoroughness.
    /// Must stay within <see cref="ScanTimeout.MaxSafeBudgetSeconds"/> so A05 injection-scan
    /// can call CancelAfter and convert seconds to milliseconds.
    /// </summary>
    private const int UnlimitedBudget = ScanTimeout.MaxSafeBudgetSeconds;

    public static async Task<RunResult> RunAsync(AutomationContext context, RunOptions options, CancellationToken ct = default)
    {
        AuthControlIdentifier.ScanResult? authControl = null;
        var wantsAuthControl = options.ProbeIds.Any(id =>
            id.Equals(EndpointProbeCatalog.AuthControlIdentifierId, StringComparison.OrdinalIgnoreCase));

        // Auth Control Identifier runs once across all selected endpoints (for consistency summary).
        if (wantsAuthControl)
        {
            authControl = await RunAuthControlIdentifierAsync(context, options, ct);
        }

        foreach (var endpoint in options.Endpoints)
        {
            ct.ThrowIfCancellationRequested();

            context.Log($"=== Endpoint: {endpoint.Method} {endpoint.Url} ===", "#4EC9B0");

            if (options.ReplayOnceBeforeScan)
            {
                await ReplayEndpointAsync(context, endpoint, options.UseCapturedHeadersBody, ct);
            }

            foreach (var probeId in options.ProbeIds)
            {
                ct.ThrowIfCancellationRequested();

                if (probeId.Equals(EndpointProbeCatalog.AuthControlIdentifierId, StringComparison.OrdinalIgnoreCase))
                    continue; // already ran above

                if (probeId.Equals(EndpointProbeCatalog.RequestFuzzerId, StringComparison.OrdinalIgnoreCase))
                {
                    await RunRequestFuzzerAsync(context, endpoint, options, ct);
                    continue;
                }

                await RunPlaybookAsync(context, endpoint, probeId, options, ct);
            }

            context.Log("", "#CCCCCC");
        }

        return new RunResult { AuthControl = authControl };
    }

    private static async Task<AuthControlIdentifier.ScanResult?> RunAuthControlIdentifierAsync(
        AutomationContext context, RunOptions options, CancellationToken ct)
    {
        if (!options.SafetyMode.AllowsWriteVerbs())
        {
            context.Log("  Auth Control Identifier skipped — requires Active or Aggressive safety mode.", "#CCA700");
            return null;
        }

        var endpoints = options.UseCapturedHeadersBody
            ? options.Endpoints
            : options.Endpoints.Select(e => new EndpointProbeItem
            {
                Method = e.Method,
                Url = e.Url,
                Priority = e.Priority,
                Timestamp = e.Timestamp,
                RequestHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                RequestBody = null,
                StatusCode = e.StatusCode,
                ResourceType = e.ResourceType,
                IsImported = e.IsImported
            }).ToList();

        var methodHint = endpoints.Any(e => e.Method is "POST" or "PUT" or "PATCH" or "DELETE");
        if (methodHint)
        {
            var n = endpoints.Sum(e =>
            {
                // Rough candidate count for the warning (cookies + interest headers).
                var cookies = 0;
                if (e.RequestHeaders.TryGetValue("Cookie", out var c) && !string.IsNullOrEmpty(c))
                    cookies = c.Split(';', StringSplitOptions.RemoveEmptyEntries).Length;
                return 1 + 2 * Math.Max(1, cookies);
            });
            context.Log(
                $"  Note: state-changing methods will be replayed roughly {n}+ times (baseline + omit/tamper per candidate).",
                "#CCA700");
        }

        var colored = new AuthControlIdentifier(context, (msg, color) => context.Log(msg, color));
        var result = await colored.RunAsync(new AuthControlIdentifier.ProbeOptions
        {
            Endpoints = endpoints.ToList(),
            AllHeaders = options.AuthControlAllHeaders,
            TimeoutMs = 12_000
        }, ct);

        AuthControlIdentifier.LogMarkdownTable((msg, color) => context.Log(msg, color), result);
        return result;
    }

    private static async Task ReplayEndpointAsync(
        AutomationContext context,
        EndpointProbeItem endpoint,
        bool useCaptured,
        CancellationToken ct)
    {
        Dictionary<string, string>? headers = null;
        string? body = null;

        if (useCaptured)
        {
            headers = FilterReplayHeaders(endpoint.RequestHeaders);
            body = endpoint.RequestBody;
        }

        context.Log($"  Replay: {endpoint.Method} {endpoint.Url}", "#888888");
        try
        {
            var json = await context.Fetch(endpoint.Url, endpoint.Method, headers, body);
            using var doc = JsonDocument.Parse(json);
            var status = doc.RootElement.TryGetProperty("status", out var sp) ? sp.GetInt32() : 0;
            context.Log($"  Replay response: HTTP {status}", status >= 400 ? "#CCA700" : "#888888");
        }
        catch (Exception ex)
        {
            context.Log($"  Replay failed: {ex.Message}", "#F44747");
        }
    }

    private static Dictionary<string, string>? FilterReplayHeaders(Dictionary<string, string> headers)
    {
        if (headers.Count == 0)
            return null;

        var skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Host", "Content-Length", "Connection", "Transfer-Encoding"
        };

        var filtered = headers
            .Where(kv => !skip.Contains(kv.Key))
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);

        return filtered.Count > 0 ? filtered : null;
    }

    private static async Task RunPlaybookAsync(
        AutomationContext context,
        EndpointProbeItem endpoint,
        string playbookId,
        RunOptions options,
        CancellationToken ct)
    {
        context.Log($"  Playbook: {playbookId} ({options.SafetyMode.ToLabel()}, depth={options.Depth})", "#569CD6");
        string? scopeHost = null;
        if (Uri.TryCreate(endpoint.Url, UriKind.Absolute, out var endpointUri))
            scopeHost = endpointUri.Host;

        await context.PrintPlaybookReport(
            playbookId,
            safetyMode: options.SafetyMode.ToLabel(),
            depth: options.Depth,
            host: scopeHost,
            maxSeconds: UnlimitedBudget,
            maxRequests: UnlimitedBudget,
            includeCrawl: false,
            targetUrl: endpoint.Url,
            targetMethod: endpoint.Method,
            ct: ct);
    }

    private static async Task RunRequestFuzzerAsync(
        AutomationContext context,
        EndpointProbeItem endpoint,
        RunOptions options,
        CancellationToken ct)
    {
        if (!options.SafetyMode.AllowsWriteVerbs())
        {
            context.Log("  Request Fuzzer skipped — requires Active or Aggressive safety mode.", "#CCA700");
            return;
        }

        var includeInjection = options.SafetyMode == SafetyMode.Aggressive;
        if ((endpoint.RequestBody?.Length ?? 0) > EndpointProbeFuzzer.MaxBodyChars
            && EndpointProbeFuzzer.LooksLikeJson(endpoint))
        {
            context.Log("  JSON body is over 64 KB — field mutations skipped.", "#CCA700");
        }

        var probes = EndpointProbeFuzzer.BuildProbes(endpoint, includeInjection, options.UseCapturedHeadersBody);
        if (probes.Count == 0)
        {
            context.Log("  Request Fuzzer skipped — nothing to mutate on this endpoint.", "#CCA700");
            return;
        }

        context.Log(includeInjection
            ? $"  Request Fuzzer: {probes.Count} single-fault probe(s), including injection"
            : $"  Request Fuzzer: {probes.Count} single-fault probe(s). Aggressive safety mode adds injection.",
            "#569CD6");

        var baselineHeaders = options.UseCapturedHeadersBody
            ? CapturedHeaders(endpoint, EndpointProbeFuzzer.LooksLikeJson(endpoint))
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (EndpointProbeFuzzer.LooksLikeJson(endpoint))
            baselineHeaders["Content-Type"] = "application/json";

        var baseline = await SendProbeAsync(context, new EndpointProbeFuzzer.FuzzProbe
        {
            Fault = "baseline (captured request)",
            Method = endpoint.Method,
            Url = endpoint.Url,
            Headers = baselineHeaders,
            Body = endpoint.RequestBody
        }, ct);

        var sent = baseline.BrowserRefused ? 0 : 1;
        var refused = baseline.BrowserRefused ? 1 : 0;
        var failures = new List<(EndpointProbeFuzzer.FuzzProbe Probe, ProbeSend Send)>();
        var reflections = new List<(EndpointProbeFuzzer.FuzzProbe Probe, ProbeSend Send)>();

        if (baseline.Status >= 500 || baseline.Dropped)
        {
            failures.Add((new EndpointProbeFuzzer.FuzzProbe
            {
                Fault = "baseline (captured request)",
                Method = endpoint.Method,
                Url = endpoint.Url,
                Headers = baselineHeaders,
                Body = endpoint.RequestBody
            }, baseline));
            context.Log("  Baseline already failed — mutations skipped so they are not double-counted.", "#F44747");
        }
        else
        {
            foreach (var probe in probes)
            {
                ct.ThrowIfCancellationRequested();
                var result = await SendProbeAsync(context, probe, ct);
                if (result.BrowserRefused)
                {
                    refused++;
                    continue;
                }
                sent++;
                if (result.Status >= 500 || result.Dropped)
                    failures.Add((probe, result));
                else if (IsReflected(probe, result))
                    reflections.Add((probe, result));
            }
        }

        foreach (var (probe, result) in failures)
            LogProbeHit(context, probe, result, "#F44747");

        if (reflections.Count > 0)
        {
            context.Log($"  Reflections ({reflections.Count}) — response echoed a probe value without a 5xx:", "#CCA700");
            foreach (var (probe, result) in reflections.Take(8))
                LogProbeHit(context, probe, result, "#CCA700");
            if (reflections.Count > 8)
                context.Log($"    ... and {reflections.Count - 8} more reflection(s).", "#888888");
        }

        context.Log(
            $"  Fuzzer summary: {failures.Count} server failure(s) ({failures.Count(f => f.Send.Status >= 500)} 5xx, {failures.Count(f => f.Send.Dropped)} dropped), {reflections.Count} reflection(s), {sent} sent" +
            (refused > 0 ? $", {refused} refused by the browser" : ""),
            "#569CD6");
    }

    private static void LogProbeHit(AutomationContext context, EndpointProbeFuzzer.FuzzProbe probe, ProbeSend result, string color)
    {
        var status = result.Dropped ? "connection dropped" : $"{result.Status} {result.StatusText}".Trim();
        context.Log($"    {status} — {probe.Fault}", color);
        context.Log($"      {probe.Method} {Clip(probe.Url, 240)}", "#888888");
        if (!string.IsNullOrEmpty(probe.Body))
            context.Log($"      body: {Clip(probe.Body, 240)}", "#888888");
        if (!string.IsNullOrEmpty(result.Body))
            context.Log($"      response: {Clip(result.Body, 200)}", "#888888");
    }

    private static bool IsReflected(EndpointProbeFuzzer.FuzzProbe probe, ProbeSend result)
    {
        var needle = probe.ReflectNeedle;
        if (string.IsNullOrEmpty(needle) || needle.Length < 4) return false;
        return result.Body.Contains(needle, StringComparison.Ordinal);
    }

    private static Dictionary<string, string> CapturedHeaders(EndpointProbeItem endpoint, bool forceJson)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in endpoint.RequestHeaders)
        {
            if (IsHopByHop(kv.Key)) continue;
            headers[kv.Key] = kv.Value;
        }
        if (forceJson)
            headers["Content-Type"] = "application/json";
        return headers;
    }

    private static bool IsHopByHop(string name)
    {
        var n = name.ToLowerInvariant();
        if (n.StartsWith("sec-", StringComparison.Ordinal) || n.StartsWith("proxy-", StringComparison.Ordinal))
            return true;
        return n is "cookie" or "host" or "content-length" or "connection" or "accept-encoding"
            or "origin" or "referer" or "transfer-encoding" or "keep-alive" or "te" or "upgrade"
            or "content-encoding" or "trailer";
    }

    private static async Task<ProbeSend> SendProbeAsync(
        AutomationContext context, EndpointProbeFuzzer.FuzzProbe probe, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            var raw = await context.Fetch(probe.Url, probe.Method, probe.Headers, probe.Body, timeoutMs: 8000);
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            var status = root.TryGetProperty("status", out var st) && st.TryGetInt32(out var n) ? n : 0;
            var statusText = root.TryGetProperty("statusText", out var tx) ? tx.GetString() ?? "" : "";
            var body = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            var error = root.TryGetProperty("error", out var err) ? err.GetString() : null;
            if (status == 0 && IsBrowserReject(error))
                return new ProbeSend(0, statusText, body, Dropped: false, BrowserRefused: true);
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.True;
            return new ProbeSend(status, statusText, body, Dropped: status == 0 && !ok, BrowserRefused: false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (IsBrowserReject(ex.Message))
        {
            return new ProbeSend(0, "", "", Dropped: false, BrowserRefused: true);
        }
        catch (Exception)
        {
            return new ProbeSend(0, "", "", Dropped: true, BrowserRefused: false);
        }
    }

    private static string Clip(string? value, int max)
    {
        var text = FuzzText.Clean(value);
        return text.Length > max ? text[..(max - 3)] + "..." : text;
    }

    private static bool IsBrowserReject(string? message)
    {
        if (string.IsNullOrEmpty(message)) return false;
        return message.Contains("forbidden header", StringComparison.OrdinalIgnoreCase)
            || message.Contains("invalid header", StringComparison.OrdinalIgnoreCase)
            || message.Contains("is not a valid HTTP header", StringComparison.OrdinalIgnoreCase)
            || message.Contains("Failed to execute 'set'", StringComparison.OrdinalIgnoreCase);
    }

    private readonly record struct ProbeSend(int Status, string StatusText, string Body, bool Dropped, bool BrowserRefused);
}
