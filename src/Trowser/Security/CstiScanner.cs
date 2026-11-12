using System.Diagnostics;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Single-point client-side template injection probe — navigates with template payloads and checks rendered DOM.
/// </summary>
public static class CstiScanner
{
    public sealed class CstiProbeOptions
    {
        public bool Escalate { get; set; }
        public bool MonitorSinks { get; set; } = true;
        public int TimeoutMs { get; set; } = 10_000;
        public IReadOnlyList<CstiProbes.Engine>? EngineCandidates { get; set; }
    }

    public sealed class CstiRow
    {
        public string Payload { get; init; } = "";
        public string Level { get; init; } = "basic";
        public bool ExpressionEvaluated { get; init; }
        public string? EvaluatedToken { get; init; }
        public bool CodeExecution { get; init; }
        public List<string> Sinks { get; init; } = [];
        public string Severity { get; init; } = "info";
        public string? EngineHint { get; init; }
    }

    public sealed class CstiProbeResult
    {
        public string BaseUrl { get; init; } = "";
        public string ParamName { get; init; } = "";
        public string Source { get; init; } = "";
        public string Engine { get; init; } = "";
        public List<CstiRow> Rows { get; init; } = [];
        public int ElapsedMs { get; init; }
        public bool HasFindings => Rows.Any(r => r.ExpressionEvaluated && r.Level is "basic" or "escalation");
        public string? WorstSeverity { get; init; }
    }

    public static Task<CstiProbeResult> ProbeAsync(
        AutomationContext ctx,
        string baseUrl,
        string paramName,
        CstiProbes.Source source,
        CstiProbes.Engine engine,
        CstiProbeOptions options,
        CancellationToken ct = default)
    {
        var singleEngineOptions = new CstiProbeOptions
        {
            Escalate = options.Escalate,
            MonitorSinks = options.MonitorSinks,
            TimeoutMs = options.TimeoutMs,
            EngineCandidates = [engine]
        };
        return IdentifyAndProbeAsync(ctx, baseUrl, paramName, source, singleEngineOptions, ct);
    }

    public static async Task<CstiProbeResult> IdentifyAndProbeAsync(
        AutomationContext ctx,
        string baseUrl,
        string paramName,
        CstiProbes.Source source,
        CstiProbeOptions options,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var rows = new List<CstiRow>();
        var baselineValue = "trowser-csti-baseline";
        var waitMs = Math.Clamp(options.TimeoutMs / 3, 500, 2000);
        var candidates = options.EngineCandidates?.Where(e => e != CstiProbes.Engine.Generic).Distinct().ToList() ?? [];

        var basic = await ProbePayloadAsync(ctx, baseUrl, paramName, source, "{{7*7}}", "basic", baselineValue,
            options, waitMs, expectedToken: "49", ct);
        rows.Add(basic);

        if (!basic.ExpressionEvaluated)
        {
            sw.Stop();
            return BuildResult(baseUrl, paramName, source, CstiProbes.Engine.Generic, rows, sw);
        }

        async Task<bool> DifferentiatorMatches(CstiProbes.Engine engine)
        {
            var diff = CstiProbes.Differentiator(engine);
            if (diff == null) return false;
            var row = await ProbePayloadAsync(ctx, baseUrl, paramName, source, diff.Payload, "differentiator",
                baselineValue, options, waitMs, expectedToken: diff.ExpectedToken, ct);
            rows.Add(new CstiRow
            {
                Payload = row.Payload,
                Level = row.Level,
                ExpressionEvaluated = row.ExpressionEvaluated,
                EvaluatedToken = row.EvaluatedToken,
                CodeExecution = row.CodeExecution,
                Sinks = row.Sinks,
                Severity = row.Severity,
                EngineHint = CstiProbes.EngineName(engine)
            });
            return row.ExpressionEvaluated;
        }

        var identified = await CstiProbes.IdentifyEngineAsync(ctx, candidates, DifferentiatorMatches);

        if (options.Escalate)
        {
            foreach (var escalation in CstiProbes.EscalationVariants(identified))
            {
                ct.ThrowIfCancellationRequested();
                var row = await ProbePayloadAsync(ctx, baseUrl, paramName, source, escalation, "escalation",
                    baselineValue, options, waitMs, expectedToken: CstiDomOracle.ExpectedToken(escalation), ct);
                rows.Add(row);
                if (row.ExpressionEvaluated)
                    break;
            }
        }

        sw.Stop();
        return BuildResult(baseUrl, paramName, source, identified, rows, sw);
    }

    private static CstiProbeResult BuildResult(
        string baseUrl,
        string paramName,
        CstiProbes.Source source,
        CstiProbes.Engine engine,
        List<CstiRow> rows,
        Stopwatch sw)
    {
        var hasBasic = rows.Any(r => r.Level == "basic" && r.ExpressionEvaluated);
        var worst = rows.Where(r => r.ExpressionEvaluated && r.Level is "basic" or "escalation")
            .Select(r => r.Severity)
            .OrderByDescending(SeverityRank)
            .FirstOrDefault();

        return new CstiProbeResult
        {
            BaseUrl = baseUrl,
            ParamName = paramName,
            Source = SourceName(source),
            Engine = CstiProbes.EngineName(engine),
            Rows = rows,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            WorstSeverity = hasBasic ? worst : null
        };
    }

    private static async Task<CstiRow> ProbePayloadAsync(
        AutomationContext ctx,
        string baseUrl,
        string paramName,
        CstiProbes.Source source,
        string payload,
        string level,
        string baselineValue,
        CstiProbeOptions options,
        int waitMs,
        string? expectedToken,
        CancellationToken ct)
    {
        string? docScriptId = null;
        if (options.MonitorSinks)
        {
            docScriptId = await Runtime.RuntimeSensorInstaller.InstallDocumentCreatedAsync(ctx);
            if (docScriptId == null)
                await Runtime.RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(ctx);
        }

        try
        {
            var baselineUrl = BuildUrl(baseUrl, paramName, source, baselineValue);
            if (source == CstiProbes.Source.UrlHash)
                baselineUrl = UrlPayloadInjector.StripFragment(baselineUrl);

            await ctx.Navigate(baselineUrl);
            await Task.Delay(waitMs, ct);
            var baselineDom = await CstiDomOracle.CaptureAsync(ctx);

            ct.ThrowIfCancellationRequested();
            var probeUrl = BuildUrl(baseUrl, paramName, source, payload);
            if (source == CstiProbes.Source.UrlHash)
                probeUrl = UrlPayloadInjector.EnsureFullNavigation(probeUrl);

            await ctx.Navigate(probeUrl);
            await Task.Delay(waitMs, ct);
            var probeDom = await CstiDomOracle.CaptureAsync(ctx);

            var token = expectedToken ?? CstiDomOracle.ExpectedToken(payload);
            var evaluated = !string.IsNullOrEmpty(token)
                && CstiDomOracle.DetectToken(baselineDom, probeDom, token);
            var windowEscape = level == "escalation"
                               && CstiDomOracle.DetectWindowObject(baselineDom, probeDom);
            var sinks = options.MonitorSinks ? await CollectSinksAsync(ctx) : [];
            var sinkNames = sinks.Select(s => s.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? s)
                .ToList();
            var codeExecution = level == "escalation"
                                && (windowEscape
                                    || (evaluated && sinkNames.Any(s =>
                                        s.Contains("Function", StringComparison.OrdinalIgnoreCase)
                                        || s.Contains("eval", StringComparison.OrdinalIgnoreCase))));

            var severity = evaluated switch
            {
                false => "info",
                _ when codeExecution => "critical",
                _ when sinks.Count > 0 => "high",
                _ => "medium"
            };

            return new CstiRow
            {
                Payload = payload,
                Level = level,
                ExpressionEvaluated = evaluated,
                EvaluatedToken = evaluated ? token : null,
                CodeExecution = codeExecution,
                Sinks = sinks,
                Severity = severity
            };
        }
        catch (Exception ex)
        {
            return new CstiRow
            {
                Payload = payload,
                Level = level,
                Severity = "info",
                Sinks = [$"error: {ex.Message}"]
            };
        }
        finally
        {
            if (docScriptId != null)
            {
                try { await ctx.RemoveDocumentCreatedScriptAsync(docScriptId); }
                catch { }
            }
        }
    }

    private static string BuildUrl(string baseUrl, string paramName, CstiProbes.Source source, string payload)
    {
        var spec = source switch
        {
            CstiProbes.Source.UrlQuery => new UrlInjectionSpec
            {
                Part = UrlInjectionPart.Query,
                Param = paramName,
                Encode = UrlPayloadEncodeMode.None
            },
            _ => new UrlInjectionSpec
            {
                Part = UrlInjectionPart.Hash,
                Param = paramName,
                Encode = UrlPayloadEncodeMode.None
            }
        };

        return UrlPayloadInjector.Build(baseUrl, spec, payload);
    }

    private static string SourceName(CstiProbes.Source source) => source switch
    {
        CstiProbes.Source.UrlQuery => "url-query",
        _ => "url-hash"
    };

    private static async Task<List<string>> CollectSinksAsync(AutomationContext ctx)
    {
        try
        {
            var json = await ctx.ExecuteJs("""
                (function() {
                    var log = window.__trowser_sink_log || [];
                    return JSON.stringify(log.map(function(e) {
                        return { sink: e.sink || '', stack: e.stack || '' };
                    }));
                })()
                """);
            var entries = JsonSerializer.Deserialize<List<SinkLogEntry>>(json) ?? [];
            return AggregateSinkLog(entries);
        }
        catch
        {
            return [];
        }
    }

    private sealed class SinkLogEntry
    {
        public string Sink { get; set; } = "";
        public string Stack { get; set; } = "";
    }

    private static List<string> AggregateSinkLog(IReadOnlyList<SinkLogEntry> entries)
    {
        if (entries.Count == 0) return [];

        return entries
            .GroupBy(e => (Sink: string.IsNullOrWhiteSpace(e.Sink) ? "unknown" : e.Sink,
                Script: ExtractScriptHint(e.Stack)))
            .Select(g =>
            {
                var label = g.Key.Sink;
                if (g.Count() > 1) label += $" × {g.Count()}";
                if (!string.IsNullOrEmpty(g.Key.Script)) label += $" ({g.Key.Script})";
                return label;
            })
            .OrderByDescending(s => s)
            .ToList();
    }

    private static string ExtractScriptHint(string stack)
    {
        if (string.IsNullOrWhiteSpace(stack)) return "";
        var m = System.Text.RegularExpressions.Regex.Match(stack, @"([^/\\]+\.js)", System.Text.RegularExpressions.RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
        return m.Success ? m.Groups[1].Value : "";
    }

    private static int SeverityRank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };
}
