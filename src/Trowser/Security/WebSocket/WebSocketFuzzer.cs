using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Robustness;
using Trowser.Security.Runtime;

namespace Trowser.Security.WebSocket;

/// <summary>
/// Active WebSocket message fuzzing: sends payload catalogs and inspects received frames.
/// </summary>
public sealed class WebSocketFuzzer
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    private static readonly Regex HtmlPattern = new(
        @"<(?:script|img|svg|iframe|object|embed|link)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public WebSocketFuzzer(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<WebSocketFuzzResult> RunAsync(WebSocketFuzzOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var manager = _ctx.ActiveTab.WebSocket;
        var connections = manager.GetConnections()
            .Where(c => c.State is "open" or "connecting")
            .ToList();

        if (options.ConnectionId is int cid)
            connections = connections.Where(c => c.ConnectionId == cid).ToList();

        if (connections.Count == 0)
        {
            return new WebSocketFuzzResult
            {
                Message = "No active WebSocket connections. Browse the app and trigger realtime traffic first.",
                SkippedReason = "no-connections"
            };
        }

        var payloadSets = ResolvePayloadSets(options);
        var findings = new List<WebSocketFuzzFinding>();
        var payloadsSent = 0;
        var waitMs = options.ResponseWaitMs > 0 ? options.ResponseWaitMs : 500;

        await WebSocketJsBridge.EnsureHookAsync(_ctx);
        try
        {
            await _ctx.InstallRuntimeSensorAsync();
        }
        catch
        {
            /* best effort */
        }

        foreach (var conn in connections.Take(options.MaxConnections))
        {
            ct.ThrowIfCancellationRequested();

            foreach (var oracle in WebSocketExecOracle.BuildProbes(4))
            {
                ct.ThrowIfCancellationRequested();
                var rtMark = _ctx.ActiveTab.RuntimeEvents.Mark();
                var send = await WebSocketJsBridge.SendAsync(_ctx, conn.ConnectionId, oracle.Payload);
                payloadsSent++;
                if (!send.Ok)
                    continue;

                await Task.Delay(Math.Max(waitMs, 600), ct);
                if (await DetectWsExecOracleAsync(rtMark, oracle.CanaryId))
                {
                    findings.Add(new WebSocketFuzzFinding
                    {
                        Severity = "critical",
                        Confidence = "confirmed",
                        ConnectionId = conn.ConnectionId,
                        Url = conn.Url,
                        PayloadSet = "ws-code-exec-oracle",
                        Payload = Truncate(oracle.Payload, 120),
                        MessageSent = Truncate(oracle.Payload, 200),
                        Indicator = "ws-code-execution-confirmed",
                        Detail = $"Inbound WebSocket message executed attacker-controlled JavaScript ({oracle.Vector}).",
                        ReceivedSnippet = oracle.CanaryId
                    });
                    break;
                }
            }

            if (options.IncludeMessageTypeMatrix)
            {
                var matrixFindings = await RunMessageTypeMatrixAsync(conn, manager, waitMs, options, ct);
                findings.AddRange(matrixFindings);
                payloadsSent += matrixFindings.Count;
            }

            foreach (var (setName, payloads) in payloadSets)
            {
                foreach (var payload in payloads.Take(options.MaxPayloadsPerSet))
                {
                    ct.ThrowIfCancellationRequested();
                    var messages = BuildMessages(payload, options, conn);
                    foreach (var message in messages)
                    {
                        var rtMark = _ctx.ActiveTab.RuntimeEvents.Mark();
                        var beforeCount = manager.GetFrames(conn.ConnectionId).Count;
                        var send = await WebSocketJsBridge.SendAsync(_ctx, conn.ConnectionId, message);
                        payloadsSent++;
                        if (!send.Ok)
                        {
                            findings.Add(new WebSocketFuzzFinding
                            {
                                Severity = "info",
                                Confidence = "confirmed",
                                ConnectionId = conn.ConnectionId,
                                Url = conn.Url,
                                PayloadSet = setName,
                                Payload = Truncate(payload, 120),
                                MessageSent = Truncate(message, 200),
                                Indicator = "send-failed",
                                Detail = send.Error ?? "WebSocket send failed"
                            });
                            continue;
                        }

                        await Task.Delay(waitMs, ct);
                        var newFrames = manager.GetFrames(conn.ConnectionId)
                            .Skip(beforeCount)
                            .Where(f => f.Direction == "received")
                            .ToList();

                        AnalyzeReceivedFrames(conn, setName, payload, message, newFrames, findings);
                        AppendSinkReachFindings(conn, setName, payload, message, rtMark, findings);
                    }
                }
            }
        }

        sw.Stop();
        return BuildResult(findings, connections.Count, payloadsSent, sw.ElapsedMilliseconds);
    }

    private async Task<List<WebSocketFuzzFinding>> RunMessageTypeMatrixAsync(
        WebSocketConnection conn,
        WebSocketManager manager,
        int waitMs,
        WebSocketFuzzOptions options,
        CancellationToken ct)
    {
        var findings = new List<WebSocketFuzzFinding>();
        var frames = manager.GetFrames(conn.ConnectionId);
        var privilegedTypes = DiscoverPrivilegedTypes(frames);
        if (privilegedTypes.Count == 0)
            return findings;

        foreach (var msgType in privilegedTypes.Take(options.MaxMessageTypes))
        {
            ct.ThrowIfCancellationRequested();
            var template = frames
                .Where(f => f.Direction == "sent" && f.IsJson)
                .FirstOrDefault(f => f.JsonType?.Equals(msgType, StringComparison.OrdinalIgnoreCase) == true);
            var body = template != null
                ? MutateJsonType(template.Data, msgType)
                : JsonSerializer.Serialize(new { type = msgType, payload = "<script>alert(1)</script>" });

            var beforeCount = manager.GetFrames(conn.ConnectionId).Count;
            var send = await WebSocketJsBridge.SendAsync(_ctx, conn.ConnectionId, body);
            if (!send.Ok) continue;

            await Task.Delay(waitMs, ct);
            var received = manager.GetFrames(conn.ConnectionId)
                .Skip(beforeCount)
                .Where(f => f.Direction == "received")
                .ToList();

            if (received.Any(f => HtmlPattern.IsMatch(f.Data)))
            {
                findings.Add(new WebSocketFuzzFinding
                {
                    Severity = "high",
                    Confidence = "likely",
                    ConnectionId = conn.ConnectionId,
                    Url = conn.Url,
                    PayloadSet = "message-type-matrix",
                    Payload = msgType,
                    MessageSent = Truncate(body, 200),
                    Indicator = "ws-html-in-response",
                    Detail = $"Replayed privileged message type '{msgType}' — HTML/script content in received frame.",
                    ReceivedSnippet = Truncate(received.First(f => HtmlPattern.IsMatch(f.Data)).Data, 200)
                });
            }
            else if (received.Count > 0)
            {
                findings.Add(new WebSocketFuzzFinding
                {
                    Severity = "info",
                    Confidence = "tentative",
                    ConnectionId = conn.ConnectionId,
                    Url = conn.Url,
                    PayloadSet = "message-type-matrix",
                    Payload = msgType,
                    MessageSent = Truncate(body, 200),
                    Indicator = "ws-type-accepted",
                    Detail = $"Server responded to replayed type '{msgType}' ({received.Count} frame(s))."
                });
            }
        }

        return findings;
    }

    private static HashSet<string> DiscoverPrivilegedTypes(List<WebSocketFrame> frames)
    {
        var types = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var frame in frames.Where(f => f.Direction == "sent" && f.IsJson && f.JsonType != null))
        {
            var t = frame.JsonType!;
            if (t.Contains("admin", StringComparison.OrdinalIgnoreCase)
                || t.Contains("auth", StringComparison.OrdinalIgnoreCase)
                || t.Contains("subscribe", StringComparison.OrdinalIgnoreCase)
                || t.Contains("private", StringComparison.OrdinalIgnoreCase)
                || t.Contains("execute", StringComparison.OrdinalIgnoreCase))
                types.Add(t);
        }

        if (types.Count == 0)
        {
            foreach (var frame in frames.Where(f => f.Direction == "sent" && f.IsJson && f.JsonType != null))
                types.Add(frame.JsonType!);
        }

        return types;
    }

    private static string MutateJsonType(string original, string msgType)
    {
        try
        {
            using var doc = JsonDocument.Parse(original);
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.Name.Equals("type", StringComparison.OrdinalIgnoreCase)
                        || prop.Name.Equals("action", StringComparison.OrdinalIgnoreCase)
                        || prop.Name.Equals("event", StringComparison.OrdinalIgnoreCase))
                        writer.WriteString(prop.Name, msgType);
                    else if (prop.Value.ValueKind == JsonValueKind.String
                             && (prop.Name.Contains("content", StringComparison.OrdinalIgnoreCase)
                                 || prop.Name.Contains("message", StringComparison.OrdinalIgnoreCase)
                                 || prop.Name.Contains("data", StringComparison.OrdinalIgnoreCase)))
                        writer.WriteString(prop.Name, "<script>alert(1)</script>");
                    else
                        prop.WriteTo(writer);
                }
                writer.WriteEndObject();
            }
            return System.Text.Encoding.UTF8.GetString(stream.ToArray());
        }
        catch
        {
            return JsonSerializer.Serialize(new { type = msgType, data = "<script>alert(1)</script>" });
        }
    }

    private static List<(string Name, string[] Payloads)> ResolvePayloadSets(WebSocketFuzzOptions options)
    {
        var names = options.PayloadSets is { Count: > 0 }
            ? options.PayloadSets
            : ["xss-basic", "sqli-basic", "json-breaking"];

        var list = new List<(string, string[])>();
        foreach (var name in names)
        {
            var payloads = FuzzerPayloads.Resolve(name, options.PayloadProfile);
            if (payloads is { Length: > 0 })
                list.Add((name, payloads));
        }
        return list;
    }

    private static IEnumerable<string> BuildMessages(string payload, WebSocketFuzzOptions options, WebSocketConnection conn)
    {
        yield return payload;

        if (options.WrapJsonPayloads)
        {
            yield return JsonSerializer.Serialize(new { type = "message", data = payload });
            yield return JsonSerializer.Serialize(new { action = "send", content = payload });
            if (conn.Url.Contains("graphql", StringComparison.OrdinalIgnoreCase))
                yield return JsonSerializer.Serialize(new { type = "connection_init", payload = new { query = payload } });
        }
    }

    private void AnalyzeReceivedFrames(
        WebSocketConnection conn,
        string setName,
        string payload,
        string messageSent,
        List<WebSocketFrame> received,
        List<WebSocketFuzzFinding> findings)
    {
        if (received.Count == 0)
            return;

        foreach (var frame in received)
        {
            if (frame.Data.Contains(payload, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new WebSocketFuzzFinding
                {
                    Severity = setName.StartsWith("xss", StringComparison.OrdinalIgnoreCase) ? "high" : "medium",
                    Confidence = "likely",
                    ConnectionId = conn.ConnectionId,
                    Url = conn.Url,
                    PayloadSet = setName,
                    Payload = Truncate(payload, 120),
                    MessageSent = Truncate(messageSent, 200),
                    Indicator = "ws-payload-reflected",
                    Detail = "Sent payload reflected in received WebSocket frame.",
                    ReceivedSnippet = Truncate(frame.Data, 200)
                });
                return;
            }

            if (HtmlPattern.IsMatch(frame.Data))
            {
                findings.Add(new WebSocketFuzzFinding
                {
                    Severity = "high",
                    Confidence = "likely",
                    ConnectionId = conn.ConnectionId,
                    Url = conn.Url,
                    PayloadSet = setName,
                    Payload = Truncate(payload, 120),
                    MessageSent = Truncate(messageSent, 200),
                    Indicator = "ws-html-in-response",
                    Detail = "Received frame contains HTML/script tags after fuzz send.",
                    ReceivedSnippet = Truncate(frame.Data, 200)
                });
                return;
            }

            if (LooksLikeSqliError(frame.Data))
            {
                findings.Add(new WebSocketFuzzFinding
                {
                    Severity = "medium",
                    Confidence = "tentative",
                    ConnectionId = conn.ConnectionId,
                    Url = conn.Url,
                    PayloadSet = setName,
                    Payload = Truncate(payload, 120),
                    MessageSent = Truncate(messageSent, 200),
                    Indicator = "ws-sqli-indicator",
                    Detail = "Received frame contains SQL error patterns.",
                    ReceivedSnippet = Truncate(frame.Data, 200)
                });
                return;
            }
        }
    }

    private static bool LooksLikeSqliError(string text) =>
        text.Contains("SQL syntax", StringComparison.OrdinalIgnoreCase)
        || text.Contains("sqlite", StringComparison.OrdinalIgnoreCase)
        || text.Contains("ORA-", StringComparison.OrdinalIgnoreCase)
        || text.Contains("unclosed quotation", StringComparison.OrdinalIgnoreCase);

    private static WebSocketFuzzResult BuildResult(
        List<WebSocketFuzzFinding> findings, int connections, int payloadsSent, long elapsedMs)
    {
        var deduped = findings
            .GroupBy(f => $"{f.ConnectionId}|{f.Indicator}|{f.PayloadSet}|{f.Payload}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => SeverityRank(x.Severity)).First())
            .ToList();

        var message = deduped.Count == 0
            ? payloadsSent == 0
                ? "No WebSocket fuzz payloads sent."
                : $"No WebSocket injection indicators ({payloadsSent} payload(s) on {connections} connection(s))."
            : $"Found {deduped.Count} WebSocket fuzz indicator(s) ({payloadsSent} payload(s)).";

        return new WebSocketFuzzResult
        {
            Message = message,
            ConnectionsFuzzed = connections,
            PayloadsSent = payloadsSent,
            Findings = deduped,
            ElapsedMs = elapsedMs
        };
    }

    private static int SeverityRank(string s) => s switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    private async Task<bool> DetectWsExecOracleAsync(long rtMark, string canaryId)
    {
        var events = _ctx.ActiveTab.RuntimeEvents.SliceSinceMark(rtMark);
        if (events.Any(e =>
                e.Kind.Equals("oracle", StringComparison.OrdinalIgnoreCase)
                && e.Name.Equals("exec", StringComparison.OrdinalIgnoreCase)
                && (e.Data?.Contains(canaryId, StringComparison.OrdinalIgnoreCase) == true
                    || e.Data?.Contains(TraceInputPayloadPrep.ExecGlobal, StringComparison.OrdinalIgnoreCase) == true)))
            return true;

        if (events.Any(e =>
                e.Kind.Equals("sink", StringComparison.OrdinalIgnoreCase)
                && (e.Name.Equals("eval", StringComparison.OrdinalIgnoreCase)
                    || e.Name.Equals("Function", StringComparison.OrdinalIgnoreCase))
                && e.Data?.Contains(canaryId, StringComparison.OrdinalIgnoreCase) == true))
            return true;

        try
        {
            var proof = await _ctx.ExecuteJs(
                $"(function(){{ try {{ return window.{TraceInputPayloadPrep.ProofGlobal}===1 " +
                $"|| String(window.{TraceInputPayloadPrep.ExecGlobal}).includes({System.Text.Json.JsonSerializer.Serialize(canaryId)}); " +
                $"}} catch(e) {{ return false; }} }})()");
            if (proof.Trim().Equals("true", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        catch
        {
            /* best-effort */
        }

        return false;
    }

    private void AppendSinkReachFindings(
        WebSocketConnection conn,
        string setName,
        string payload,
        string message,
        long rtMark,
        List<WebSocketFuzzFinding> findings)
    {
        var sinks = _ctx.ActiveTab.RuntimeEvents.SliceSinceMark(rtMark)
            .Where(e => e.Kind.Equals("sink", StringComparison.OrdinalIgnoreCase)
                        && e.Name is "eval" or "Function" or "innerHTML" or "outerHTML")
            .ToList();
        if (sinks.Count == 0)
            return;

        findings.Add(new WebSocketFuzzFinding
        {
            Severity = "high",
            Confidence = "likely",
            ConnectionId = conn.ConnectionId,
            Url = conn.Url,
            PayloadSet = setName,
            Payload = Truncate(payload, 120),
            MessageSent = Truncate(message, 200),
            Indicator = "ws-message-to-sink",
            Detail = $"Inbound WebSocket traffic correlated with sink(s): {string.Join(", ", sinks.Select(s => s.Name).Distinct())}",
            ReceivedSnippet = Truncate(sinks[0].Data ?? "", 200)
        });
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";
}

public sealed class WebSocketFuzzOptions
{
    public int? ConnectionId { get; init; }
    public List<string>? PayloadSets { get; init; }
    public int MaxConnections { get; init; } = 3;
    public int MaxPayloadsPerSet { get; init; } = 8;
    public int MaxMessageTypes { get; init; } = 6;
    public int ResponseWaitMs { get; init; } = 500;
    public bool WrapJsonPayloads { get; init; } = true;
    public bool IncludeMessageTypeMatrix { get; init; } = true;
    public PayloadProfile PayloadProfile { get; init; } = PayloadProfile.Small;
}

public sealed class WebSocketFuzzResult
{
    public string Message { get; init; } = "";
    public string? SkippedReason { get; init; }
    public int ConnectionsFuzzed { get; init; }
    public int PayloadsSent { get; init; }
    public long ElapsedMs { get; init; }
    public List<WebSocketFuzzFinding> Findings { get; init; } = [];
}

public sealed class WebSocketFuzzFinding
{
    public string Severity { get; init; } = "medium";
    public string Confidence { get; init; } = "likely";
    public int ConnectionId { get; init; }
    public string Url { get; init; } = "";
    public string PayloadSet { get; init; } = "";
    public string Payload { get; init; } = "";
    public string MessageSent { get; init; } = "";
    public string Indicator { get; init; } = "";
    public string Detail { get; init; } = "";
    public string ReceivedSnippet { get; init; } = "";
}
