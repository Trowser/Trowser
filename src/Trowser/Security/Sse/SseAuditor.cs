using Trowser.Automation;
using Trowser.Security.Orchestration;

namespace Trowser.Security.Sse;

public static class SseAuditor
{
    public sealed class AuditOptions
    {
        public int? ConnectionId { get; init; }
        public HashSet<string> Checks { get; init; } = ["all"];
        public int MaxEventsProbe { get; init; } = 50;
        public int MaxMsProbe { get; init; } = 5000;
        public SafetyMode SafetyMode { get; init; } = SafetyMode.Safe;

        /// <summary>Copy non-auth request headers from the owner stream for shape validation (excludes Cookie/Authorization).</summary>
        public bool UseCapturedShapeHeaders { get; init; } = true;
    }

    public static SseAuditResult AuditPassive(
        AutomationContext ctx,
        SseManager manager,
        AuditOptions? options = null)
    {
        options ??= new AuditOptions();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var checks = options.Checks;
        var runAll = checks.Contains("all");
        var findings = new List<SseAuditFinding>();

        foreach (var entry in ctx.Network.Entries.Where(e => e.IsEventStream))
            manager.OnNetworkEntryBodyUpdated(ctx.ActiveTab, entry.Id);

        var connections = options.ConnectionId > 0
            ? manager.GetConnections().Where(c => c.ConnectionId == options.ConnectionId).ToList()
            : manager.GetConnections();

        var networkStreamsTab = ctx.Network.Entries.Where(e => e.IsEventStream).ToList();
        var networkStreams = ScopeNetworkStreams(networkStreamsTab, connections, options.ConnectionId);
        var anyTruncated = networkStreams.Any(e => NetworkCaptureLimits.IsResponseBodyTruncated(e) == true);

        foreach (var conn in connections)
        {
            if (runAll || checks.Contains("cors-credentials"))
                findings.AddRange(CheckCorsCredentials(conn));

            if (runAll || checks.Contains("sensitive-data"))
            {
                var samples = manager.GetMessages(conn.ConnectionId, last: 200);
                findings.AddRange(CheckSensitiveData(conn, samples));
            }
        }

        foreach (var entry in networkStreams.Take(options.ConnectionId > 0 ? 5 : 20))
        {
            if ((runAll || checks.Contains("sensitive-data")) && !string.IsNullOrEmpty(entry.ResponseBody))
            {
                foreach (var ev in SseParser.Parse(entry.ResponseBody).Take(100))
                {
                    foreach (var hit in StreamSensitiveDataPatterns.ScanSample(ev.Data))
                    {
                        findings.Add(new SseAuditFinding
                        {
                            Check = "sensitive-data",
                            Severity = hit.Severity,
                            Title = $"Sensitive data in captured SSE body: {hit.Name}",
                            Detail = "Network log captured event-stream body contains a pattern match.",
                            Evidence = StreamSensitiveDataPatterns.MaskSensitive(hit.Match),
                            Url = entry.Url,
                            Remediation = "Do not stream secrets over unauthenticated or broad-audience SSE channels."
                        });
                        break;
                    }
                }
            }
        }

        var open = connections.Any(c => c.State == "open");
        var messagesInScope = connections.Sum(c => c.MessagesReceived);
        var wireBytes = connections.Sum(c => manager.GetWireBytes(c.CdpRequestId));
        var captureModes = connections.Select(c => manager.DescribeCaptureMode(c.CdpRequestId)).Distinct().ToList();
        var skipped = new List<SseSkippedCheck>();
        var requestedSensitive = runAll || checks.Contains("sensitive-data");
        var requestedSink = runAll || checks.Contains("event-data-sink");
        var hasBodySamples = messagesInScope > 0
            || networkStreams.Any(e => !string.IsNullOrEmpty(e.ResponseBody));
        var payloadVisible = messagesInScope > 0 || hasBodySamples;

        string verdict;
        if (connections.Count == 0 && networkStreamsTab.Count == 0)
        {
            verdict = "no_traffic";
            findings.Add(new SseAuditFinding
            {
                Check = "coverage",
                Severity = "info",
                Title = "No SSE traffic captured",
                Detail = "No text/event-stream requests or SSE connections on this tab. Browse or open streams before audit.",
            });
        }
        else if (!payloadVisible)
        {
            verdict = "incomplete";
            findings.Add(new SseAuditFinding
            {
                Check = "coverage",
                Severity = wireBytes > 0 ? "medium" : "medium",
                Title = "SSE payload capture incomplete",
                Detail = wireBytes > 0
                    ? $"Captured {wireBytes} wire bytes but parsed 0 events. Stream may use a non-standard framing or events arrived after audit."
                    : "Streams were seen at the HTTP layer but no event payloads were captured yet (open fetch() stream, or no data flushed). Checks that need event bodies did not run.",
            });
            if (requestedSensitive)
                skipped.Add(new SseSkippedCheck
                {
                    Check = "sensitive-data",
                    Reason = "No parsed SSE event payloads available."
                });
            if (requestedSink)
                skipped.Add(new SseSkippedCheck
                {
                    Check = "event-data-sink",
                    Reason = "Page handler scan still runs; event content was not available for correlation."
                });
        }
        else
        {
            verdict = "complete";
        }

        sw.Stop();
        return new SseAuditResult
        {
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            AuditVerdict = verdict,
            SkippedChecks = skipped,
            Findings = findings,
            Coverage = new SseAuditCoverage
            {
                ConnectionsCaptured = connections.Count,
                MessagesCaptured = messagesInScope,
                EventStreamNetworkRows = networkStreamsTab.Count,
                WireBytesCaptured = wireBytes,
                CaptureModes = captureModes,
                AnyStreamPossiblyOpen = open,
                AnyBodyTruncated = anyTruncated == true,
                Note = anyTruncated == true
                    ? "One or more network bodies hit the capture cap; earlier events may be missing."
                    : null
            },
            Connections = connections.Select(c => new SseConnectionAuditSummary
            {
                ConnectionId = c.ConnectionId,
                NetworkEntryId = c.NetworkEntryId,
                Url = c.Url,
                State = c.State,
                MessageCount = c.MessagesReceived,
                WireBytes = manager.GetWireBytes(c.CdpRequestId),
                CaptureMode = manager.DescribeCaptureMode(c.CdpRequestId)
            }).ToList()
        };
    }

    internal static List<NetworkEntry> ScopeNetworkStreams(
        List<NetworkEntry> tabStreams,
        List<SseConnection> connections,
        int? connectionId)
    {
        if (connectionId is not > 0)
            return tabStreams;

        if (connections.Count == 0)
            return [];

        var conn = connections[0];
        if (conn.NetworkEntryId is int nid)
            return tabStreams.Where(e => e.Id == nid).ToList();

        return tabStreams
            .Where(e => e.Url.Equals(conn.Url, StringComparison.OrdinalIgnoreCase)
                && e.Method.Equals(conn.Method, StringComparison.OrdinalIgnoreCase))
            .Take(1)
            .ToList();
    }

    private static List<SseAuditFinding> CheckCorsCredentials(SseConnection conn)
    {
        var findings = new List<SseAuditFinding>();
        if (!conn.ResponseHeaders.TryGetValue("Access-Control-Allow-Credentials", out var cred)
            || !cred.Trim().Equals("true", StringComparison.OrdinalIgnoreCase))
            return findings;

        conn.ResponseHeaders.TryGetValue("Access-Control-Allow-Origin", out var acao);
        if (string.IsNullOrEmpty(acao) || acao == "*")
        {
            findings.Add(new SseAuditFinding
            {
                Check = "cors-credentials",
                Severity = "medium",
                Title = "SSE response allows credentials with weak ACAO",
                Detail = "Access-Control-Allow-Credentials is true but Access-Control-Allow-Origin is missing or wildcard.",
                Evidence = acao,
                ConnectionId = conn.ConnectionId,
                Url = conn.Url,
                Remediation = "Use a specific ACAO origin when credentials are enabled; verify with cross-origin EventSource proof."
            });
            return findings;
        }

        if (acao != "*" && acao.Length > 1)
        {
            findings.Add(new SseAuditFinding
            {
                Check = "cors-credentials",
                Severity = "info",
                Title = "SSE CORS allows credentialed cross-origin reads",
                Detail = $"Access-Control-Allow-Origin is '{acao}' with credentials. Confirm only trusted origins may subscribe.",
                ConnectionId = conn.ConnectionId,
                Url = conn.Url,
                Remediation = "Run cross-origin check or restrict ACAO to required origins."
            });
        }

        return findings;
    }

    private static List<SseAuditFinding> CheckSensitiveData(SseConnection conn, List<SseMessage> messages)
    {
        var findings = new List<SseAuditFinding>();
        var seen = new HashSet<string>();
        foreach (var msg in messages.Take(500))
        {
            foreach (var hit in StreamSensitiveDataPatterns.ScanSample(msg.Data))
            {
                var key = $"{hit.Name}|{conn.ConnectionId}";
                if (!seen.Add(key)) continue;
                findings.Add(new SseAuditFinding
                {
                    Check = "sensitive-data",
                    Severity = hit.Severity,
                    Title = $"Sensitive data in SSE event: {hit.Name}",
                    Detail = $"Event '{msg.EventName}' data matches '{hit.Name}'.",
                    Evidence = StreamSensitiveDataPatterns.MaskSensitive(hit.Match),
                    ConnectionId = conn.ConnectionId,
                    Url = conn.Url,
                    Remediation = "Avoid streaming credentials, tokens, or PII over SSE."
                });
            }
        }

        return findings;
    }
}
