using System.Net.Http;
using System.Text.Json;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Security.Orchestration;

namespace Trowser.Security.Sse;

public static class SseActiveProbes
{
    public static async Task<List<SseAuditFinding>> RunAsync(
        AutomationContext ctx,
        SseManager manager,
        SseConnection target,
        SseAuditor.AuditOptions options,
        PeerRegistry? peers,
        CancellationToken ct = default)
    {
        var findings = new List<SseAuditFinding>();
        var checks = options.Checks;
        var runAll = checks.Contains("all");

        var isPost = target.Method.Equals("POST", StringComparison.OrdinalIgnoreCase);
        var minimum = isPost ? SafetyMode.Active : SafetyMode.Safe;
        var gate = SafetyGate.RequireAtLeast(options.SafetyMode, minimum,
            isPost
                ? "POST event-stream can trigger server-side work"
                : "SSE active subscribe");
        if (gate != null)
        {
            findings.Add(new SseAuditFinding
            {
                Check = "safety",
                Severity = "info",
                Title = "Active SSE checks skipped",
                Detail = gate.Value.Message
            });
            return findings;
        }

        var ownerSamples = manager.GetMessages(target.ConnectionId, last: 20)
            .Select(m => m.Data)
            .Where(d => d.Length > 0)
            .ToList();
        if (ownerSamples.Count == 0)
        {
            var body = ctx.Network.Entries
                .Where(e => e.IsEventStream && string.Equals(e.Url, target.Url, StringComparison.OrdinalIgnoreCase))
                .Select(e => e.ResponseBody)
                .FirstOrDefault(b => !string.IsNullOrEmpty(b));
            if (body != null)
            {
                ownerSamples = SseParser.Parse(body).Select(e => e.Data).Where(d => d.Length > 0).Take(20).ToList();
            }
        }

        if (runAll || checks.Contains("unauthenticated"))
            findings.AddRange(await UnauthenticatedSubscribeAsync(target, ownerSamples, options, ct));

        if (runAll || checks.Contains("cross-origin"))
        {
            var proof = await SseCrossOriginProver.TestAsync(ctx, new SseCrossOriginProver.ProofOptions
            {
                TargetUrl = target.Url,
                MonitorMs = options.MaxMsProbe
            }, ct);
            if (proof.Vulnerable)
            {
                findings.Add(new SseAuditFinding
                {
                    Check = "cross-origin",
                    Severity = proof.Severity,
                    Title = "Cross-origin EventSource received data",
                    Detail = proof.Detail,
                    Evidence = proof.EventSamples.FirstOrDefault(),
                    Url = target.Url,
                    ConnectionId = target.ConnectionId,
                    Remediation = "Restrict CORS and session binding on SSE endpoints."
                });
            }
        }

        if (runAll || checks.Contains("last-event-id"))
            findings.AddRange(await LastEventIdReplayAsync(ctx, target, ownerSamples, options, ct));

        if ((runAll || checks.Contains("peer")) && peers != null)
            findings.AddRange(await PeerSubscribeAsync(ctx, target, ownerSamples, peers, options, ct));

        return findings;
    }

    private static async Task<List<SseAuditFinding>> UnauthenticatedSubscribeAsync(
        SseConnection target,
        List<string> ownerSamples,
        SseAuditor.AuditOptions options,
        CancellationToken ct)
    {
        var findings = new List<SseAuditFinding>();
        if (ownerSamples.Count == 0)
        {
            findings.Add(new SseAuditFinding
            {
                Check = "unauthenticated",
                Severity = "info",
                Title = "Unauthenticated SSE check inconclusive",
                Detail = "No owner event payloads were captured to compare. Run the flow until at least one event is visible in GET /api/sse/messages.",
                Url = target.Url,
                ConnectionId = target.ConnectionId
            });
            return findings;
        }

        using var handler = new HttpClientHandler { UseCookies = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(options.MaxMsProbe + 2000) };
        var shapeHeaders = options.UseCapturedShapeHeaders ? BuildShapeHeaders(target) : null;
        var read = await SseStreamReader.ReadAsync(client, target.Url, shapeHeaders, options.MaxEventsProbe, options.MaxMsProbe, ct);

        if (read.StatusCode is 401 or 403)
        {
            findings.Add(new SseAuditFinding
            {
                Check = "unauthenticated",
                Severity = "info",
                Title = "Unauthenticated SSE subscribe rejected",
                Detail = $"Cookie-less GET returned HTTP {read.StatusCode}.",
                Url = target.Url,
                ConnectionId = target.ConnectionId
            });
            return findings;
        }

        if (read.StatusCode is >= 400 and < 500 && read.Events.Count == 0)
        {
            findings.Add(new SseAuditFinding
            {
                Check = "unauthenticated",
                Severity = "info",
                Title = "Unauthenticated SSE probe inconclusive (client error)",
                Detail = $"HTTP {read.StatusCode} with no event data. This may be request-shape validation (missing required headers), not proof of authentication. Compare with captured owner request headers or POST /api/fetch-direct.",
                Url = target.Url,
                ConnectionId = target.ConnectionId
            });
            return findings;
        }

        if (read.Error != null || read.Events.Count == 0)
            return findings;

        foreach (var ev in read.Events)
        {
            if (ownerSamples.Any(o => o.Length > 8 && ev.Data.Contains(o, StringComparison.Ordinal)))
            {
                findings.Add(new SseAuditFinding
                {
                    Check = "unauthenticated",
                    Severity = "high",
                    Title = "Unauthenticated SSE subscribe received owner-equivalent data",
                    Detail = "Cookie-less GET returned event data matching captured owner stream.",
                    Evidence = ev.Data.Length > 120 ? ev.Data[..120] + "..." : ev.Data,
                    Url = target.Url,
                    ConnectionId = target.ConnectionId,
                    Remediation = "Require authentication before streaming sensitive events."
                });
                break;
            }
        }

        return findings;
    }

    private static async Task<List<SseAuditFinding>> LastEventIdReplayAsync(
        AutomationContext ctx,
        SseConnection target,
        List<string> ownerSamples,
        SseAuditor.AuditOptions options,
        CancellationToken ct)
    {
        var findings = new List<SseAuditFinding>();
        if (ownerSamples.Count == 0)
            return findings;

        var messages = ctx.ActiveTab.Sse.GetMessages(target.ConnectionId, last: 50);
        var replayId = messages.Select(m => m.EventId).LastOrDefault(id => !string.IsNullOrEmpty(id));
        if (replayId == null)
            return findings;

        using var handler = new HttpClientHandler { UseCookies = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(options.MaxMsProbe + 2000) };
        var headers = new Dictionary<string, string> { ["Last-Event-ID"] = replayId };
        if (options.UseCapturedShapeHeaders)
        {
            foreach (var kv in BuildShapeHeaders(target) ?? [])
                headers.TryAdd(kv.Key, kv.Value);
        }

        var read = await SseStreamReader.ReadAsync(client, target.Url, headers, options.MaxEventsProbe, options.MaxMsProbe, ct);
        if (read.Events.Count == 0)
            return findings;

        var replayed = read.Events.Any(ev =>
            ownerSamples.Any(o => o.Length > 8 && ev.Data.Contains(o, StringComparison.Ordinal)));
        if (replayed)
        {
            findings.Add(new SseAuditFinding
            {
                Check = "last-event-id",
                Severity = "medium",
                Title = "Last-Event-ID replay returned prior event data without session",
                Detail = $"Replay with Last-Event-ID={replayId} returned data matching owner capture.",
                Url = target.Url,
                ConnectionId = target.ConnectionId,
                Remediation = "Bind stream offsets to authenticated sessions; do not replay cross-user history."
            });
        }

        return findings;
    }

    private static async Task<List<SseAuditFinding>> PeerSubscribeAsync(
        AutomationContext ctx,
        SseConnection target,
        List<string> ownerSamples,
        PeerRegistry peers,
        SseAuditor.AuditOptions options,
        CancellationToken ct)
    {
        var findings = new List<SseAuditFinding>();
        var peerNames = peers.GetAll().Select(p => p.Name).ToList();
        if (peerNames.Count == 0)
        {
            findings.Add(new SseAuditFinding
            {
                Check = "peer",
                Severity = "info",
                Title = "Peer SSE check inconclusive",
                Detail = "No peers registered. Open Peer Sessions for a second identity."
            });
            return findings;
        }

        if (ownerSamples.Count == 0)
        {
            findings.Add(new SseAuditFinding
            {
                Check = "peer",
                Severity = "info",
                Title = "Peer SSE check inconclusive",
                Detail = "No owner event payloads captured for comparison.",
                Url = target.Url
            });
            return findings;
        }

        var body = JsonSerializer.Serialize(new
        {
            url = target.Url,
            method = target.Method,
            timeout = options.MaxMsProbe
        });

        foreach (var name in peerNames.Take(2))
        {
            try
            {
                var resp = await peers.ForwardAsync(name, "POST", "/api/fetch-direct", body,
                    timeoutMs: options.MaxMsProbe + 10_000);
                if (resp.Body == null || !resp.Body.Contains("data:", StringComparison.Ordinal))
                    continue;
                var events = SseParser.Parse(resp.Body);
                if (events.Any(ev => ownerSamples.Any(o => o.Length > 8 && ev.Data.Contains(o, StringComparison.Ordinal))))
                {
                    findings.Add(new SseAuditFinding
                    {
                        Check = "peer",
                        Severity = "high",
                        Title = "Peer identity received owner-equivalent SSE payload",
                        Detail = $"Peer '{name}' fetch-direct returned SSE data matching owner stream.",
                        Url = target.Url,
                        Remediation = "Enforce per-user channel isolation on event streams."
                    });
                    break;
                }
            }
            catch
            {
                /* inconclusive */
            }
        }

        return findings;
    }

    private static Dictionary<string, string>? BuildShapeHeaders(SseConnection target)
    {
        if (target.RequestHeaders.Count == 0) return null;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in target.RequestHeaders)
        {
            if (!NetworkCaptureLimits.ShouldMergeCapturedRequestHeader(kv.Key)) continue;
            if (kv.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase)) continue;
            if (kv.Key.StartsWith("Sec-", StringComparison.OrdinalIgnoreCase)) continue;
            headers[kv.Key] = kv.Value;
        }

        return headers.Count == 0 ? null : headers;
    }
}
