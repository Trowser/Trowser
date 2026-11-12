using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Security.Authz;
using Trowser.Security.Orchestration;

namespace Trowser.Security.WebSocket;

/// <summary>
/// Cross-identity WebSocket frame check. Sends one captured frame on a peer's already-open
/// socket and classifies the next frames with the same verdict words as Live Authz Shadow.
/// This is not an HTTP BOLA replay: a peer with no live socket is inconclusive.
/// </summary>
public static class WebSocketAuthz
{
    private static readonly HashSet<string> ReadLikeTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "ping", "pong", "heartbeat", "subscribe", "unsubscribe", "query", "get", "read",
        "list", "fetch", "connection_init", "connection_ack", "ka", "keepalive"
    };

    private static readonly Regex Email = new(
        @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        RegexOptions.Compiled);

    private static readonly Regex Jwt = new(
        @"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        RegexOptions.Compiled);

    private static readonly Regex ErrorFrame = new(
        @"unauthorized|forbidden|access denied|not allowed|""error""\s*:",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool IsWriteLike(string? message)
    {
        if (string.IsNullOrWhiteSpace(message)) return true;
        var type = ReadJsonType(message);
        if (type == null) return true;
        if (ReadLikeTypes.Contains(type)) return false;
        return true;
    }

    /// <summary>
    /// Classify a peer socket outcome. <paramref name="peerOutcome"/> is
    /// <c>frames</c>, <c>silence</c>, <c>closed</c>, <c>error-frame</c>, <c>no-socket</c>, or <c>send-failed</c>.
    /// </summary>
    public static AuthzVerdict Classify(
        string? ownerBody,
        string? peerBody,
        string peerOutcome,
        IReadOnlyList<string>? ownerTokens = null)
    {
        switch (peerOutcome)
        {
            case "no-socket":
                return Verdict(AuthzVerdictKind.Inconclusive, "low",
                    "Peer has no open socket for this URL. The peer must already be browsing with the socket open; cookies alone are not enough.");
            case "send-failed":
                return Verdict(AuthzVerdictKind.Inconclusive, "low",
                    "The frame was not sent on the peer socket.");
            case "closed":
                return Verdict(AuthzVerdictKind.ProperlyDenied, "medium",
                    "Peer socket closed after the frame. Treated as a denial, not as an HTTP status.");
            case "error-frame":
                return Verdict(AuthzVerdictKind.ProperlyDenied, "high",
                    "Peer socket returned an error frame (unauthorized, forbidden, or an error object).");
            case "silence":
                return Verdict(AuthzVerdictKind.ProperlyDenied, "low",
                    "No application frame came back and the socket stayed open. Silence is treated as a denial, not as proof the peer was limited to its own data.");
        }

        if (string.IsNullOrWhiteSpace(ownerBody))
        {
            return Verdict(AuthzVerdictKind.NeedsReview, "low",
                "Peer accepted the frame and sent data, but the owner capture has no following frame to compare.");
        }

        var evaluated = AuthzVerdictEvaluator.Evaluate(
            new Trowser.Security.DirectFetchHelper.DirectFetchResult { Status = 200, Body = ownerBody },
            new Trowser.Security.DirectFetchHelper.DirectFetchResult { Status = 200, Body = peerBody ?? "" },
            ownerTokens,
            null);

        if (evaluated.Kind == AuthzVerdictKind.ProperlyDenied)
            return evaluated;

        return evaluated;
    }

    public static IReadOnlyList<string> OwnerTokens(string? ownerBody, string? sentMessage)
    {
        if (string.IsNullOrWhiteSpace(ownerBody)) return [];
        var sent = sentMessage ?? "";
        var found = new List<string>();
        foreach (Match match in Email.Matches(ownerBody))
        {
            if (sent.Contains(match.Value, StringComparison.OrdinalIgnoreCase)) continue;
            if (!found.Contains(match.Value, StringComparer.OrdinalIgnoreCase))
                found.Add(match.Value);
        }

        foreach (Match match in Jwt.Matches(ownerBody))
        {
            if (sent.Contains(match.Value, StringComparison.Ordinal)) continue;
            if (!found.Contains(match.Value, StringComparer.Ordinal))
                found.Add(match.Value);
        }

        return found;
    }

    public static string? ReadJsonType(string message)
    {
        try
        {
            using var doc = JsonDocument.Parse(message);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            foreach (var name in new[] { "type", "action", "event", "op" })
            {
                if (doc.RootElement.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String)
                    return prop.GetString();
            }
        }
        catch
        {
            /* not JSON */
        }

        return null;
    }

    public static bool LooksLikeErrorFrame(string? data) =>
        !string.IsNullOrWhiteSpace(data) && ErrorFrame.IsMatch(data);

    private static AuthzVerdict Verdict(AuthzVerdictKind kind, string confidence, string reason) =>
        new() { Kind = kind, Confidence = confidence, Reason = reason };
}

public sealed class WebSocketAuthzTester
{
    private readonly AutomationContext _context;
    private readonly PeerRegistry _peers;

    public WebSocketAuthzTester(AutomationContext context, PeerRegistry peers)
    {
        _context = context;
        _peers = peers;
    }

    public async Task<WebSocketAuthzReport> RunAsync(WebSocketAuthzRequest request, CancellationToken ct = default)
    {
        var manager = _context.ActiveTab.WebSocket;
        var conn = manager.GetConnection(request.ConnectionId);
        if (conn == null)
        {
            return WebSocketAuthzReport.Failed(
                $"No WebSocket connection {request.ConnectionId}. Browse until the socket is open and check GET /api/websocket/connections.");
        }

        var message = request.Message;
        WebSocketFrame? sent = null;
        if (string.IsNullOrEmpty(message))
        {
            sent = SelectSentFrame(manager, conn.ConnectionId, request.FrameId);
            message = sent?.Data;
        }

        if (string.IsNullOrEmpty(message))
        {
            return WebSocketAuthzReport.Failed(
                "No sent text frame on this socket. Use the app so a frame is captured, or pass message.");
        }

        var minimum = WebSocketAuthz.IsWriteLike(message) ? SafetyMode.Active : SafetyMode.Safe;
        var gate = SafetyGate.RequireAtLeast(request.SafetyMode, minimum,
            minimum == SafetyMode.Active
                ? "This WebSocket frame looks like a write (not subscribe, query, or ping)"
                : "WebSocket authz sends a frame on the peer socket");
        if (gate != null)
            return WebSocketAuthzReport.Failed(gate.Value.Message);

        var peerNames = request.Peers is { Count: > 0 }
            ? request.Peers
            : _peers.GetAll().Select(p => p.Name).ToList();
        if (peerNames.Count == 0)
            return WebSocketAuthzReport.Failed("No peers registered. Open Peer Sessions and start a second identity first.");

        var ownerBody = OwnerObservation(manager, conn.ConnectionId, sent);
        var tokens = WebSocketAuthz.OwnerTokens(ownerBody, message);
        var wait = Math.Clamp(request.ResponseWaitMs <= 0 ? 800 : request.ResponseWaitMs, 200, 5000);
        var results = new List<WebSocketAuthzPeerResult>();

        foreach (var peerName in peerNames)
        {
            ct.ThrowIfCancellationRequested();
            results.Add(await ProbePeerAsync(peerName, conn.Url, message, ownerBody, tokens, wait, ct));
        }

        return new WebSocketAuthzReport
        {
            ConnectionId = conn.ConnectionId,
            Url = conn.Url,
            Message = Trim(message, 500),
            WriteLike = WebSocketAuthz.IsWriteLike(message),
            OwnerObservation = Trim(ownerBody, 500),
            Results = results
        };
    }

    private async Task<WebSocketAuthzPeerResult> ProbePeerAsync(
        string peerName,
        string ownerUrl,
        string message,
        string ownerBody,
        IReadOnlyList<string> tokens,
        int waitMs,
        CancellationToken ct)
    {
        var listed = await _peers.ForwardAsync(peerName, "GET", "/api/websocket/connections", timeoutMs: 15000);
        if (!listed.Success)
        {
            return Peer(peerName, WebSocketAuthz.Classify(ownerBody, null, "send-failed", tokens),
                peerError: listed.Body ?? "Peer connection list failed.");
        }

        var match = FindOpenSocket(listed.Body, ownerUrl);
        if (match == null)
        {
            return Peer(peerName, WebSocketAuthz.Classify(ownerBody, null, "no-socket", tokens));
        }

        var before = await ReadReceivedAsync(peerName, match.Value.ConnectionId);
        var sendBody = JsonSerializer.Serialize(new { connectionId = match.Value.ConnectionId, message });
        var sent = await _peers.ForwardAsync(peerName, "POST", "/api/websocket/send", sendBody, timeoutMs: 15000);
        if (!sent.Success)
        {
            return Peer(peerName, WebSocketAuthz.Classify(ownerBody, null, "send-failed", tokens),
                peerConnectionId: match.Value.ConnectionId,
                peerError: sent.Body ?? "Peer send failed.");
        }

        await Task.Delay(waitMs, ct);
        var after = await ReadReceivedAsync(peerName, match.Value.ConnectionId);
        var fresh = NewFrames(before, after);
        var stillOpen = await SocketStillOpenAsync(peerName, match.Value.ConnectionId, ownerUrl);

        string outcome;
        if (fresh.Any(WebSocketAuthz.LooksLikeErrorFrame))
            outcome = "error-frame";
        else if (fresh.Count > 0)
            outcome = "frames";
        else if (!stillOpen)
            outcome = "closed";
        else
            outcome = "silence";

        var peerBody = string.Join("\n", fresh);
        var verdict = WebSocketAuthz.Classify(ownerBody, peerBody, outcome, tokens);
        return Peer(peerName, verdict, peerConnectionId: match.Value.ConnectionId, peerBody: Trim(peerBody, 500), outcome: outcome);
    }

    private async Task<List<string>> ReadReceivedAsync(string peerName, int connectionId)
    {
        var path = $"/api/websocket/messages?connectionId={connectionId}&direction=received&limit=50";
        var resp = await _peers.ForwardAsync(peerName, "GET", path, timeoutMs: 15000);
        if (!resp.Success || string.IsNullOrWhiteSpace(resp.Body)) return [];
        return ReadFramePayloads(resp.Body);
    }

    private async Task<bool> SocketStillOpenAsync(string peerName, int connectionId, string ownerUrl)
    {
        var listed = await _peers.ForwardAsync(peerName, "GET", "/api/websocket/connections", timeoutMs: 15000);
        if (!listed.Success) return false;
        var match = FindOpenSocket(listed.Body, ownerUrl);
        return match?.ConnectionId == connectionId;
    }

    private static WebSocketFrame? SelectSentFrame(WebSocketManager manager, int connectionId, int? frameId)
    {
        var frames = manager.GetFrames(connectionId, directionFilter: "sent")
            .Where(f => f.DataType == "text" && !string.IsNullOrWhiteSpace(f.Data))
            .ToList();
        if (frameId is int id)
            return frames.FirstOrDefault(f => f.FrameId == id);
        return frames.Count == 0 ? null : frames[^1];
    }

    private static string OwnerObservation(WebSocketManager manager, int connectionId, WebSocketFrame? sent)
    {
        var received = manager.GetFrames(connectionId, directionFilter: "received")
            .Where(f => f.DataType == "text" && !string.IsNullOrWhiteSpace(f.Data));
        if (sent != null)
            received = received.Where(f => f.Timestamp >= sent.Timestamp && f.FrameId != sent.FrameId);
        var text = string.Join("\n", received.TakeLast(5).Select(f => f.Data));
        return text.Length > 4000 ? text[^4000..] : text;
    }

    private static (int ConnectionId, string Url)? FindOpenSocket(string? body, string ownerUrl)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("data", out var data)) return null;
            if (!data.TryGetProperty("connections", out var arr) || arr.ValueKind != JsonValueKind.Array)
                return null;

            var want = WebSocketAuditor.NormalizeConnectionUrl(ownerUrl);
            (int ConnectionId, string Url)? match = null;
            foreach (var el in arr.EnumerateArray())
            {
                var state = el.TryGetProperty("state", out var s) ? s.GetString() : null;
                if (!string.Equals(state, "open", StringComparison.OrdinalIgnoreCase)) continue;
                var url = el.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
                if (!string.Equals(WebSocketAuditor.NormalizeConnectionUrl(url), want, StringComparison.OrdinalIgnoreCase))
                    continue;
                var id = el.TryGetProperty("connectionId", out var idEl) ? idEl.GetInt32() : 0;
                if (id <= 0) continue;
                if (match == null || id > match.Value.ConnectionId)
                    match = (id, url);
            }

            return match;
        }
        catch
        {
            return null;
        }
    }

    private static List<string> ReadFramePayloads(string body)
    {
        var list = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("data", out var data)) return list;
            if (!data.TryGetProperty("frames", out var arr) || arr.ValueKind != JsonValueKind.Array)
                return list;
            foreach (var el in arr.EnumerateArray())
            {
                var dataText = el.TryGetProperty("data", out var d) ? d.GetString() : null;
                var stamp = el.TryGetProperty("timestamp", out var t) ? t.GetString() ?? "" : "";
                if (!string.IsNullOrEmpty(dataText))
                    list.Add(stamp + "\n" + dataText);
            }
        }
        catch
        {
            /* ignore */
        }

        return list;
    }

    private static List<string> NewFrames(List<string> before, List<string> after)
    {
        var seen = new HashSet<string>(before, StringComparer.Ordinal);
        return after.Where(f => seen.Add(f)).Select(StripStamp).ToList();
    }

    private static string StripStamp(string stamped)
    {
        var nl = stamped.IndexOf('\n');
        return nl >= 0 ? stamped[(nl + 1)..] : stamped;
    }

    private static WebSocketAuthzPeerResult Peer(
        string peer,
        AuthzVerdict verdict,
        int? peerConnectionId = null,
        string? peerBody = null,
        string? peerError = null,
        string? outcome = null) => new()
    {
        Peer = peer,
        Verdict = verdict.Kind.ToString(),
        Confidence = verdict.Confidence,
        Reason = verdict.Reason,
        PeerConnectionId = peerConnectionId,
        PeerFrames = peerBody,
        PeerError = peerError,
        Outcome = outcome
    };

    private static string Trim(string? text, int max)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= max) return text ?? "";
        return text[..max];
    }
}

public sealed class WebSocketAuthzRequest
{
    public int ConnectionId { get; init; }
    public int? FrameId { get; init; }
    public string? Message { get; init; }
    public List<string>? Peers { get; init; }
    public int ResponseWaitMs { get; init; } = 800;
    public SafetyMode SafetyMode { get; init; } = SafetyMode.Safe;
}

public static class WebSocketAuthzRecorder
{
    public static void Record(AutomationContext context, WebSocketAuthzReport report)
    {
        var shadow = context.LiveAuthzShadow;
        if (shadow == null || !report.Ok) return;

        var host = AuthzHostKey.Canonical(report.Url);
        var template = "/";
        if (Uri.TryCreate(report.Url, UriKind.Absolute, out var uri))
            template = Trowser.Security.AttackSurfaceMapper.TemplatizePath(uri.AbsolutePath);

        foreach (var peer in report.Results)
        {
            if (!Enum.TryParse<AuthzVerdictKind>(peer.Verdict, out var kind))
                kind = AuthzVerdictKind.Inconclusive;

            shadow.RecordSocketResult(new LiveAuthzShadowResult
            {
                Host = host,
                Method = "WS",
                Url = report.Url,
                UrlTemplate = template,
                Peer = peer.Peer,
                Verdict = kind,
                Confidence = peer.Confidence,
                Reason = peer.Reason,
                PeerError = peer.PeerError,
                NeedsClassification = kind is AuthzVerdictKind.BolaSuspected
                    or AuthzVerdictKind.ConfirmedLeak
                    or AuthzVerdictKind.SameShapeDifferentData
            });
        }
    }
}

public sealed class WebSocketAuthzReport
{
    public bool Ok { get; init; } = true;
    public string? Error { get; init; }
    public int ConnectionId { get; init; }
    public string Url { get; init; } = "";
    public string Message { get; init; } = "";
    public bool WriteLike { get; init; }
    public string OwnerObservation { get; init; } = "";
    public List<WebSocketAuthzPeerResult> Results { get; init; } = [];

    public static WebSocketAuthzReport Failed(string error) => new() { Ok = false, Error = error };
}

public sealed class WebSocketAuthzPeerResult
{
    public string Peer { get; init; } = "";
    public string Verdict { get; init; } = "";
    public string Confidence { get; init; } = "";
    public string Reason { get; init; } = "";
    public int? PeerConnectionId { get; init; }
    public string? PeerFrames { get; init; }
    public string? PeerError { get; init; }
    public string? Outcome { get; init; }
}
