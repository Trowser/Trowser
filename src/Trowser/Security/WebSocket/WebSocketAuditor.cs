using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Security.WebSocket;

/// <summary>
/// Comprehensive security auditor for WebSocket connections. Analyzes handshake,
/// frame contents, and connection behavior for common WebSocket vulnerabilities.
/// </summary>
public static class WebSocketAuditor
{
    public sealed class AuditOptions
    {
        public int? ConnectionId { get; init; }
        public HashSet<string> Checks { get; init; } = ["all"];
    }

    public sealed class AuditResult
    {
        public int ConnectionId { get; init; }
        public string Url { get; init; } = "";
        public List<WebSocketAuditFinding> Findings { get; init; } = [];
        public Dictionary<string, List<string>>? MessageTypeDiscovery { get; init; }
        public int ElapsedMs { get; init; }
    }

    /// <summary>
    /// Run security checks on a WebSocket connection.
    /// </summary>
    public static AuditResult Audit(WebSocketConnection connection, WebSocketManager manager, AuditOptions? options = null)
    {
        options ??= new AuditOptions();
        var checks = options.Checks;
        var runAll = checks.Contains("all");
        var findings = new List<WebSocketAuditFinding>();
        var sw = System.Diagnostics.Stopwatch.StartNew();

        // Get frames for analysis
        var frames = manager.GetFrames(connection.ConnectionId);

        if (runAll || checks.Contains("origin"))
            findings.AddRange(CheckOrigin(connection));

        if (runAll || checks.Contains("auth"))
            findings.AddRange(CheckAuth(connection));

        if (runAll || checks.Contains("tls"))
            findings.AddRange(CheckTls(connection));

        if (runAll || checks.Contains("sensitive-data"))
            findings.AddRange(CheckSensitiveData(frames));

        if (runAll || checks.Contains("input-validation"))
            findings.AddRange(CheckInputPatterns(frames));

        if (runAll || checks.Contains("message-types"))
            findings.AddRange(CheckMessageTypes(frames));

        if (runAll || checks.Contains("message-trust") || checks.Contains("authz"))
            findings.AddRange(CheckClientAssertedPrivileges(frames));

        if (runAll || checks.Contains("message-handler"))
            findings.AddRange(CheckInboundExecutionSignals(frames));

        // Discover message types for reporting
        var typeDiscovery = DiscoverMessageTypes(frames);

        sw.Stop();
        return new AuditResult
        {
            ConnectionId = connection.ConnectionId,
            Url = connection.Url,
            Findings = findings,
            MessageTypeDiscovery = typeDiscovery,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    // ── Individual Checks ──

    private static List<WebSocketAuditFinding> CheckOrigin(WebSocketConnection conn)
    {
        var findings = new List<WebSocketAuditFinding>();

        // Check if Origin was validated (we can only infer from the handshake succeeding)
        if (conn.HandshakeStatus == 101 && string.IsNullOrEmpty(conn.Origin))
        {
            findings.Add(new WebSocketAuditFinding
            {
                Check = "origin",
                Severity = "medium",
                Title = "WebSocket Origin not observable",
                Detail = "Could not determine the Origin header from the handshake. Manual CSWSH testing recommended.",
                Remediation = "Use POST /api/security/cswsh-test to verify Origin validation."
            });
        }

        return findings;
    }

    private static List<WebSocketAuditFinding> CheckAuth(WebSocketConnection conn)
    {
        var findings = new List<WebSocketAuditFinding>();

        // Check what auth mechanism is used
        var hasCookie = conn.RequestHeaders.Any(h =>
            h.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(h.Value));
        var hasAuthHeader = conn.RequestHeaders.Any(h =>
            h.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase));
        var hasTokenInUrl = conn.Url.Contains("token=", StringComparison.OrdinalIgnoreCase) ||
                           conn.Url.Contains("access_token=", StringComparison.OrdinalIgnoreCase) ||
                           conn.Url.Contains("apiKey=", StringComparison.OrdinalIgnoreCase) ||
                           conn.Url.Contains("key=", StringComparison.OrdinalIgnoreCase);

        if (hasTokenInUrl)
        {
            findings.Add(new WebSocketAuditFinding
            {
                Check = "auth",
                Severity = "medium",
                Title = "Authentication token in WebSocket URL",
                Detail = "The WebSocket URL contains what appears to be an authentication token in a query parameter. " +
                         "URL parameters are logged in server access logs, browser history, and may be visible in referrer headers.",
                Evidence = MaskTokenInUrl(conn.Url),
                Remediation = "Send authentication tokens in the first WebSocket message or via cookies instead of URL parameters."
            });
        }

        if (!hasCookie && !hasAuthHeader && !hasTokenInUrl)
        {
            findings.Add(new WebSocketAuditFinding
            {
                Check = "auth",
                Severity = "medium",
                Title = "No observable authentication on WebSocket handshake",
                Detail = "The WebSocket upgrade request does not appear to carry any authentication " +
                         "(no cookies, no Authorization header, no token in URL). The connection may rely on " +
                         "message-level authentication or may be unauthenticated.",
                Remediation = "Verify that the WebSocket connection requires authentication. If auth is message-based, ensure the server rejects unauthenticated messages."
            });
        }

        return findings;
    }

    private static List<WebSocketAuditFinding> CheckTls(WebSocketConnection conn)
    {
        var findings = new List<WebSocketAuditFinding>();

        if (conn.Url.StartsWith("ws://", StringComparison.OrdinalIgnoreCase) &&
            !conn.Url.Contains("localhost", StringComparison.OrdinalIgnoreCase) &&
            !conn.Url.Contains("127.0.0.1"))
        {
            findings.Add(new WebSocketAuditFinding
            {
                Check = "tls",
                Severity = "high",
                Title = "Unencrypted WebSocket connection (ws://)",
                Detail = $"WebSocket connection to {conn.Url} uses unencrypted ws:// protocol. " +
                         "All frames are transmitted in cleartext, exposing data to network-level attackers.",
                Remediation = "Use wss:// (WebSocket Secure) for all production WebSocket connections."
            });
        }

        return findings;
    }

    private static List<WebSocketAuditFinding> CheckSensitiveData(List<WebSocketFrame> frames)
    {
        var findings = new List<WebSocketAuditFinding>();
        var sensitivePatterns = new (string Name, string Pattern, string Severity)[]
        {
            ("Email address", @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "medium"),
            ("JWT token", @"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.", "high"),
            ("API key pattern", @"(?:api[_-]?key|apikey|api_secret)[""'\s:=]+[A-Za-z0-9_\-]{16,}", "high"),
            ("Password field", @"""(?:password|passwd|pwd|secret|credential)"":\s*""[^""]+""", "critical"),
            ("Bearer token", @"Bearer\s+[A-Za-z0-9_\-\.]{20,}", "high"),
            ("Credit card pattern", @"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "critical"),
            ("SSN pattern", @"\b\d{3}-\d{2}-\d{4}\b", "critical"),
            ("Internal IP", @"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "low"),
        };

        // Sample frames (don't scan thousands)
        var sampled = frames.Where(f => f.DataType == "text").Take(500).ToList();
        var seen = new HashSet<string>();

        foreach (var (name, pattern, severity) in sensitivePatterns)
        {
            foreach (var frame in sampled)
            {
                if (Regex.IsMatch(frame.Data, pattern, RegexOptions.IgnoreCase))
                {
                    var key = $"{name}|{frame.Direction}";
                    if (seen.Add(key))
                    {
                        var match = Regex.Match(frame.Data, pattern, RegexOptions.IgnoreCase);
                        findings.Add(new WebSocketAuditFinding
                        {
                            Check = "sensitive-data",
                            Severity = severity,
                            Title = $"Sensitive data in WebSocket {frame.Direction} frame: {name}",
                            Detail = $"A {frame.Direction} WebSocket frame contains data matching the '{name}' pattern.",
                            Evidence = MaskSensitive(match.Value),
                            Remediation = $"Review whether {name} data needs to be transmitted over WebSocket. Consider encryption or tokenization."
                        });
                    }
                }
            }
        }

        return findings;
    }

    private static List<WebSocketAuditFinding> CheckInputPatterns(List<WebSocketFrame> frames)
    {
        var findings = new List<WebSocketAuditFinding>();

        // Look for reflected input: check if sent payloads appear in received frames
        var sentTexts = frames.Where(f => f.Direction == "sent" && f.DataType == "text")
            .Select(f => f.Data).Take(100).ToList();
        var receivedTexts = frames.Where(f => f.Direction == "received" && f.DataType == "text")
            .Select(f => f.Data).Take(500).ToList();

        // Check for HTML/script content in received frames (potential XSS vector)
        var htmlPattern = new Regex(@"<(?:script|img|svg|iframe|object|embed|link)\b", RegexOptions.IgnoreCase);
        foreach (var received in receivedTexts.Take(200))
        {
            if (htmlPattern.IsMatch(received))
            {
                findings.Add(new WebSocketAuditFinding
                {
                    Check = "input-validation",
                    Severity = "medium",
                    Title = "HTML/script content in WebSocket received frame",
                    Detail = "A received WebSocket frame contains HTML tags that could be used for XSS if rendered unsafely in the DOM.",
                    Evidence = received.Length > 200 ? received[..200] + "..." : received,
                    Remediation = "Ensure WebSocket message content is properly sanitized before DOM insertion. Use textContent instead of innerHTML."
                });
                break;
            }
        }

        return findings;
    }

    private static List<WebSocketAuditFinding> CheckClientAssertedPrivileges(List<WebSocketFrame> frames)
    {
        var findings = new List<WebSocketAuditFinding>();
        var roleInSent = new Regex(
            @"""role""\s*:\s*""(?<role>admin|administrator|root|superuser|moderator|staff|internal)""",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);
        var adminFlag = new Regex(
            @"""(?:isAdmin|admin|isSuperuser|privileged|isStaff)""\s*:\s*(?:true|1|""yes"")",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        foreach (var frame in frames.Where(f => f.Direction == "sent" && f.DataType == "text").Take(200))
        {
            if (roleInSent.IsMatch(frame.Data))
            {
                var role = roleInSent.Match(frame.Data).Groups["role"].Value;
                findings.Add(new WebSocketAuditFinding
                {
                    Check = "message-trust",
                    Severity = "high",
                    Title = "Client-asserted privileged WebSocket role",
                    Detail = $"A sent WebSocket frame assigns role '{role}'. If the server trusts client-supplied role/type " +
                             "fields without server-side session binding, this is a common authz bypass (BOLA/vertical escalation).",
                    Evidence = TruncateFrame(frame.Data),
                    Remediation = "Derive authorization from server-side session only. Ignore client role claims or validate them against stored identity. " +
                                  "Use POST /api/security/websocket-fuzz with includeMessageTypeMatrix and websocket-authz probes."
                });
                break;
            }

            if (adminFlag.IsMatch(frame.Data))
            {
                findings.Add(new WebSocketAuditFinding
                {
                    Check = "message-trust",
                    Severity = "high",
                    Title = "Client-asserted admin/privilege flag in WebSocket message",
                    Detail = "A sent WebSocket JSON frame sets an admin or privilege boolean/flag. Servers must not trust this without verification.",
                    Evidence = TruncateFrame(frame.Data),
                    Remediation = "Validate privileges server-side on every message handler. Fuzz with POST /api/security/websocket-fuzz."
                });
                break;
            }
        }

        return findings;
    }

    private static List<WebSocketAuditFinding> CheckInboundExecutionSignals(List<WebSocketFrame> frames)
    {
        var findings = new List<WebSocketAuditFinding>();
        var evalEcho = new Regex(@"\beval\s*\(\s*[^)]*(event\.data|message\.data|msg\.data|payload|data)\b",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);
        var sentSamples = frames.Where(f => f.Direction == "sent" && f.DataType == "text")
            .Select(f => f.Data)
            .Where(d => d.Length is >= 4 and <= 120)
            .Take(30)
            .ToList();

        foreach (var received in frames.Where(f => f.Direction == "received" && f.DataType == "text").Take(300))
        {
            if (evalEcho.IsMatch(received.Data))
            {
                findings.Add(new WebSocketAuditFinding
                {
                    Check = "message-handler",
                    Severity = "high",
                    Title = "WebSocket received frame suggests eval on message data",
                    Detail = "Received WebSocket text resembles executable code referencing inbound message data (eval(event.data) class). " +
                             "Passive frame capture cannot confirm execution — active ws-code-exec-oracle probes recommended.",
                    Evidence = TruncateFrame(received.Data),
                    Remediation = "Remove eval/Function on WebSocket payloads. Use POST /api/security/websocket-fuzz (ws-code-exec-oracle)."
                });
                break;
            }

            foreach (var sample in sentSamples)
            {
                if (received.Data.Contains(sample, StringComparison.Ordinal)
                    && (received.Data.Contains("eval", StringComparison.OrdinalIgnoreCase)
                        || received.Data.Contains("Function(", StringComparison.OrdinalIgnoreCase)))
                {
                    findings.Add(new WebSocketAuditFinding
                    {
                        Check = "message-handler",
                        Severity = "medium",
                        Title = "WebSocket frame echoes client input near dynamic execution",
                        Detail = "A received frame reflects prior client message content alongside eval/Function — possible code injection over the socket.",
                        Evidence = TruncateFrame(received.Data),
                        Remediation = "Never execute reflected WebSocket content. Run websocket-fuzz with ws-code-exec-oracle."
                    });
                    return findings;
                }
            }
        }

        return findings;
    }

    private static List<WebSocketAuditFinding> CheckMessageTypes(List<WebSocketFrame> frames)
    {
        var findings = new List<WebSocketAuditFinding>();
        var types = DiscoverMessageTypes(frames);
        if (types == null) return findings;

        // Flag if there are many message types (large attack surface)
        var allTypes = types.Values.SelectMany(v => v).Distinct().ToList();
        if (allTypes.Count > 15)
        {
            findings.Add(new WebSocketAuditFinding
            {
                Check = "message-types",
                Severity = "info",
                Title = $"Large WebSocket message type surface ({allTypes.Count} types)",
                Detail = $"The WebSocket connection uses {allTypes.Count} distinct message types: {string.Join(", ", allTypes.Take(20))}. " +
                         "Each message type is a potential attack vector for authorization bypass or injection.",
                Remediation = "Ensure server-side authorization checks on each message type. Limit the message types accepted per role."
            });
        }

        return findings;
    }

    // ── Helpers ──

    private static Dictionary<string, List<string>>? DiscoverMessageTypes(List<WebSocketFrame> frames)
    {
        var sent = new HashSet<string>();
        var received = new HashSet<string>();

        foreach (var frame in frames.Where(f => f.IsJson && f.JsonType != null))
        {
            if (frame.Direction == "sent")
                sent.Add(frame.JsonType!);
            else
                received.Add(frame.JsonType!);
        }

        if (sent.Count == 0 && received.Count == 0) return null;

        return new Dictionary<string, List<string>>
        {
            ["sent"] = sent.OrderBy(s => s).ToList(),
            ["received"] = received.OrderBy(s => s).ToList()
        };
    }

    private static string MaskTokenInUrl(string url)
    {
        return Regex.Replace(url, @"(token|access_token|apiKey|key)=([^&]{4})[^&]*",
            "$1=$2****", RegexOptions.IgnoreCase);
    }

    private static string MaskSensitive(string value)
    {
        if (value.Length <= 8) return "****";
        return value[..4] + new string('*', Math.Min(value.Length - 4, 20));
    }

    private static string TruncateFrame(string data) =>
        data.Length <= 240 ? data : data[..240] + "...";

    /// <summary>
    /// Normalize a WebSocket URL for deduplication — strips volatile query params like Socket.IO <c>sid</c>.
    /// </summary>
    public static string NormalizeConnectionUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;

        var queryParts = uri.Query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries);
        var filtered = queryParts
            .Where(p => !p.StartsWith("sid=", StringComparison.OrdinalIgnoreCase))
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var pathAndQuery = uri.AbsolutePath;
        if (filtered.Length > 0)
            pathAndQuery += "?" + string.Join("&", filtered);

        return $"{uri.Scheme}://{uri.Authority}{pathAndQuery}";
    }

    /// <summary>
    /// Deduplicate findings across connections by check/title and normalized URL pattern.
    /// </summary>
    public static List<AggregatedWebSocketAuditFinding> AggregateFindings(
        IEnumerable<(WebSocketAuditFinding Finding, string ConnectionUrl, int ConnectionId)> items)
    {
        var groups = new Dictionary<string, (WebSocketAuditFinding Finding, string NormalizedUrl, int Occurrences, List<string> SeenUrls, List<int> ConnectionIds)>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var (finding, connectionUrl, connectionId) in items)
        {
            var normalizedUrl = NormalizeConnectionUrl(connectionUrl);
            var key = $"{finding.Check}|{finding.Title}|{normalizedUrl}";

            if (!groups.TryGetValue(key, out var bucket))
            {
                bucket = (finding, normalizedUrl, 0, [], []);
                groups[key] = bucket;
            }

            bucket.Occurrences++;
            if (!bucket.SeenUrls.Contains(normalizedUrl, StringComparer.OrdinalIgnoreCase))
                bucket.SeenUrls.Add(normalizedUrl);
            if (!bucket.ConnectionIds.Contains(connectionId))
                bucket.ConnectionIds.Add(connectionId);
            groups[key] = bucket;
        }

        return groups.Values
            .Select(g => new AggregatedWebSocketAuditFinding
            {
                Check = g.Finding.Check,
                Severity = g.Finding.Severity,
                Title = g.Finding.Title,
                Detail = g.Finding.Detail,
                Evidence = g.Finding.Evidence,
                Remediation = g.Finding.Remediation,
                NormalizedUrl = g.NormalizedUrl,
                Occurrences = g.Occurrences,
                SeenConnectionUrls = g.SeenUrls,
                ConnectionIds = g.ConnectionIds
            })
            .OrderByDescending(f => f.Severity switch
            {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0
            })
            .ThenBy(f => f.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
