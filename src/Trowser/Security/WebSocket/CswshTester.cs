using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Trowser.Security.WebSocket;

/// <summary>
/// Cross-Site WebSocket Hijacking (CSWSH) tester. Uses raw TCP connections to
/// craft WebSocket Upgrade requests with controlled Origin headers and victim cookies,
/// testing whether the server validates the Origin during handshake.
/// </summary>
public static class CswshTester
{
    public sealed class CswshResult
    {
        public string TargetUrl { get; init; } = "";
        public string TestedOrigin { get; init; } = "";
        public bool Vulnerable { get; init; }
        public string Severity { get; init; } = "info";
        public string Detail { get; init; } = "";
        public int HandshakeStatus { get; init; }
        public List<string> ReceivedMessages { get; init; } = [];
        public string? Evidence { get; init; }
        public int ElapsedMs { get; init; }
    }

    public sealed class CswshOptions
    {
        /// <summary>Target WebSocket URL (ws:// or wss://).</summary>
        public string TargetUrl { get; init; } = "";

        /// <summary>Attacker's origin to test with.</summary>
        public string AttackerOrigin { get; init; } = "https://evil.example.com";

        /// <summary>Victim's cookies to include in the handshake (simulating browser cookie jar).</summary>
        public Dictionary<string, string>? Cookies { get; init; }

        /// <summary>Sec-WebSocket-Protocol to request.</summary>
        public string? Protocol { get; init; }

        /// <summary>Message to send after successful connection (e.g., connection_init for graphql-ws).</summary>
        public string? SendAfterConnect { get; init; }

        /// <summary>How long to monitor for incoming messages after connecting (ms).</summary>
        public int MonitorMs { get; init; } = 5000;

        /// <summary>Connection timeout (ms).</summary>
        public int TimeoutMs { get; init; } = 10000;
    }

    /// <summary>
    /// Test for Cross-Site WebSocket Hijacking by attempting a WebSocket handshake
    /// from an attacker-controlled Origin with the victim's session cookies.
    /// </summary>
    public static async Task<CswshResult> TestAsync(CswshOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        try
        {
            var uri = new Uri(options.TargetUrl);
            var host = uri.Host;
            var port = uri.Port > 0 ? uri.Port : (uri.Scheme == "wss" ? 443 : 80);
            var isSecure = uri.Scheme.Equals("wss", StringComparison.OrdinalIgnoreCase);
            var path = uri.PathAndQuery;
            if (string.IsNullOrEmpty(path)) path = "/";

            // Build the WebSocket Upgrade request with attacker's Origin
            var wsKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            var request = new StringBuilder();
            request.AppendLine($"GET {path} HTTP/1.1");
            request.AppendLine($"Host: {host}");
            request.AppendLine("Upgrade: websocket");
            request.AppendLine("Connection: Upgrade");
            request.AppendLine($"Sec-WebSocket-Key: {wsKey}");
            request.AppendLine("Sec-WebSocket-Version: 13");
            request.AppendLine($"Origin: {options.AttackerOrigin}");

            if (options.Protocol != null)
                request.AppendLine($"Sec-WebSocket-Protocol: {options.Protocol}");

            if (options.Cookies?.Count > 0)
            {
                var cookieStr = string.Join("; ", options.Cookies.Select(kv => $"{kv.Key}={kv.Value}"));
                request.AppendLine($"Cookie: {cookieStr}");
            }

            request.AppendLine(); // Empty line to end headers

            // Open raw TCP connection
            using var tcp = new TcpClient();
            tcp.SendTimeout = options.TimeoutMs;
            tcp.ReceiveTimeout = options.TimeoutMs;

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(options.TimeoutMs);
            await tcp.ConnectAsync(host, port, connectCts.Token);

            Stream stream = tcp.GetStream();

            if (isSecure)
            {
                var sslStream = new SslStream(stream, false, (_, _, _, _) => true);
                await sslStream.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                                         System.Security.Authentication.SslProtocols.Tls13,
                }, connectCts.Token);
                stream = sslStream;
            }

            // Send the Upgrade request
            var requestBytes = Encoding.ASCII.GetBytes(request.ToString());
            await stream.WriteAsync(requestBytes, ct);
            await stream.FlushAsync(ct);

            // Read the handshake response
            var responseBuffer = new byte[8192];
            var responseText = new StringBuilder();
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(options.TimeoutMs);

            try
            {
                var bytesRead = await stream.ReadAsync(responseBuffer, readCts.Token);
                if (bytesRead > 0)
                    responseText.Append(Encoding.ASCII.GetString(responseBuffer, 0, bytesRead));
            }
            catch (OperationCanceledException)
            {
                return MakeResult(options, sw, 0, false,
                    "Connection timed out during handshake — server may have rejected or ignored the request.");
            }

            // Parse handshake status
            var statusLine = responseText.ToString().Split('\n').FirstOrDefault() ?? "";
            var status = ParseStatusCode(statusLine);

            if (status != 101)
            {
                return MakeResult(options, sw, status, false,
                    $"Server rejected WebSocket upgrade from attacker origin with HTTP {status}. Origin validation appears to be working.");
            }

            // Handshake succeeded from attacker origin — CSWSH is possible!
            var receivedMessages = new List<string>();

            // Send init message if provided
            if (options.SendAfterConnect != null)
            {
                var frame = BuildTextFrame(options.SendAfterConnect);
                await stream.WriteAsync(frame, ct);
                await stream.FlushAsync(ct);
            }

            // Monitor for incoming messages
            using var monitorCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            monitorCts.CancelAfter(options.MonitorMs);

            try
            {
                var frameBuffer = new byte[65536];
                while (true)
                {
                    var bytesRead = await stream.ReadAsync(frameBuffer, monitorCts.Token);
                    if (bytesRead == 0) break;

                    var msg = TryDecodeTextFrame(frameBuffer, bytesRead);
                    if (msg != null)
                        receivedMessages.Add(msg.Length > 500 ? msg[..500] + "..." : msg);

                    if (receivedMessages.Count >= 20) break; // cap for safety
                }
            }
            catch (OperationCanceledException) { /* expected — monitoring period ended */ }

            sw.Stop();

            var evidence = receivedMessages.Count > 0
                ? $"Received {receivedMessages.Count} message(s) from attacker origin. First: {receivedMessages[0]}"
                : "WebSocket upgrade accepted from attacker origin (status 101) but no application messages received during monitoring.";

            return new CswshResult
            {
                TargetUrl = options.TargetUrl,
                TestedOrigin = options.AttackerOrigin,
                Vulnerable = true,
                Severity = receivedMessages.Count > 0 ? "critical" : "high",
                Detail = $"Cross-Site WebSocket Hijacking confirmed. The server accepted a WebSocket handshake from origin '{options.AttackerOrigin}' " +
                         $"with the victim's session cookies. " +
                         (receivedMessages.Count > 0
                             ? $"The attacker received {receivedMessages.Count} application message(s), confirming data exfiltration is possible."
                             : "No application messages received during the monitoring window, but the connection was established."),
                HandshakeStatus = 101,
                ReceivedMessages = receivedMessages,
                Evidence = evidence,
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }
        catch (Exception ex)
        {
            sw.Stop();
            return MakeResult(options, sw, 0, false,
                $"Test failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Build a WebSocket text frame (opcode 1) from a string payload.
    /// Client frames must be masked per RFC 6455.
    /// </summary>
    private static byte[] BuildTextFrame(string text)
    {
        var payload = Encoding.UTF8.GetBytes(text);
        var frame = new List<byte>();

        // FIN + opcode 1 (text)
        frame.Add(0x81);

        // Mask bit set + payload length
        if (payload.Length < 126)
        {
            frame.Add((byte)(0x80 | payload.Length));
        }
        else if (payload.Length < 65536)
        {
            frame.Add(0xFE); // 0x80 | 126
            frame.Add((byte)(payload.Length >> 8));
            frame.Add((byte)(payload.Length & 0xFF));
        }
        else
        {
            frame.Add(0xFF); // 0x80 | 127
            for (var i = 7; i >= 0; i--)
                frame.Add((byte)((payload.Length >> (i * 8)) & 0xFF));
        }

        // Masking key
        var mask = RandomNumberGenerator.GetBytes(4);
        frame.AddRange(mask);

        // Masked payload
        for (var i = 0; i < payload.Length; i++)
            frame.Add((byte)(payload[i] ^ mask[i % 4]));

        return frame.ToArray();
    }

    /// <summary>
    /// Try to decode a text frame from raw bytes (simplified — handles basic cases).
    /// </summary>
    private static string? TryDecodeTextFrame(byte[] buffer, int length)
    {
        if (length < 2) return null;

        var opcode = buffer[0] & 0x0F;
        if (opcode != 1) return null; // only text frames

        var masked = (buffer[1] & 0x80) != 0;
        var payloadLen = buffer[1] & 0x7F;
        var offset = 2;

        if (payloadLen == 126)
        {
            if (length < 4) return null;
            payloadLen = (buffer[2] << 8) | buffer[3];
            offset = 4;
        }
        else if (payloadLen == 127)
        {
            offset = 10; // 8-byte extended length
            if (length < offset) return null;
            payloadLen = 0;
            for (var i = 2; i < 10; i++)
                payloadLen = (payloadLen << 8) | buffer[i];
        }

        byte[]? mask = null;
        if (masked)
        {
            if (length < offset + 4) return null;
            mask = new byte[4];
            Array.Copy(buffer, offset, mask, 0, 4);
            offset += 4;
        }

        if (length < offset + payloadLen) payloadLen = length - offset;
        if (payloadLen <= 0) return null;

        var payload = new byte[payloadLen];
        Array.Copy(buffer, offset, payload, 0, payloadLen);

        if (mask != null)
            for (var i = 0; i < payloadLen; i++)
                payload[i] ^= mask[i % 4];

        return Encoding.UTF8.GetString(payload);
    }

    private static int ParseStatusCode(string statusLine)
    {
        var parts = statusLine.Trim().Split(' ');
        if (parts.Length >= 2 && int.TryParse(parts[1], out var code))
            return code;
        return 0;
    }

    private static CswshResult MakeResult(CswshOptions options, Stopwatch sw, int status, bool vuln, string detail)
    {
        sw.Stop();
        return new CswshResult
        {
            TargetUrl = options.TargetUrl,
            TestedOrigin = options.AttackerOrigin,
            Vulnerable = vuln,
            Severity = vuln ? "critical" : "info",
            Detail = detail,
            HandshakeStatus = status,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }
}
