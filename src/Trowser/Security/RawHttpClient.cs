using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace Trowser.Security;

/// <summary>
/// HTTP/1.x raw send: assemble request-line + header block + body as bytes and write
/// them on a new TCP (or TLS) connection. Does not use <see cref="HttpClient"/>, so
/// Transfer-Encoding, Content-Length, duplicates, and the version token are under
/// caller control.
/// </summary>
internal static class RawHttpClient
{
    public const int DefaultTimeoutMs = 15000;
    public const int MaxResponseBytes = 128 * 1024;

    public sealed class BuildOptions
    {
        public bool NormalizeHeaders { get; init; } = true;
        public bool AddHostIfMissing { get; init; } = true;
    }

    public sealed class BuildResult
    {
        public required byte[] Bytes { get; init; }
        public required string RequestSent { get; init; }
        public bool HostWasAdded { get; init; }
    }

    public sealed class RawResult
    {
        public int Status { get; init; }
        public string StatusText { get; init; } = "";
        public List<string> Headers { get; init; } = [];
        /// <summary>Decoded response body (chunked framing removed when applicable).</summary>
        public string Body { get; init; } = "";
        /// <summary>Wire-format body after the header block (includes chunk sizes when chunked).</summary>
        public string? BodyRaw { get; init; }
        public bool BodyWasChunked { get; init; }
        public string RequestSent { get; set; } = "";
        public bool HostWasAdded { get; set; }
        public bool TimedOut { get; init; }
        public string? Error { get; init; }
        public long DurationMs { get; init; }
    }

    public static string DefaultRequestLine(string method, Uri target)
    {
        var verb = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim();
        var path = string.IsNullOrEmpty(target.PathAndQuery) ? "/" : target.PathAndQuery;
        return $"{verb} {path} HTTP/1.1";
    }

    public static bool HeaderBlockHasHost(string headerBlock)
    {
        if (string.IsNullOrEmpty(headerBlock)) return false;
        foreach (var rawLine in headerBlock.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            if (line[..colon].Trim().Equals("Host", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public static BuildResult BuildRequest(string requestLine, string? headerBlock, string? body, Uri target,
        BuildOptions? options = null)
    {
        options ??= new BuildOptions();
        var line = (requestLine ?? "").Trim();
        if (line.Length == 0)
            throw new ArgumentException("Request line is required.", nameof(requestLine));

        var hostAdded = false;
        var headers = headerBlock ?? "";

        if (options.AddHostIfMissing && !HeaderBlockHasHost(headers))
        {
            var hostLine = "Host: " + target.Authority;
            headers = string.IsNullOrWhiteSpace(headers)
                ? hostLine
                : hostLine + "\n" + headers.TrimStart('\r', '\n');
            hostAdded = true;
        }

        string headerText;
        if (options.NormalizeHeaders)
        {
            var parts = new List<string>();
            foreach (var rawLine in headers.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
            {
                var trimmedEnd = rawLine.TrimEnd();
                if (trimmedEnd.Length == 0 && parts.Count == 0)
                    continue;
                parts.Add(rawLine.TrimEnd('\r'));
            }
            while (parts.Count > 0 && parts[^1].Length == 0)
                parts.RemoveAt(parts.Count - 1);
            headerText = parts.Count == 0
                ? line + "\r\n\r\n"
                : line + "\r\n" + string.Join("\r\n", parts) + "\r\n\r\n";
        }
        else
        {
            var sep = headers.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
            var block = headers.TrimEnd('\r', '\n');
            headerText = string.IsNullOrEmpty(block)
                ? line + sep + sep
                : line + sep + block + sep + sep;
        }

        var headBytes = Encoding.UTF8.GetBytes(headerText);
        var bodyBytes = string.IsNullOrEmpty(body) ? [] : Encoding.UTF8.GetBytes(body);
        var bytes = new byte[headBytes.Length + bodyBytes.Length];
        Buffer.BlockCopy(headBytes, 0, bytes, 0, headBytes.Length);
        if (bodyBytes.Length > 0)
            Buffer.BlockCopy(bodyBytes, 0, bytes, headBytes.Length, bodyBytes.Length);

        return new BuildResult
        {
            Bytes = bytes,
            RequestSent = Encoding.UTF8.GetString(bytes),
            HostWasAdded = hostAdded
        };
    }

    public static async Task<RawResult> SendAsync(Uri target, string requestLine, string? headerBlock, string? body,
        int timeoutMs = DefaultTimeoutMs, BuildOptions? options = null, CancellationToken ct = default)
    {
        BuildResult built;
        try
        {
            built = BuildRequest(requestLine, headerBlock, body, target, options);
        }
        catch (Exception ex)
        {
            return new RawResult { Error = ex.Message };
        }

        var sent = await SendBytesAsync(target, built.Bytes, timeoutMs, ct);
        sent.RequestSent = built.RequestSent;
        sent.HostWasAdded = built.HostWasAdded;
        return sent;
    }

    public static async Task<RawResult> SendBytesAsync(Uri target, byte[] requestBytes, int timeoutMs,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var host = target.Host;
            var port = target.Port > 0 ? target.Port : (target.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80);
            var isHttps = target.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

            using var tcp = new TcpClient();
            tcp.SendTimeout = timeoutMs;
            tcp.ReceiveTimeout = timeoutMs;

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(timeoutMs);
            await tcp.ConnectAsync(host, port, connectCts.Token);

            Stream stream = tcp.GetStream();
            if (isHttps)
            {
                var sslStream = new SslStream(stream, false, (_, _, _, _) => true);
                await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                                          System.Security.Authentication.SslProtocols.Tls13,
                    ApplicationProtocols = [SslApplicationProtocol.Http11]
                }, connectCts.Token);
                stream = sslStream;
            }

            await stream.WriteAsync(requestBytes, ct);
            await stream.FlushAsync(ct);

            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(timeoutMs);

            var rawBytes = await ReadHttpMessageBytesAsync(stream, readCts.Token);
            sw.Stop();

            if (rawBytes.Length == 0)
            {
                return new RawResult
                {
                    TimedOut = readCts.IsCancellationRequested || ct.IsCancellationRequested,
                    DurationMs = sw.ElapsedMilliseconds
                };
            }

            return ParseRawResponse(rawBytes, sw.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            return new RawResult { TimedOut = true, DurationMs = sw.ElapsedMilliseconds };
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new RawResult { Error = ex.Message, DurationMs = sw.ElapsedMilliseconds };
        }
    }

    /// <summary>
    /// Read one HTTP response: headers, then Content-Length / chunked / until close.
    /// </summary>
    internal static async Task<byte[]> ReadHttpMessageBytesAsync(Stream stream, CancellationToken ct)
    {
        var ms = new MemoryStream();
        var buffer = new byte[8192];

        try
        {
            while (ms.Length < MaxResponseBytes)
            {
                int n = await stream.ReadAsync(buffer, ct);
                if (n == 0) break;
                ms.Write(buffer, 0, n);
                if (IndexOfHeaderEnd(ms) >= 0) break;
            }

            int headerEnd = IndexOfHeaderEnd(ms);
            if (headerEnd < 0)
                return ms.ToArray();

            int bodyStart = headerEnd + 4;
            var headerText = Encoding.ASCII.GetString(ms.GetBuffer(), 0, headerEnd);
            bool chunked = HeaderBlockHasChunked(headerText);
            long? contentLength = TryHeaderBlockContentLength(headerText);

            if (chunked)
            {
                while (ms.Length < MaxResponseBytes && !ChunkedBodyComplete(ms, bodyStart))
                {
                    int n = await stream.ReadAsync(buffer, ct);
                    if (n == 0) break;
                    ms.Write(buffer, 0, n);
                }
            }
            else if (contentLength is long cl && cl >= 0)
            {
                long need = bodyStart + cl;
                while (ms.Length < need && ms.Length < MaxResponseBytes)
                {
                    int n = await stream.ReadAsync(buffer, ct);
                    if (n == 0) break;
                    ms.Write(buffer, 0, n);
                }
            }
            else
            {
                while (ms.Length < MaxResponseBytes)
                {
                    int n = await stream.ReadAsync(buffer, ct);
                    if (n == 0) break;
                    ms.Write(buffer, 0, n);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Partial response — caller decides TimedOut vs parse.
        }

        return ms.ToArray();
    }

    private static int IndexOfHeaderEnd(MemoryStream ms)
    {
        var buf = ms.GetBuffer();
        int len = (int)ms.Length;
        for (int i = 0; i <= len - 4; i++)
        {
            if (buf[i] == (byte)'\r' && buf[i + 1] == (byte)'\n' &&
                buf[i + 2] == (byte)'\r' && buf[i + 3] == (byte)'\n')
                return i;
        }
        return -1;
    }

    private static bool HeaderBlockHasChunked(string headerBlock)
    {
        foreach (var line in headerBlock.Split("\r\n"))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            if (!line[..colon].Trim().Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                continue;
            return line[(colon + 1)..].Contains("chunked", StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    private static long? TryHeaderBlockContentLength(string headerBlock)
    {
        foreach (var line in headerBlock.Split("\r\n"))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            if (!line[..colon].Trim().Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                continue;
            var raw = line[(colon + 1)..].Trim();
            var comma = raw.IndexOf(',');
            if (comma >= 0)
                raw = raw[..comma].Trim();
            if (long.TryParse(raw, out var n) && n >= 0)
                return n;
        }
        return null;
    }

    private static bool ChunkedBodyComplete(MemoryStream ms, int bodyStart)
    {
        var buf = ms.GetBuffer();
        int len = (int)ms.Length;
        if (len - bodyStart < 5)
            return false;
        for (int i = Math.Max(bodyStart, len - 16); i <= len - 5; i++)
        {
            if (buf[i] == (byte)'0' && buf[i + 1] == (byte)'\r' && buf[i + 2] == (byte)'\n' &&
                buf[i + 3] == (byte)'\r' && buf[i + 4] == (byte)'\n')
                return true;
        }
        return false;
    }

    internal static RawResult ParseRawResponse(byte[] rawBytes, long durationMs)
    {
        var raw = Encoding.UTF8.GetString(rawBytes);
        if (string.IsNullOrEmpty(raw))
            return new RawResult { Error = "Empty response", DurationMs = durationMs };

        var headers = new List<string>();
        var statusCode = 0;
        var statusText = "";

        var headerEnd = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var headerSection = headerEnd >= 0 ? raw[..headerEnd] : raw;
        var body = headerEnd >= 0 ? raw[(headerEnd + 4)..] : "";

        var lines = headerSection.Split("\r\n");
        if (lines.Length > 0)
        {
            var statusLine = lines[0];
            var parts = statusLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && int.TryParse(parts[1], out var code))
                statusCode = code;
            if (parts.Length >= 3)
                statusText = parts[2];
            else if (parts.Length == 2)
                statusText = "";
        }

        for (int i = 1; i < lines.Length; i++)
        {
            if (lines[i].Length > 0)
                headers.Add(lines[i]);
        }

        var chunked = HeaderBlockHasChunked(headerSection);
        string? bodyRaw = null;
        if (chunked)
        {
            bodyRaw = body;
            body = DecodeChunkedBody(body);
        }

        return new RawResult
        {
            Status = statusCode,
            StatusText = statusText,
            Headers = headers,
            Body = body,
            BodyRaw = bodyRaw,
            BodyWasChunked = chunked,
            DurationMs = durationMs
        };
    }

    /// <summary>Decode an HTTP/1.1 chunked body (hex chunk sizes, optional extensions).</summary>
    internal static string DecodeChunkedBody(string chunkedBody)
    {
        if (string.IsNullOrEmpty(chunkedBody))
            return chunkedBody;

        var sb = new StringBuilder(chunkedBody.Length);
        var index = 0;
        while (index < chunkedBody.Length)
        {
            var lineEnd = chunkedBody.IndexOf('\n', index);
            if (lineEnd < 0)
                break;

            var sizeLine = chunkedBody[index..lineEnd].TrimEnd('\r');
            index = lineEnd + 1;

            var semi = sizeLine.IndexOf(';');
            if (semi >= 0)
                sizeLine = sizeLine[..semi].Trim();

            if (!int.TryParse(sizeLine, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var chunkSize))
                break;

            if (chunkSize == 0)
                break;

            if (index + chunkSize > chunkedBody.Length)
            {
                sb.Append(chunkedBody.AsSpan(index));
                break;
            }

            sb.Append(chunkedBody.AsSpan(index, chunkSize));
            index += chunkSize;

            if (index < chunkedBody.Length && chunkedBody[index] == '\r')
                index++;
            if (index < chunkedBody.Length && chunkedBody[index] == '\n')
                index++;
        }

        return sb.ToString();
    }
}
