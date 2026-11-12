using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Trowser.Automation;

namespace Trowser;

/// <summary>
/// Forwarding from the breakpoint dialog via <see cref="HttpClient"/> (not the browser stack).
/// Event streams use timed slice reads instead of a single full-body read.
/// </summary>
internal static class BreakpointForwardHttp
{
    public const int StandardTimeoutSeconds = 30;
    public const int StreamSliceMs = 8_000;
    public const int InitialStreamSliceMs = 5_000;

    private static readonly HashSet<string> SkipRequestHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Content-Length", "Transfer-Encoding", "Connection"
    };

    public static bool RequestLooksLikeEventStream(IReadOnlyDictionary<string, string> headers, string? resourceType)
    {
        if (!string.IsNullOrEmpty(resourceType)
            && resourceType.Contains("EventSource", StringComparison.OrdinalIgnoreCase))
            return true;

        if (headers.TryGetValue("Accept", out var accept)
            && accept.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    public static bool ResponseLooksLikeEventStream(HttpResponseMessage response)
    {
        var ct = response.Content.Headers.ContentType?.MediaType;
        return ct != null && ct.Contains("event-stream", StringComparison.OrdinalIgnoreCase);
    }

    public static HttpRequestMessage BuildRequest(
        string url,
        string method,
        IReadOnlyDictionary<string, string> headerDict,
        string? bodyText)
    {
        var request = new HttpRequestMessage(new HttpMethod(method.Trim()), url.Trim());

        string? contentType = null;
        foreach (var kv in headerDict)
        {
            if (SkipRequestHeaders.Contains(kv.Key)) continue;
            if (kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                contentType = kv.Value;
                continue;
            }
            request.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        }

        if (!string.IsNullOrEmpty(bodyText))
        {
            request.Content = new StringContent(bodyText, Encoding.UTF8);
            if (contentType != null)
            {
                try { request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType); }
                catch { /* keep default */ }
            }
        }

        return request;
    }

    public static HttpClientHandler CreateForwardHandler() => new()
    {
        AutomaticDecompression = DecompressionMethods.All,
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
        AllowAutoRedirect = false
    };

    public static Dictionary<string, string> CollectResponseHeaders(HttpResponseMessage response)
    {
        var responseHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in response.Headers)
            responseHeaders[h.Key] = string.Join(", ", h.Value);
        foreach (var h in response.Content.Headers)
            responseHeaders[h.Key] = string.Join(", ", h.Value);
        return responseHeaders;
    }

    public static async Task<BreakpointForwardStreamSession> OpenStreamSessionAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken = default)
    {
        var handler = CreateForwardHandler();
        var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return new BreakpointForwardStreamSession(client, handler, response, stream);
    }
}

/// <summary>Keeps an upstream event-stream open while the breakpoint dialog samples body text.</summary>
internal sealed class BreakpointForwardStreamSession : IAsyncDisposable
{
    private readonly HttpClient _client;
    private readonly HttpClientHandler _handler;
    private readonly StreamReader _reader;
    private readonly char[] _buffer = new char[8192];

    public HttpResponseMessage Response { get; }
    public bool StreamEnded { get; private set; }
    public bool HitCharCap { get; private set; }

    internal BreakpointForwardStreamSession(
        HttpClient client,
        HttpClientHandler handler,
        HttpResponseMessage response,
        Stream bodyStream)
    {
        _client = client;
        _handler = handler;
        Response = response;
        _reader = new StreamReader(bodyStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true,
            bufferSize: 8192, leaveOpen: false);
    }

    public int StatusCode => (int)Response.StatusCode;

    public Dictionary<string, string> ResponseHeaders =>
        BreakpointForwardHttp.CollectResponseHeaders(Response);

    public async Task<(int CharsRead, bool StreamEnded, bool HitCharCap)> ReadSliceAsync(
        StringBuilder into,
        int maxTotalChars,
        int sliceMs,
        CancellationToken cancellationToken = default)
    {
        if (StreamEnded || HitCharCap)
            return (0, StreamEnded, HitCharCap);

        var startLen = into.Length;
        using var sliceCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        sliceCts.CancelAfter(sliceMs);

        try
        {
            while (into.Length < maxTotalChars)
            {
                var toRead = Math.Min(_buffer.Length, maxTotalChars - into.Length);
                var read = await _reader.ReadAsync(_buffer.AsMemory(0, toRead), sliceCts.Token);
                if (read == 0)
                {
                    StreamEnded = true;
                    break;
                }

                into.Append(_buffer, 0, read);
            }
        }
        catch (OperationCanceledException) when (sliceCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            // Timed slice — keep partial data.
        }

        if (into.Length >= maxTotalChars)
        {
            HitCharCap = true;
            StreamEnded = true;
        }

        return (into.Length - startLen, StreamEnded, HitCharCap);
    }

    public async ValueTask DisposeAsync()
    {
        _reader.Dispose();
        Response.Dispose();
        _client.Dispose();
        _handler.Dispose();
        await ValueTask.CompletedTask;
    }
}
