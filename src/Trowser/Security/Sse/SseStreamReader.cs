using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using Trowser.Automation;

namespace Trowser.Security.Sse;

/// <summary>Read a bounded slice of an SSE HTTP response (probe traffic).</summary>
public static class SseStreamReader
{
    public sealed class ReadResult
    {
        public int StatusCode { get; init; }
        public List<SseParsedEvent> Events { get; init; } = [];
        public string RawPrefix { get; init; } = "";
        public bool TruncatedByCap { get; init; }
        public string? Error { get; init; }
    }

    public static async Task<ReadResult> ReadAsync(
        HttpClient client,
        string url,
        IReadOnlyDictionary<string, string>? extraHeaders,
        int maxEvents,
        int maxMs,
        CancellationToken ct = default)
    {
        maxEvents = Math.Clamp(maxEvents, 1, 500);
        maxMs = Math.Clamp(maxMs, 500, 120_000);

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        if (extraHeaders != null)
        {
            foreach (var (k, v) in extraHeaders)
            {
                if (k.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                req.Headers.TryAddWithoutValidation(k, v);
            }
        }

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(maxMs);
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            var status = (int)resp.StatusCode;
            await using var stream = await resp.Content.ReadAsStreamAsync(cts.Token);
            using var reader = new StreamReader(stream);

            var raw = new System.Text.StringBuilder();
            var events = new List<SseParsedEvent>();
            while (events.Count < maxEvents)
            {
                string? line;
                try
                {
                    line = await reader.ReadLineAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (line == null) break;
                raw.AppendLine(line);
                if (raw.Length > 65536) break;
            }

            events = SseParser.Parse(raw.ToString());
            if (events.Count > maxEvents)
                events = events.Take(maxEvents).ToList();

            return new ReadResult
            {
                StatusCode = status,
                Events = events,
                RawPrefix = raw.Length > 4096 ? raw.ToString()[..4096] : raw.ToString(),
                TruncatedByCap = events.Count >= maxEvents || raw.Length > 60000
            };
        }
        catch (Exception ex)
        {
            return new ReadResult { StatusCode = 0, Error = ex.Message };
        }
    }
}
