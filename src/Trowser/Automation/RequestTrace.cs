using System.Text;

namespace Trowser.Automation;

/// <summary>
/// A single outbound HTTP request issued during a traced operation (e.g. a security scan).
/// Captures enough to let a human see and verify exactly what was sent: the method, URL and
/// request payload, plus the response status and timing.
/// </summary>
public sealed class RequestTraceEntry
{
    /// <summary>1-based order in which the request was issued.</summary>
    public int Seq { get; init; }

    /// <summary>Milliseconds from the start of the trace to when this request completed.</summary>
    public long AtMs { get; init; }

    public string Method { get; init; } = "GET";
    public string Url { get; init; } = "";

    /// <summary>Request payload (body) as sent, truncated to the trace's body limit. Null for bodyless requests.</summary>
    public string? Body { get; init; }

    /// <summary>HTTP response status, or 0 when the request failed before a response was received.</summary>
    public int Status { get; init; }

    public long ElapsedMs { get; init; }

    /// <summary>Error message when the request threw (timeout, connection failure, etc.); null on success.</summary>
    public string? Error { get; init; }

    /// <summary>Which transport issued the request: "browser" (page fetch) or "httpclient" (server-side probe).</summary>
    public string Transport { get; init; } = "";
}

/// <summary>
/// Thread-safe collector of outbound HTTP requests for one logical operation. Created via
/// <see cref="AutomationContext.BeginRequestTrace"/> and surfaced to API callers that pass
/// <c>verbose: true</c>. Bounded by <see cref="MaxEntries"/> / <see cref="MaxBodyChars"/> so a
/// noisy scan can never blow up memory or the response payload.
/// </summary>
public sealed class RequestTrace
{
    private readonly object _lock = new();
    private readonly List<RequestTraceEntry> _entries = new();
    private readonly long _startTimestamp = System.Diagnostics.Stopwatch.GetTimestamp();
    private int _seq;
    private int _dropped;

    public int MaxEntries { get; }
    public int MaxBodyChars { get; }

    public RequestTrace(int maxEntries = 2000, int maxBodyChars = 4000)
    {
        MaxEntries = Math.Max(1, maxEntries);
        MaxBodyChars = Math.Max(0, maxBodyChars);
    }

    /// <summary>Record one completed (or failed) outbound request.</summary>
    public void Record(string method, string url, string? body, int status, long elapsedMs, string? error, string transport)
    {
        lock (_lock)
        {
            _seq++;
            if (_entries.Count >= MaxEntries)
            {
                _dropped++;
                return;
            }

            _entries.Add(new RequestTraceEntry
            {
                Seq = _seq,
                AtMs = (long)((System.Diagnostics.Stopwatch.GetTimestamp() - _startTimestamp) * 1000.0 / System.Diagnostics.Stopwatch.Frequency),
                Method = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant(),
                Url = url ?? "",
                Body = Truncate(body),
                Status = status,
                ElapsedMs = elapsedMs,
                Error = error,
                Transport = transport
            });
        }
    }

    /// <summary>Total requests issued, including any dropped past <see cref="MaxEntries"/>.</summary>
    public int Count
    {
        get { lock (_lock) return _seq; }
    }

    /// <summary>Number of requests omitted because <see cref="MaxEntries"/> was reached.</summary>
    public int Dropped
    {
        get { lock (_lock) return _dropped; }
    }

    /// <summary>Snapshot of captured requests (does not include dropped ones).</summary>
    public IReadOnlyList<RequestTraceEntry> Entries
    {
        get { lock (_lock) return _entries.ToArray(); }
    }

    private string? Truncate(string? body)
    {
        if (body == null) return null;
        if (MaxBodyChars == 0) return "";
        if (body.Length <= MaxBodyChars) return body;
        return body[..MaxBodyChars] + $"...(+{body.Length - MaxBodyChars} chars)";
    }
}

/// <summary>
/// Disposable scope that captures outbound requests on an <see cref="AutomationContext"/> until
/// disposed, restoring any previously-active trace. Use with <c>using</c>:
/// <code>using var scope = ctx.BeginRequestTrace(); await ctx.RunSsrfScan(...); var reqs = scope.Trace.Entries;</code>
/// </summary>
public sealed class RequestTraceScope : IDisposable
{
    private readonly AutomationContext _context;
    private readonly RequestTrace? _previous;
    private bool _disposed;

    public RequestTrace Trace { get; }

    internal RequestTraceScope(AutomationContext context, RequestTrace trace, RequestTrace? previous)
    {
        _context = context;
        Trace = trace;
        _previous = previous;
    }

    public IReadOnlyList<RequestTraceEntry> Entries => Trace.Entries;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _context.EndRequestTrace(_previous);
    }
}

/// <summary>Renders a request trace as a compact human-readable block (used in MCP text responses).</summary>
public static class RequestTraceFormatter
{
    public static string ToText(RequestTrace trace)
    {
        var entries = trace.Entries;
        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine($"--- Verbose request trace ({trace.Count} request(s) issued) ---");
        if (entries.Count == 0)
        {
            sb.AppendLine("  (no HTTP requests were issued by this operation)");
            return sb.ToString().TrimEnd();
        }

        foreach (var e in entries)
        {
            var statusPart = e.Error != null ? $"ERR {e.Error}" : e.Status.ToString();
            sb.AppendLine($"  [{e.Seq}] {e.Method} {e.Url} -> {statusPart} ({e.ElapsedMs}ms, {e.Transport})");
            if (!string.IsNullOrEmpty(e.Body))
                sb.AppendLine($"        payload: {e.Body}");
        }

        if (trace.Dropped > 0)
            sb.AppendLine($"  ...{trace.Dropped} further request(s) not shown (trace limit reached).");

        return sb.ToString().TrimEnd();
    }
}
