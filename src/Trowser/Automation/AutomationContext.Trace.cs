using System.Text.Json;

namespace Trowser.Automation;

public partial class AutomationContext
{
    #region Action Trace

    private readonly object _traceLock = new();
    private ActionTraceSession? _trace;

    /// <summary>Whether an action timeline is currently recording.</summary>
    public bool IsTracing
    {
        get { lock (_traceLock) return _trace is { Active: true }; }
    }

    /// <summary>
    /// Start recording automation actions into a ring buffer.
    /// Optional compact DOM snapshots are off by default (payload size).
    /// </summary>
    public object StartTrace(bool domSnapshots = false, int maxSteps = 200)
    {
        if (maxSteps < 1) maxSteps = 1;
        if (maxSteps > 5000) maxSteps = 5000;

        lock (_traceLock)
        {
            _trace = new ActionTraceSession
            {
                Active = true,
                DomSnapshots = domSnapshots,
                MaxSteps = maxSteps,
                StartedAt = DateTime.UtcNow
            };
        }

        return new { tracing = true, domSnapshots, maxSteps };
    }

    /// <summary>Stop recording. Steps remain available via <see cref="GetTrace"/> until cleared or restarted.</summary>
    public object StopTrace()
    {
        lock (_traceLock)
        {
            if (_trace == null)
                return new { tracing = false, steps = 0 };
            _trace.Active = false;
            _trace.StoppedAt = DateTime.UtcNow;
            return new { tracing = false, steps = _trace.Steps.Count, startedAt = _trace.StartedAt, stoppedAt = _trace.StoppedAt };
        }
    }

    /// <summary>Current trace buffer (empty list when never started).</summary>
    public object GetTrace()
    {
        lock (_traceLock)
        {
            if (_trace == null)
                return new { tracing = false, steps = Array.Empty<object>(), domSnapshots = new Dictionary<string, string>() };

            return new
            {
                tracing = _trace.Active,
                domSnapshots = _trace.DomSnapshots,
                maxSteps = _trace.MaxSteps,
                startedAt = _trace.StartedAt,
                stoppedAt = _trace.StoppedAt,
                steps = _trace.Steps.Select(s => s.ToApiObject()).ToList(),
                // Compact HTML blobs keyed by domSnapshotId (only when domSnapshots was enabled)
                domSnapshotData = _trace.DomBlobs.Count > 0 ? _trace.DomBlobs : null
            };
        }
    }

    /// <summary>Export the trace buffer as a JSON-serializable object (same shape as <see cref="GetTrace"/>).</summary>
    public object ExportTrace() => GetTrace();

    /// <summary>Clear the stored timeline (does not affect journal).</summary>
    public void ClearTrace()
    {
        lock (_traceLock)
            _trace = null;
    }

    /// <summary>Record one automation step when a trace is active.</summary>
    public void RecordTraceStep(string action, object? args = null, string? url = null, int? refGeneration = null,
        string? screenshotId = null, string? domSnapshotId = null, string? journalEntryId = null)
    {
        ActionTraceSession? session;
        lock (_traceLock)
            session = _trace is { Active: true } ? _trace : null;
        if (session == null) return;

        var step = new ActionTraceStep
        {
            T = DateTime.UtcNow,
            Action = action,
            Args = args,
            Url = url ?? "",
            RefGeneration = refGeneration ?? RefGeneration,
            ScreenshotId = screenshotId,
            DomSnapshotId = domSnapshotId,
            JournalEntryId = journalEntryId
        };

        lock (_traceLock)
        {
            if (_trace is not { Active: true }) return;
            _trace.Steps.Add(step);
            while (_trace.Steps.Count > _trace.MaxSteps)
                _trace.Steps.RemoveAt(0);
        }
    }

    /// <summary>
    /// Record a step; when the active trace has <c>domSnapshots: true</c>, capture a compact
    /// outerHTML snippet and attach its id to the step (also stored on the session for export).
    /// </summary>
    public async Task RecordTraceStepAsync(string action, object? args = null, string? url = null)
    {
        if (!IsTracing) return;

        string? domId = null;
        bool wantDom;
        lock (_traceLock)
            wantDom = _trace is { Active: true, DomSnapshots: true };

        if (wantDom)
        {
            try
            {
                var html = await RunJs(
                    "(function(){try{return (document.documentElement&&document.documentElement.outerHTML||'').substring(0,12000);}catch(e){return '';}})()");
                try
                {
                    if (html.Length >= 2 && html[0] == '"' && html[^1] == '"')
                        html = System.Text.Json.JsonSerializer.Deserialize<string>(html) ?? html;
                }
                catch { /* keep raw */ }

                if (!string.IsNullOrEmpty(html))
                {
                    domId = "dom_" + Guid.NewGuid().ToString("N")[..10];
                    lock (_traceLock)
                    {
                        if (_trace != null)
                            _trace.DomBlobs[domId] = html;
                    }
                }
            }
            catch (Exception ex)
            {
                TrowserLog.Warn($"trace DOM snapshot failed: {ex.Message}");
            }
        }

        string resolvedUrl = url ?? "";
        if (string.IsNullOrEmpty(resolvedUrl))
        {
            try { resolvedUrl = await GetCurrentUrl(); }
            catch { /* ignore */ }
        }

        RecordTraceStep(action, args, resolvedUrl, domSnapshotId: domId);
    }

    /// <summary>Last N steps as a compact summary (for assert/error attachment).</summary>
    public List<object> GetTraceSummary(int lastN = 10)
    {
        lock (_traceLock)
        {
            if (_trace == null || _trace.Steps.Count == 0)
                return new List<object>();
            return _trace.Steps
                .TakeLast(Math.Max(1, lastN))
                .Select(s => (object)new { t = s.T, action = s.Action, url = s.Url, refGeneration = s.RefGeneration })
                .ToList();
        }
    }

    #endregion

    #region HAR export

    /// <summary>
    /// Export the current tab's network log as HAR 1.2 JSON.
    /// Bodies are truncated to match the in-memory caps unless already absent.
    /// </summary>
    public object ExportHar(
        bool includeHeaders = true,
        bool includeBodies = true,
        string? urlContains = null,
        string? method = null,
        bool errorsOnly = false,
        bool pageOnly = false)
    {
        var entries = pageOnly ? Network.PageEntries : Network.Entries;
        IEnumerable<NetworkEntry> filtered = entries;

        if (errorsOnly)
            filtered = filtered.Where(e => e.IsError);
        if (!string.IsNullOrEmpty(urlContains))
            filtered = filtered.Where(e => e.Url.Contains(urlContains, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrEmpty(method))
            filtered = filtered.Where(e => e.Method.Equals(method, StringComparison.OrdinalIgnoreCase));

        var list = filtered.ToList();
        var harEntries = new List<object>();
        foreach (var e in list)
        {
            var started = e.Timestamp.ToUniversalTime().ToString("o");
            var time = e.DurationMs ?? 0;

            object ReqHeaders()
            {
                if (!includeHeaders) return Array.Empty<object>();
                return e.RequestHeaders.Select(h => new { name = h.Key, value = h.Value }).ToList();
            }

            object ResHeaders()
            {
                if (!includeHeaders) return Array.Empty<object>();
                return e.ResponseHeaders.Select(h => new { name = h.Key, value = h.Value }).ToList();
            }

            object? postData = null;
            if (includeBodies && !string.IsNullOrEmpty(e.RequestBody))
            {
                postData = new
                {
                    mimeType = e.RequestHeaders.TryGetValue("Content-Type", out var ct) ? ct
                        : e.RequestHeaders.TryGetValue("content-type", out var ct2) ? ct2 : "application/octet-stream",
                    text = e.RequestBody
                };
            }

            object content;
            if (includeBodies && e.ResponseBody != null)
            {
                var truncated = NetworkCaptureLimits.IsResponseBodyTruncated(e) == true;
                content = new
                {
                    size = e.ContentLengthBytes ?? e.ResponseBody.Length,
                    mimeType = string.IsNullOrEmpty(e.ContentType) ? "application/octet-stream" : e.ContentType,
                    text = e.ResponseBody,
                    _trowserCapturedChars = e.ResponseBody.Length,
                    _trowserBodyTruncated = truncated,
                    _trowserBodyCaptureLimitChars = NetworkCaptureLimits.MaxTextBodyChars
                };
            }
            else
            {
                content = new
                {
                    size = 0,
                    mimeType = string.IsNullOrEmpty(e.ContentType) ? "application/octet-stream" : e.ContentType,
                    text = ""
                };
            }

            harEntries.Add(new
            {
                startedDateTime = started,
                time,
                request = new
                {
                    method = e.Method,
                    url = e.Url,
                    httpVersion = "HTTP/1.1",
                    cookies = Array.Empty<object>(),
                    headers = ReqHeaders(),
                    queryString = Array.Empty<object>(),
                    postData,
                    headersSize = -1,
                    bodySize = e.RequestBody?.Length ?? 0
                },
                response = new
                {
                    status = e.StatusCode,
                    statusText = e.ReasonPhrase ?? "",
                    httpVersion = "HTTP/1.1",
                    cookies = Array.Empty<object>(),
                    headers = ResHeaders(),
                    content,
                    redirectURL = "",
                    headersSize = -1,
                    bodySize = e.ResponseBody?.Length ?? -1
                },
                cache = new { },
                timings = new
                {
                    send = 0,
                    wait = time,
                    receive = 0
                },
                _resourceType = e.ResourceType,
                _trowserGenerated = e.IsTrowserGenerated,
                _servedFromCache = e.ServedFromCache
            });
        }

        return new
        {
            log = new
            {
                version = "1.2",
                creator = new { name = "Trowser", version = App.Version },
                pages = new object[]
                {
                    new
                    {
                        startedDateTime = list.Count > 0
                            ? list[0].Timestamp.ToUniversalTime().ToString("o")
                            : DateTime.UtcNow.ToString("o"),
                        id = "page_1",
                        title = ActiveTab.Title ?? "",
                        pageTimings = new { onContentLoad = (double?)null, onLoad = (double?)null }
                    }
                },
                entries = harEntries
            }
        };
    }

    #endregion
}

internal sealed class ActionTraceSession
{
    public bool Active { get; set; }
    public bool DomSnapshots { get; set; }
    public int MaxSteps { get; set; } = 200;
    public DateTime StartedAt { get; set; }
    public DateTime? StoppedAt { get; set; }
    public List<ActionTraceStep> Steps { get; } = new();
    public Dictionary<string, string> DomBlobs { get; } = new(StringComparer.Ordinal);
}

internal sealed class ActionTraceStep
{
    public DateTime T { get; init; }
    public string Action { get; init; } = "";
    public object? Args { get; init; }
    public string Url { get; init; } = "";
    public int RefGeneration { get; init; }
    public string? ScreenshotId { get; init; }
    public string? DomSnapshotId { get; init; }
    public string? JournalEntryId { get; init; }

    public object ToApiObject() => new
    {
        t = T,
        action = Action,
        args = Args,
        url = Url,
        refGeneration = RefGeneration,
        screenshotId = ScreenshotId,
        domSnapshotId = DomSnapshotId,
        journalEntryId = JournalEntryId
    };
}
