using System.Collections.Concurrent;
using System.Text.Json;

namespace Trowser.Security.Runtime;

/// <summary>
/// Per-tab ring of runtime sensor events. Caps size and rate; events are untrusted evidence.
/// </summary>
public sealed class RuntimeEventLog
{
    public const int DefaultMaxEntries = 2_000;
    public const int DefaultMaxPerSecond = 200;

    private readonly object _gate = new();
    private readonly List<RuntimeEvent> _events = new();
    private long _nextId = 1;
    private long _markId;
    private DateTime _windowStart = DateTime.UtcNow;
    private int _windowCount;

    public int MaxEntries { get; set; } = DefaultMaxEntries;
    public int MaxPerSecond { get; set; } = DefaultMaxPerSecond;

    /// <summary>True when the sensor was installed for this tab (document-created or execute-js).</summary>
    public bool Installed { get; set; }

    /// <summary>Document-created script id when installed via AddScriptToExecuteOnDocumentCreated.</summary>
    public string? DocumentScriptId { get; set; }

    /// <summary>Document-created gadget-radar script so the next navigation is scanned before page scripts finish.</summary>
    public string? GadgetRadarScriptId { get; set; }

    public int Count
    {
        get { lock (_gate) return _events.Count; }
    }

    /// <summary>Capture a watermark; <see cref="SliceSinceMark"/> returns events after this point.</summary>
    public long Mark()
    {
        lock (_gate)
        {
            _markId = _nextId - 1;
            return _markId;
        }
    }

    public IReadOnlyList<RuntimeEvent> SliceSinceMark(long? mark = null)
    {
        lock (_gate)
        {
            var from = mark ?? _markId;
            return _events.Where(e => e.Id > from).ToList();
        }
    }

    public IReadOnlyList<RuntimeEvent> All()
    {
        lock (_gate) return _events.ToList();
    }

    public IReadOnlyList<RuntimeEvent> OfKind(string kind)
    {
        lock (_gate)
            return _events.Where(e => e.Kind.Equals(kind, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    public void Clear()
    {
        lock (_gate)
        {
            _events.Clear();
            _markId = _nextId - 1;
        }
    }

    /// <summary>Ingest a <c>__trowser_rt</c> web message root (or a batch under <c>events</c>).</summary>
    public void Ingest(JsonElement root, string? frameName = null, string? frameOrigin = null)
    {
        if (root.TryGetProperty("events", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var el in arr.EnumerateArray())
                TryAddOne(el, frameName, frameOrigin);
            return;
        }

        TryAddOne(root, frameName, frameOrigin);
    }

    private void TryAddOne(JsonElement el, string? frameName, string? frameOrigin)
    {
        if (el.ValueKind != JsonValueKind.Object) return;

        var kind = el.TryGetProperty("kind", out var k) ? k.GetString() ?? "" : "";
        var name = el.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(kind) || string.IsNullOrEmpty(name)) return;

        var data = el.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.String
            ? Truncate(d.GetString(), 500) : null;
        var stack = el.TryGetProperty("stack", out var st) && st.ValueKind == JsonValueKind.String
            ? Truncate(st.GetString(), 2_000) : null;

        var fn = frameName ?? (el.TryGetProperty("frameName", out var fnEl) ? fnEl.GetString() : null);
        var fo = frameOrigin ?? (el.TryGetProperty("frameOrigin", out var foEl) ? foEl.GetString() : null);
        var documentUrl = el.TryGetProperty("documentUrl", out var duEl) && duEl.ValueKind == JsonValueKind.String
            ? Truncate(duEl.GetString(), 300)
            : null;

        var extra = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (el.TryGetProperty("extra", out var ex) && ex.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in ex.EnumerateObject())
                extra[p.Name] = p.Value.ValueKind == JsonValueKind.String
                    ? Truncate(p.Value.GetString(), 300)
                    : Truncate(p.Value.GetRawText(), 300);
        }

        lock (_gate)
        {
            var now = DateTime.UtcNow;
            if ((now - _windowStart).TotalSeconds >= 1)
            {
                _windowStart = now;
                _windowCount = 0;
            }
            if (_windowCount >= MaxPerSecond)
                return;
            _windowCount++;

            // Dedupe consecutive identical sink+stack-top
            var stackTop = StackTop(stack);
            if (_events.Count > 0)
            {
                var last = _events[^1];
                if (last.Kind == kind && last.Name == name
                    && string.Equals(last.Data, data, StringComparison.Ordinal)
                    && string.Equals(StackTop(last.Stack), stackTop, StringComparison.Ordinal))
                    return;
            }

            var evt = new RuntimeEvent
            {
                Id = _nextId++,
                Timestamp = now,
                Kind = kind,
                Name = name,
                Data = data,
                Stack = stack,
                FrameName = fn,
                FrameOrigin = fo,
                DocumentUrl = documentUrl,
                Extra = extra
            };
            _events.Add(evt);
            while (_events.Count > MaxEntries)
                _events.RemoveAt(0);
        }
    }

    /// <summary>Also accept a polled sink-log entry (legacy poll path).</summary>
    public void AddPolledSink(string sink, string? data, string? stack)
    {
        lock (_gate)
        {
            _events.Add(new RuntimeEvent
            {
                Id = _nextId++,
                Kind = "sink",
                Name = sink,
                Data = Truncate(data, 500),
                Stack = Truncate(stack, 2_000)
            });
            while (_events.Count > MaxEntries)
                _events.RemoveAt(0);
        }
    }

    private static string? Truncate(string? s, int max)
    {
        if (s == null) return null;
        return s.Length <= max ? s : s[..max];
    }

    private static string? StackTop(string? stack)
    {
        if (string.IsNullOrEmpty(stack)) return null;
        var line = stack.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        return line;
    }
}
