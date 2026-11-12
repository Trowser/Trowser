using System.Text.Json;
using Microsoft.Web.WebView2.Core;

namespace Trowser.Automation;

/// <summary>
/// Per-tab registry of WebView2 frames (including cross-origin). Populated from
/// <see cref="CoreWebView2.FrameCreated"/> and reconciled with DOM / CDP frame trees.
/// </summary>
public sealed class FrameRegistry
{
    private readonly object _gate = new();
    private readonly List<FrameEntry> _entries = new();
    private int _nextId = 1;

    public sealed class FrameEntry
    {
        public string FrameId { get; init; } = "";
        public string Name { get; set; } = "";
        public string Url { get; set; } = "";
        public string? Origin { get; set; }
        public string? ParentFrameId { get; set; }
        public bool SameOrigin { get; set; }
        public bool CrossOrigin => !SameOrigin;
        public bool Inspectable { get; set; }
        public bool OutOfScope { get; set; }
        public WeakReference<CoreWebView2Frame>? FrameRef { get; set; }

        public CoreWebView2Frame? TryGetFrame()
        {
            if (FrameRef != null && FrameRef.TryGetTarget(out var f))
                return f;
            return null;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
            _nextId = 1;
        }
    }

    public FrameEntry Register(CoreWebView2Frame frame, string? parentFrameId = null)
    {
        lock (_gate)
        {
            foreach (var existing in _entries)
            {
                if (existing.TryGetFrame() == frame)
                {
                    UpdateFromFrame(existing, frame);
                    return existing;
                }
            }

            var id = "wv2-f" + _nextId++;
            var entry = new FrameEntry
            {
                FrameId = id,
                ParentFrameId = parentFrameId,
                FrameRef = new WeakReference<CoreWebView2Frame>(frame)
            };
            UpdateFromFrame(entry, frame);
            _entries.Add(entry);

            try
            {
                frame.NavigationStarting += (_, args) =>
                {
                    entry.Url = args.Uri ?? entry.Url;
                    entry.Origin = TryOrigin(entry.Url);
                };
                frame.NavigationCompleted += (_, _) => UpdateFromFrame(entry, frame);
                frame.Destroyed += (_, _) =>
                {
                    lock (_gate) _entries.Remove(entry);
                };
            }
            catch
            {
                /* some events may be unavailable */
            }

            return entry;
        }
    }

    public IReadOnlyList<FrameEntry> Snapshot()
    {
        lock (_gate)
        {
            PruneUnlocked();
            return _entries.Select(Clone).ToList();
        }
    }

    public FrameEntry? Find(string? frameSpec)
    {
        if (string.IsNullOrWhiteSpace(frameSpec)) return null;
        lock (_gate)
        {
            PruneUnlocked();
            foreach (var e in _entries)
            {
                if (e.FrameId.Equals(frameSpec, StringComparison.OrdinalIgnoreCase)
                    || (!string.IsNullOrEmpty(e.Name) && e.Name.Equals(frameSpec, StringComparison.OrdinalIgnoreCase)))
                    return e;
            }
            return null;
        }
    }

    public CoreWebView2Frame? ResolveCoreFrame(string? frameSpec) => Find(frameSpec)?.TryGetFrame();

    /// <summary>
    /// Merge DOM-based frame list with registry entries. DOM ids (f1, f2, …) are preferred when
    /// present; registry adds inspectable/origin for matching URLs/names and orphan wv2 frames.
    /// </summary>
    public List<Dictionary<string, object>> MergeWithDomFrames(
        IReadOnlyList<Dictionary<string, object>> domFrames,
        string? pageOrigin,
        Func<string?, bool>? isInScope = null)
    {
        var result = new List<Dictionary<string, object>>();
        var usedRegistryIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var registry = Snapshot();

        foreach (var dom in domFrames)
        {
            var frameId = GetStr(dom, "frameId");
            var name = GetStr(dom, "name");
            var url = GetStr(dom, "url");
            var sameOrigin = GetBool(dom, "sameOrigin");
            var parent = GetStr(dom, "parentFrameId");
            if (string.IsNullOrEmpty(parent)) parent = null;

            var match = MatchRegistry(registry, name, url, usedRegistryIds);
            var origin = match?.Origin ?? TryOrigin(url);
            var inspectable = match?.TryGetFrame() != null || sameOrigin;
            var outOfScope = origin != null && isInScope != null && !isInScope(origin);

            result.Add(new Dictionary<string, object>
            {
                ["frameId"] = !string.IsNullOrEmpty(frameId) ? frameId : (match?.FrameId ?? ""),
                ["name"] = name,
                ["url"] = url,
                ["origin"] = origin ?? "",
                ["sameOrigin"] = sameOrigin,
                ["crossOrigin"] = !sameOrigin,
                ["inspectable"] = inspectable && !outOfScope,
                ["outOfScope"] = outOfScope,
                ["parentFrameId"] = parent ?? "",
                ["registryId"] = match?.FrameId ?? ""
            });
            if (match != null) usedRegistryIds.Add(match.FrameId);
        }

        foreach (var reg in registry)
        {
            if (usedRegistryIds.Contains(reg.FrameId)) continue;
            var outOfScope = reg.Origin != null && isInScope != null && !isInScope(reg.Origin);
            result.Add(new Dictionary<string, object>
            {
                ["frameId"] = reg.FrameId,
                ["name"] = reg.Name,
                ["url"] = reg.Url,
                ["origin"] = reg.Origin ?? "",
                ["sameOrigin"] = reg.SameOrigin,
                ["crossOrigin"] = reg.CrossOrigin,
                ["inspectable"] = reg.TryGetFrame() != null && !outOfScope,
                ["outOfScope"] = outOfScope,
                ["parentFrameId"] = reg.ParentFrameId ?? "",
                ["registryId"] = reg.FrameId
            });
        }

        if (!string.IsNullOrEmpty(pageOrigin))
        {
            foreach (var row in result)
            {
                var origin = GetStr(row, "origin");
                if (string.IsNullOrEmpty(origin)) continue;
                var same = string.Equals(origin, pageOrigin, StringComparison.OrdinalIgnoreCase);
                row["sameOrigin"] = same;
                row["crossOrigin"] = !same;
            }
        }

        return result;
    }

    private static FrameEntry? MatchRegistry(
        IReadOnlyList<FrameEntry> registry, string name, string url, HashSet<string> used)
    {
        foreach (var e in registry)
        {
            if (used.Contains(e.FrameId)) continue;
            if (!string.IsNullOrEmpty(name) && name.Equals(e.Name, StringComparison.OrdinalIgnoreCase))
                return e;
        }
        foreach (var e in registry)
        {
            if (used.Contains(e.FrameId)) continue;
            if (!string.IsNullOrEmpty(url) && !string.IsNullOrEmpty(e.Url)
                && string.Equals(url, e.Url, StringComparison.OrdinalIgnoreCase))
                return e;
        }
        return null;
    }

    private void PruneUnlocked()
    {
        _entries.RemoveAll(e => e.TryGetFrame() == null);
    }

    private static FrameEntry Clone(FrameEntry e) => new()
    {
        FrameId = e.FrameId,
        Name = e.Name,
        Url = e.Url,
        Origin = e.Origin,
        ParentFrameId = e.ParentFrameId,
        SameOrigin = e.SameOrigin,
        Inspectable = e.Inspectable,
        OutOfScope = e.OutOfScope,
        FrameRef = e.FrameRef
    };

    private static void UpdateFromFrame(FrameEntry entry, CoreWebView2Frame frame)
    {
        try { entry.Name = frame.Name ?? entry.Name; }
        catch { /* ignore */ }

        try
        {
            var src = frame.GetType().GetProperty("Source")?.GetValue(frame) as string;
            if (!string.IsNullOrEmpty(src))
            {
                entry.Url = src;
                entry.Origin = TryOrigin(src);
            }
        }
        catch { /* ignore */ }

        entry.Inspectable = true;
    }

    internal static string? TryOrigin(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return uri.GetLeftPart(UriPartial.Authority);
        return null;
    }

    private static string GetStr(Dictionary<string, object> d, string key) =>
        d.TryGetValue(key, out var v) && v != null ? v.ToString() ?? "" : "";

    private static bool GetBool(Dictionary<string, object> d, string key)
    {
        if (!d.TryGetValue(key, out var v) || v == null) return false;
        if (v is bool b) return b;
        if (v is JsonElement je && (je.ValueKind is JsonValueKind.True or JsonValueKind.False))
            return je.GetBoolean();
        return bool.TryParse(v.ToString(), out var parsed) && parsed;
    }
}
