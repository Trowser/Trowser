namespace Trowser.Security.Runtime;

/// <summary>
/// Heuristic source→sink pairing for client-surface cells (not full taint).
/// </summary>
internal static class RuntimeEventCorrelation
{
    internal const int WindowMs = 2_000;

    /// <summary>
    /// untested | observed | correlated | confirmed — confirmed uses value-match/canary or lastSource lineage.
    /// </summary>
    internal static string ClassifyCell(string source, string sink, IReadOnlyList<RuntimeEvent> events)
    {
        var sinkEvents = events
            .Where(e => e.Kind.Equals("sink", StringComparison.OrdinalIgnoreCase)
                        && e.Name.Equals(sink, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (sinkEvents.Count == 0)
            return "untested";

        foreach (var sinkEvt in sinkEvents)
        {
            if (sinkEvt.Extra.TryGetValue("confidence", out var conf)
                && (conf is "canary" or "value-match")
                && sinkEvt.Extra.TryGetValue("matchedSources", out var ms)
                && !string.IsNullOrEmpty(ms)
                && SourceMatchesMatchedSources(source, ms))
                return "confirmed";
        }

        foreach (var sinkEvt in sinkEvents)
        {
            if (sinkEvt.Extra.TryGetValue("lastSource", out var ls)
                && !string.IsNullOrEmpty(ls)
                && SourceNameMatchesCell(source, ls))
                return "confirmed";
        }

        foreach (var sinkEvt in sinkEvents)
        {
            if (HasCorrelatedSource(source, sinkEvt, events))
                return "correlated";
        }

        return "observed";
    }

    private static bool SourceMatchesMatchedSources(string cellSource, string matchedSources)
    {
        foreach (var part in matchedSources.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var name = part.Split(':')[0];
            if (SourceNameMatchesCell(cellSource, name) || name.Equals("canary", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool SourceNameMatchesCell(string cellSource, string lastSourceName)
    {
        if (cellSource.Equals(lastSourceName, StringComparison.OrdinalIgnoreCase))
            return true;
        if (cellSource.Equals("postMessage", StringComparison.OrdinalIgnoreCase)
            && lastSourceName.Equals("postMessage", StringComparison.OrdinalIgnoreCase))
            return true;
        if (cellSource.Equals("storage", StringComparison.OrdinalIgnoreCase)
            && (lastSourceName.Contains("Storage", StringComparison.OrdinalIgnoreCase)
                || lastSourceName.Equals("indexedDB.get", StringComparison.OrdinalIgnoreCase)))
            return true;
        if (cellSource.Equals("url", StringComparison.OrdinalIgnoreCase)
            && lastSourceName is "document.referrer" or "history.state")
            return true;
        return false;
    }

    private static bool HasCorrelatedSource(string source, RuntimeEvent sinkEvt, IReadOnlyList<RuntimeEvent> events)
    {
        foreach (var evt in events)
        {
            if (!IsSourceForCell(source, evt))
                continue;
            if (evt.Timestamp > sinkEvt.Timestamp)
                continue;
            if ((sinkEvt.Timestamp - evt.Timestamp).TotalMilliseconds > WindowMs)
                continue;
            if (!string.IsNullOrEmpty(sinkEvt.FrameOrigin)
                && !string.IsNullOrEmpty(evt.FrameOrigin)
                && !sinkEvt.FrameOrigin.Equals(evt.FrameOrigin, StringComparison.OrdinalIgnoreCase))
                continue;
            return true;
        }

        return false;
    }

    private static bool IsSourceForCell(string source, RuntimeEvent evt)
    {
        if (source.Equals("postMessage", StringComparison.OrdinalIgnoreCase))
        {
            return evt.Kind.Equals("message", StringComparison.OrdinalIgnoreCase)
                   || (evt.Kind.Equals("listener", StringComparison.OrdinalIgnoreCase)
                       && evt.Name.Equals("message", StringComparison.OrdinalIgnoreCase));
        }

        if (source.Equals("url", StringComparison.OrdinalIgnoreCase))
        {
            return evt.Kind.Equals("source", StringComparison.OrdinalIgnoreCase)
                   && evt.Name is "document.referrer" or "history.state";
        }

        if (source.Equals("storage", StringComparison.OrdinalIgnoreCase))
        {
            return evt.Kind.Equals("source", StringComparison.OrdinalIgnoreCase)
                   && (evt.Name.Contains("Storage", StringComparison.OrdinalIgnoreCase)
                       || evt.Name.Equals("indexedDB.get", StringComparison.OrdinalIgnoreCase));
        }

        if (source.Equals("websocket-message", StringComparison.OrdinalIgnoreCase))
        {
            return evt.Kind.Equals("source", StringComparison.OrdinalIgnoreCase)
                   && evt.Name.Equals("websocket-message", StringComparison.OrdinalIgnoreCase);
        }

        return evt.Kind.Equals("source", StringComparison.OrdinalIgnoreCase)
               && evt.Name.Equals(source, StringComparison.OrdinalIgnoreCase);
    }
}
