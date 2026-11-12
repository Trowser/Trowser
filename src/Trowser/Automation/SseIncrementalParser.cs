using System.Text;

namespace Trowser.Automation;

/// <summary>Stateful SSE parser for streaming wire chunks (fetch + EventSource).</summary>
public sealed class SseParseState
{
    internal string? PendingEventName;
    internal string? PendingEventId;
    internal int? PendingRetry;
    internal readonly List<string> DataLines = [];
    internal string LineRemainder = "";
    internal long WireBytes;
}

public static class SseIncrementalParser
{
    public static List<SseParsedEvent> Append(SseParseState state, ReadOnlySpan<char> chunk)
    {
        state.WireBytes += chunk.Length;
        if (chunk.Length == 0)
            return [];

        var text = state.LineRemainder + chunk.ToString();
        state.LineRemainder = "";

        if (text.Length > 0 && text[^1] is not '\n' and not '\r')
        {
            var lastNl = text.LastIndexOf('\n');
            if (lastNl >= 0)
            {
                state.LineRemainder = text[(lastNl + 1)..];
                text = text[..(lastNl + 1)];
            }
            else
            {
                state.LineRemainder = text;
                return [];
            }
        }

        var events = new List<SseParsedEvent>();
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0)
            {
                TryDispatch(state, events);
                continue;
            }

            if (line[0] == ':')
                continue;

            var colon = line.IndexOf(':');
            string field;
            string value;
            if (colon < 0)
            {
                field = line;
                value = "";
            }
            else
            {
                field = line[..colon];
                value = line[(colon + 1)..];
                if (value.Length > 0 && value[0] == ' ')
                    value = value[1..];
            }

            switch (field)
            {
                case "event":
                    state.PendingEventName = value;
                    break;
                case "data":
                    state.DataLines.Add(value);
                    break;
                case "id":
                    if (!value.Contains('\0'))
                        state.PendingEventId = value;
                    break;
                case "retry":
                    if (int.TryParse(value, out var r) && r >= 0)
                        state.PendingRetry = r;
                    break;
            }
        }

        return events;
    }

    public static List<SseParsedEvent> Flush(SseParseState state)
    {
        if (string.IsNullOrEmpty(state.LineRemainder))
        {
            var tail = new List<SseParsedEvent>();
            TryDispatch(state, tail);
            return tail;
        }

        return Append(state, state.LineRemainder + "\n");
    }

    private static void TryDispatch(SseParseState state, List<SseParsedEvent> events)
    {
        if (state.DataLines.Count == 0)
        {
            state.PendingEventName = null;
            state.PendingRetry = null;
            return;
        }

        events.Add(new SseParsedEvent
        {
            EventId = state.PendingEventId,
            EventName = state.PendingEventName ?? "message",
            Data = string.Join("\n", state.DataLines),
            RetryMs = state.PendingRetry
        });
        state.PendingEventName = null;
        state.DataLines.Clear();
        state.PendingRetry = null;
    }
}
