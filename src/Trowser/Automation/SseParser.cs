namespace Trowser.Automation;

/// <summary>One parsed Server-Sent Events message (WHATWG event stream format).</summary>
public sealed class SseParsedEvent
{
    public string? EventId { get; init; }
    public string EventName { get; init; } = "message";
    public string Data { get; init; } = "";
    public int? RetryMs { get; init; }
}

/// <summary>Parse <c>text/event-stream</c> wire format into discrete events.</summary>
public static class SseParser
{
    /// <summary>Parse a full or partial SSE body into events.</summary>
    public static List<SseParsedEvent> Parse(string body)
    {
        var events = new List<SseParsedEvent>();
        if (string.IsNullOrEmpty(body))
            return events;

        string? eventName = null;
        var dataLines = new List<string>();
        string? eventId = null;
        int? retry = null;

        void Dispatch()
        {
            if (dataLines.Count == 0)
            {
                eventName = null;
                retry = null;
                return;
            }

            var data = string.Join("\n", dataLines);
            events.Add(new SseParsedEvent
            {
                EventId = eventId,
                EventName = eventName ?? "message",
                Data = data,
                RetryMs = retry
            });
            eventName = null;
            dataLines.Clear();
            retry = null;
        }

        foreach (var rawLine in body.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0)
            {
                Dispatch();
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
                    eventName = value;
                    break;
                case "data":
                    dataLines.Add(value);
                    break;
                case "id":
                    if (!value.Contains('\0'))
                        eventId = value;
                    break;
                case "retry":
                    if (int.TryParse(value, out var r) && r >= 0)
                        retry = r;
                    break;
            }
        }

        Dispatch();
        return events;
    }

    /// <summary>Collate <c>data:</c> payloads for LLM-style plain text (skips <c>[DONE]</c>).</summary>
    public static string ExtractDataText(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return "";
        var fromEvents = Parse(body);
        if (fromEvents.Count > 0)
        {
            var sb = new System.Text.StringBuilder();
            foreach (var ev in fromEvents)
            {
                foreach (var part in ev.Data.Split('\n'))
                {
                    var payload = part.Trim();
                    if (payload is "[DONE]" or "") continue;
                    sb.Append(payload);
                }
            }
            return sb.ToString().Trim();
        }

        return LegacyDataLinesOnly(body);
    }

    public static bool LooksLikeSse(string body) =>
        !string.IsNullOrWhiteSpace(body)
        && (body.Contains("\ndata:", StringComparison.Ordinal)
            || body.StartsWith("data:", StringComparison.OrdinalIgnoreCase)
            || body.Contains("\nevent:", StringComparison.Ordinal));

    private static string LegacyDataLinesOnly(string body)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var rawLine in body.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (!line.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                continue;
            var payload = line[5..].TrimStart();
            if (payload is "[DONE]" or "")
                continue;
            sb.Append(payload);
        }
        return sb.ToString().Trim();
    }
}
