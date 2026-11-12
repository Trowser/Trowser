namespace Trowser.Security.Runtime;

/// <summary>
/// One untrusted runtime observation from the in-page sensor.
/// Page JS can forge these — treat as evidence only; never trigger actions from them.
/// </summary>
public sealed class RuntimeEvent
{
    public long Id { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;

    /// <summary>sink | source | listener | message | gadget-read | proto-read</summary>
    public string Kind { get; init; } = "";

    /// <summary>Sink/source/listener name (e.g. innerHTML, localStorage.getItem, message).</summary>
    public string Name { get; init; } = "";

    /// <summary>Truncated argument / value / handler source.</summary>
    public string? Data { get; init; }

    /// <summary>Full stack string from the page (trimmed by the host).</summary>
    public string? Stack { get; init; }

    public string? FrameName { get; init; }
    public string? FrameOrigin { get; init; }

    /// <summary>Document URL at the time the event was captured (path and hash identify the page).</summary>
    public string? DocumentUrl { get; init; }

    /// <summary>Extra fields (attribute name, origin check hint, isTrusted, …).</summary>
    public Dictionary<string, string?> Extra { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>True for the runtime sensor's own capture-phase message probe (not app delivery proof).</summary>
    public bool IsSensorInternalMessage =>
        Kind.Equals("message", StringComparison.OrdinalIgnoreCase)
        && Extra.TryGetValue("sensor", out var s)
        && string.Equals(s, "true", StringComparison.OrdinalIgnoreCase);
}
