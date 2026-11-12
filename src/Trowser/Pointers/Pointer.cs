namespace Trowser.Pointers;

/// <summary>
/// A pointer is "this, here, at this moment, and why" — a symmetric primitive that either
/// a human (via the <c>!?</c> snip) or an agent (via <c>browser_point</c>) can create.
/// It renders as an overlay for the human and as JSON for the agent, and always keeps a
/// frozen visual crop so a reader still sees what was meant even when re-resolution fails.
/// </summary>
public sealed class Pointer
{
    /// <summary>Session-scoped id (e.g. <c>a1b2c3-p1</c>). Never reused within a session.</summary>
    public string Id { get; set; } = "";

    /// <summary>
    /// One of <see cref="PointerKinds"/>: element | region | range | absence | artifact.
    /// <c>absence</c> means "something should be here and isn't" — a location, not a thing.
    /// <c>artifact</c> means the pointer targets non-DOM chrome (script console, journal panel)
    /// and carries a crop + source label rather than a DOM anchor.
    /// </summary>
    public string Kind { get; set; } = PointerKinds.Element;

    /// <summary>How to re-find the target: locator, text, rect+scroll, ref+refGeneration.</summary>
    public PointerAnchors Anchors { get; set; } = new();

    /// <summary>Absolute path to the frozen crop image. Always captured when possible.</summary>
    public string? CropPath { get; set; }

    /// <summary>Human-readable "why" — what the author meant to convey.</summary>
    public string? Caption { get; set; }

    /// <summary>Who created it: <c>human</c> or <c>agent</c>.</summary>
    public string Author { get; set; } = PointerAuthors.Agent;

    /// <summary>Owning tab id, when known.</summary>
    public int? TabId { get; set; }

    /// <summary>Page URL at creation time.</summary>
    public string? Url { get; set; }

    /// <summary>The checkpoint this pointer belongs to (bounds "since we last synced").</summary>
    public string? CheckpointId { get; set; }

    /// <summary>
    /// <c>resolved</c> (anchor found live) | <c>stale</c> (not re-checked since a DOM change) |
    /// <c>unresolvable</c> (re-resolution failed — show the crop, never a confidently-wrong highlight).
    /// </summary>
    public string Status { get; set; } = PointerStatuses.Resolved;

    /// <summary>For non-DOM <c>artifact</c> pointers: a label for where it came from.</summary>
    public string? Source { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.Now;

    /// <summary>Journal entry index written when the pointer was created (-1 if none).</summary>
    public int JournalIndex { get; set; } = -1;
}

/// <summary>Where to re-find a pointer's target. Multiple anchors give resilience.</summary>
public sealed class PointerAnchors
{
    /// <summary>A durable locator expression, e.g. <c>ByTestId("submit")</c>.</summary>
    public string? Locator { get; set; }

    /// <summary>The locator strategy: testId | label | placeholder | role | text | selector.</summary>
    public string? LocatorKind { get; set; }

    /// <summary>CSS selector, when known.</summary>
    public string? Selector { get; set; }

    /// <summary>Visible text of the target, when known.</summary>
    public string? Text { get; set; }

    /// <summary>Bounding rect in CSS pixels plus the scroll offset it was captured at.</summary>
    public PointerRect? Rect { get; set; }

    /// <summary>Snapshot ref number, or -1 when not anchored to a ref.</summary>
    public int Ref { get; set; } = -1;

    /// <summary>The ref generation the <see cref="Ref"/> belongs to (refs go stale across generations).</summary>
    public int RefGeneration { get; set; } = -1;
}

/// <summary>A bounding rectangle in CSS pixels, with the page scroll offset at capture time.</summary>
public sealed class PointerRect
{
    public double X { get; set; }
    public double Y { get; set; }
    public double Width { get; set; }
    public double Height { get; set; }
    public double ScrollX { get; set; }
    public double ScrollY { get; set; }
}

/// <summary>Valid <see cref="Pointer.Kind"/> values.</summary>
public static class PointerKinds
{
    public const string Element = "element";
    public const string Region = "region";
    public const string Range = "range";
    public const string Absence = "absence";
    public const string Artifact = "artifact";

    public static readonly string[] All = [Element, Region, Range, Absence, Artifact];

    public static string Normalize(string? kind)
    {
        if (string.IsNullOrWhiteSpace(kind)) return Element;
        var k = kind.Trim().ToLowerInvariant();
        return Array.IndexOf(All, k) >= 0 ? k : Element;
    }

    public static bool IsKnown(string? kind) =>
        kind != null && Array.IndexOf(All, kind.Trim().ToLowerInvariant()) >= 0;
}

/// <summary>Valid <see cref="Pointer.Author"/> values.</summary>
public static class PointerAuthors
{
    public const string Human = "human";
    public const string Agent = "agent";

    public static string Normalize(string? author)
    {
        if (string.IsNullOrWhiteSpace(author)) return Agent;
        var a = author.Trim().ToLowerInvariant();
        return a == Human ? Human : Agent;
    }
}

/// <summary>Valid <see cref="Pointer.Status"/> values.</summary>
public static class PointerStatuses
{
    public const string Resolved = "resolved";
    public const string Stale = "stale";
    public const string Unresolvable = "unresolvable";

    public static readonly string[] All = [Resolved, Stale, Unresolvable];

    public static string Normalize(string? status)
    {
        if (string.IsNullOrWhiteSpace(status)) return Resolved;
        var s = status.Trim().ToLowerInvariant();
        return Array.IndexOf(All, s) >= 0 ? s : Resolved;
    }
}
