namespace Trowser.Pointers;

/// <summary>
/// A checkpoint is a timestamp that bounds "what has happened since we last synced". It is
/// what the <c>!?</c> handoff sends: everything after the most recent checkpoint (journal
/// GUI actions, console/network errors, pointers) forms the handoff payload. Checkpoints
/// also mark the start of a repro capture slice (P5). Ids are session-scoped so they can be
/// forwarded to peers later without collisions.
/// </summary>
public sealed class Checkpoint
{
    /// <summary>Session-scoped id (e.g. <c>a1b2c3-c1</c>).</summary>
    public string Id { get; set; } = "";

    /// <summary>Optional human label ("before checkout", "after login").</summary>
    public string? Label { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.Now;

    /// <summary>
    /// Journal index at the moment the checkpoint was taken. Everything with a greater index
    /// happened "since" this checkpoint — the bound used to build the handoff payload.
    /// </summary>
    public int JournalIndex { get; set; }

    /// <summary>Page URL at checkpoint time.</summary>
    public string? Url { get; set; }
}
