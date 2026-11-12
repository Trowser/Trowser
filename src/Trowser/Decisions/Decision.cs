namespace Trowser.Decisions;

/// <summary>
/// A decision is the agent asking the human to make a call: a question, 2–6 options, and a
/// recommendation. The <see cref="Lane"/> says whether the agent can proceed without an answer,
/// so an ask never silently stalls a run. Answered decisions — and defaults that fired because
/// nobody answered — are journalled, which is what makes the record accountable after the fact.
/// </summary>
public sealed class Decision
{
    /// <summary>Session-scoped id (e.g. <c>a1b2c3-d1</c>). Never reused within a session.</summary>
    public string Id { get; set; } = "";

    /// <summary>What the agent needs decided, in the human's terms.</summary>
    public string Question { get; set; } = "";

    /// <summary>2–6 answers, keyed A, B, C, … in the order supplied.</summary>
    public List<DecisionOption> Options { get; set; } = new();

    /// <summary>
    /// One of <see cref="DecisionLanes"/>: <c>gate</c> (agent blocks until answered or the timeout
    /// fires), <c>steer</c> (agent proceeds on the default and picks the answer up later), or
    /// <c>review</c> (never blocks — a record for the human, not a request).
    /// </summary>
    public string Lane { get; set; } = DecisionLanes.Steer;

    /// <summary>One of <see cref="DecisionUrgencies"/>. High urgency flashes the taskbar harder.</summary>
    public string Urgency { get; set; } = DecisionUrgencies.Normal;

    /// <summary>Option key the agent recommends, shown to the human as the suggested answer.</summary>
    public string? Recommendation { get; set; }

    /// <summary>Option key applied when nobody answers in time (and immediately, in the steer lane).</summary>
    public string? DefaultKey { get; set; }

    /// <summary>How long the question stays open before <see cref="DefaultKey"/> fires.</summary>
    public int TimeoutMs { get; set; } = DecisionDefaults.TimeoutMs;

    /// <summary>Pointers that give the question its "this, here" — rendered alongside the options.</summary>
    public List<string>? PointerIds { get; set; }

    /// <summary>Page URL when the question was asked.</summary>
    public string? Url { get; set; }

    /// <summary>The checkpoint this question belongs to.</summary>
    public string? CheckpointId { get; set; }

    /// <summary>One of <see cref="DecisionStatuses"/>.</summary>
    public string Status { get; set; } = DecisionStatuses.Pending;

    /// <summary>Chosen option key, once resolved.</summary>
    public string? AnswerKey { get; set; }

    /// <summary>Chosen option label, once resolved (denormalised so the journal reads on its own).</summary>
    public string? AnswerLabel { get; set; }

    /// <summary>One of <see cref="DecisionAnswerers"/>: who or what produced the answer.</summary>
    public string? AnsweredBy { get; set; }

    /// <summary>Free-text the human added when answering, or the reason the agent withdrew the question.</summary>
    public string? AnswerNote { get; set; }

    /// <summary>When true, the card shows a lettered Other option so the tester can type a custom answer.</summary>
    public bool AllowOther { get; set; }

    /// <summary>
    /// The letter assigned to Other (the next key after the listed options). Set when
    /// <see cref="AllowOther"/> is true — e.g. options A,B,C → Other is D.
    /// </summary>
    public string? OtherKey { get; set; }

    /// <summary>
    /// Steer lane only: milliseconds to hold the tool response, preferring a fast human answer
    /// before returning the provisional default. Zero means return immediately (classic steer).
    /// </summary>
    public int GraceMs { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.Now;

    /// <summary>When the default fires. Set by the store from <see cref="TimeoutMs"/>.</summary>
    public DateTime ExpiresAt { get; set; }

    public DateTime? ResolvedAt { get; set; }

    /// <summary>Journal entry index written when the question was asked (-1 if none).</summary>
    public int JournalIndex { get; set; } = -1;

    /// <summary>Look up a listed option by key. Does not match the Other letter.</summary>
    public DecisionOption? FindOption(string? key) =>
        string.IsNullOrWhiteSpace(key) || MatchesOtherKey(key)
            ? null
            : Options.FirstOrDefault(o => o.Key.Equals(key.Trim(), StringComparison.OrdinalIgnoreCase));

    /// <summary>True when the human typed a custom answer via the lettered Other option.</summary>
    public bool IsOtherAnswer =>
        AllowOther && !string.IsNullOrEmpty(OtherKey) &&
        string.Equals(AnswerKey, OtherKey, StringComparison.OrdinalIgnoreCase);

    /// <summary>Whether <paramref name="key"/> selects Other (letter or legacy <c>other</c> alias).</summary>
    public bool MatchesOtherKey(string? key) =>
        AllowOther && OtherKey != null &&
        (string.Equals(key?.Trim(), OtherKey, StringComparison.OrdinalIgnoreCase) ||
         DecisionOption.IsOtherAlias(key));

    /// <summary>Seconds until the default fires, floored at zero. Only meaningful while pending.</summary>
    public int SecondsRemaining =>
        Status != DecisionStatuses.Pending ? 0 : Math.Max(0, (int)Math.Ceiling((ExpiresAt - DateTime.Now).TotalSeconds));
}

/// <summary>One answer the human can pick.</summary>
public sealed class DecisionOption
{
    /// <summary>Single letter A–F, assigned in the order the options were supplied.</summary>
    public string Key { get; set; } = "";

    /// <summary>Short label shown on the button.</summary>
    public string Label { get; set; } = "";

    /// <summary>Optional second line explaining the consequence of picking this option.</summary>
    public string? Detail { get; set; }

    /// <summary>Keys in assignment order. The cap is <see cref="DecisionDefaults.MaxOptions"/>.</summary>
    private const string KeyAlphabet = "ABCDEF";

    /// <summary>The key for a zero-based option position.</summary>
    public static string KeyAt(int index) =>
        index >= 0 && index < KeyAlphabet.Length ? KeyAlphabet[index].ToString() : (index + 1).ToString();

    /// <summary>Legacy REST/MCP alias for the lettered Other option (<c>option:"other"</c>).</summary>
    public const string OtherAlias = "other";

    public static bool IsOtherAlias(string? key) =>
        string.Equals(key?.Trim(), OtherAlias, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Valid <see cref="Decision.Lane"/> values, ordered by how much they interrupt.</summary>
public static class DecisionLanes
{
    /// <summary>The agent cannot proceed: it waits for an answer or for the default to fire.</summary>
    public const string Gate = "gate";

    /// <summary>The agent proceeds on the default now; a later human answer redirects it.</summary>
    public const string Steer = "steer";

    /// <summary>Never blocks — a record the human can weigh in on.</summary>
    public const string Review = "review";

    public static readonly string[] All = [Gate, Steer, Review];

    public static string Normalize(string? lane)
    {
        if (string.IsNullOrWhiteSpace(lane)) return Steer;
        var l = lane.Trim().ToLowerInvariant();
        return Array.IndexOf(All, l) >= 0 ? l : Steer;
    }

    public static bool IsKnown(string? lane) =>
        lane != null && Array.IndexOf(All, lane.Trim().ToLowerInvariant()) >= 0;
}

/// <summary>Valid <see cref="Decision.Status"/> values.</summary>
public static class DecisionStatuses
{
    /// <summary>Open — waiting on the human.</summary>
    public const string Pending = "pending";

    /// <summary>A human (or a peer, via REST) picked an option.</summary>
    public const string Answered = "answered";

    /// <summary>Nobody answered in time and a default was configured.</summary>
    public const string Defaulted = "defaulted";

    /// <summary>Nobody answered in time and there was no default — the agent got no steer at all.</summary>
    public const string Expired = "expired";

    /// <summary>The agent withdrew the question (it worked the answer out, or it no longer matters).</summary>
    public const string Cancelled = "cancelled";

    public static readonly string[] All = [Pending, Answered, Defaulted, Expired, Cancelled];

    public static string Normalize(string? status)
    {
        if (string.IsNullOrWhiteSpace(status)) return Pending;
        var s = status.Trim().ToLowerInvariant();
        return Array.IndexOf(All, s) >= 0 ? s : Pending;
    }

    public static bool IsKnown(string? status) =>
        status != null && Array.IndexOf(All, status.Trim().ToLowerInvariant()) >= 0;
}

/// <summary>Valid <see cref="Decision.Urgency"/> values.</summary>
public static class DecisionUrgencies
{
    public const string Low = "low";
    public const string Normal = "normal";
    public const string High = "high";

    public static readonly string[] All = [Low, Normal, High];

    public static string Normalize(string? urgency)
    {
        if (string.IsNullOrWhiteSpace(urgency)) return Normal;
        var u = urgency.Trim().ToLowerInvariant();
        return Array.IndexOf(All, u) >= 0 ? u : Normal;
    }
}

/// <summary>Valid <see cref="Decision.AnsweredBy"/> values.</summary>
public static class DecisionAnswerers
{
    /// <summary>The tester clicked an option in the AI Assistant panel.</summary>
    public const string Human = "human";

    /// <summary>Nobody answered and the timeout applied <see cref="Decision.DefaultKey"/>.</summary>
    public const string Default = "default";

    /// <summary>The agent withdrew its own question.</summary>
    public const string Agent = "agent";
}

/// <summary>Bounds and defaults shared by the store, the API handlers, and the tool schemas.</summary>
public static class DecisionDefaults
{
    /// <summary>Five minutes. A human who stepped away for coffee should still get the call.</summary>
    public const int TimeoutMs = 300_000;

    public const int MinTimeoutMs = 5_000;

    /// <summary>Thirty minutes. Beyond this a question is really a note, not a decision.</summary>
    public const int MaxTimeoutMs = 1_800_000;

    public const int MinOptions = 2;
    public const int MaxOptions = 6;

    /// <summary>With <c>allowOther</c>, Other takes the next letter — so at most five listed options (A–E + F).</summary>
    public const int MaxOptionsWithOther = 5;

    /// <summary>Steer grace: max hold before returning the provisional default (two minutes).</summary>
    public const int MaxGraceMs = 120_000;
}
