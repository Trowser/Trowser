using System.Text.Json;

namespace Trowser.Recording;

/// <summary>
/// Shared DOM capture (see <see cref="ScriptRecorder.InjectionScript"/>) posts every
/// user gesture as <c>__trowser_record</c>. Several features subscribe to that stream:
/// <see cref="Sink.Script"/> (.csx recording), <see cref="Sink.Journal"/>, <see cref="Sink.Narration"/>,
/// and <see cref="Sink.Mirror"/>.
/// </summary>
/// <remarks>
/// <para>
/// The injection script is deliberately sink-agnostic — one hook, one action shape.
/// Differences between features belong here, not as ad-hoc <c>if (type == …)</c>
/// checks in each consumer. When you add a new captured action, add a
/// <see cref="Catalog"/> row and explain <em>why</em> each sink is in or out.
/// </para>
/// <para>
/// Typical split: <b>replay sinks</b> (Script / Journal / Narration) want a compact,
/// locator-stable script. <b>Live sinks</b> (Mirror) want to reproduce what the user
/// just did, including viewport motion that would be noise on replay.
/// </para>
/// </remarks>
public static class CapturedActionRouting
{
    [Flags]
    public enum ActionSinks
    {
        None = 0,
        Script = 1,
        Journal = 2,
        Narration = 4,
        Mirror = 8,

        /// <summary>Replay-oriented sinks: .csx, session journal, human-readable steps.</summary>
        Replay = Script | Journal | Narration,

        /// <summary>Every current sink. Use for ordinary clicks/types that all features want.</summary>
        All = Replay | Mirror
    }

    public enum Sink
    {
        Script,
        Journal,
        Narration,
        Mirror
    }

    /// <summary>
    /// One row per <c>action.type</c> posted by the capture script (plus context-menu types).
    /// This list is the source of truth for sink membership.
    /// </summary>
    public static readonly CapturedActionSpec[] Catalog =
    [
        new("click", ActionSinks.All,
            "Primary user gesture; semantic locators replay and mirror reliably."),
        new("hover", ActionSinks.All,
            "Needed to open menus/dropdowns before the following click."),
        new("type", ActionSinks.All,
            "Field value is the intent; locators are stable enough for both replay and live peers."),
        new("select", ActionSinks.All,
            "Dropdown choice is the intent, same as type."),
        new("key", ActionSinks.All,
            "Special keys (Enter, Tab, …) change page state; include everywhere."),
        new("radio", ActionSinks.All,
            "Radio click is a real state change, recorded as an indexed click."),
        new("scroll", ActionSinks.Mirror,
            "Live peers must follow the user's viewport. Replay scripts must not: window size, " +
            "responsive layout, and peer page versions differ, so scroll steps lengthen .csx / journal " +
            "output without making playback more reliable."),
        new("assert", ActionSinks.Script | ActionSinks.Narration,
            "Context-menu annotation for the recorded script, not a live peer action."),
        new("elementOfInterest", ActionSinks.Script | ActionSinks.Narration,
            "Context-menu annotation for the recorded script, not a live peer action.")
    ];

    public static bool Accepts(Sink sink, JsonElement action)
    {
        if (!action.TryGetProperty("type", out var typeProp) || typeProp.ValueKind != JsonValueKind.String)
            return false;
        return Accepts(sink, typeProp.GetString());
    }

    public static bool Accepts(Sink sink, string? actionType)
    {
        var flags = SinksFor(actionType);
        return sink switch
        {
            Sink.Script => flags.HasFlag(ActionSinks.Script),
            Sink.Journal => flags.HasFlag(ActionSinks.Journal),
            Sink.Narration => flags.HasFlag(ActionSinks.Narration),
            Sink.Mirror => flags.HasFlag(ActionSinks.Mirror),
            _ => false
        };
    }

    public static ActionSinks SinksFor(string? actionType)
    {
        if (string.IsNullOrEmpty(actionType))
            return ActionSinks.None;

        foreach (var spec in Catalog)
        {
            if (spec.Type.Equals(actionType, StringComparison.Ordinal))
                return spec.Sinks;
        }

        return ActionSinks.None;
    }
}

/// <summary>Declaration of one captured action type and which features consume it.</summary>
public sealed record CapturedActionSpec(string Type, CapturedActionRouting.ActionSinks Sinks, string Why);
