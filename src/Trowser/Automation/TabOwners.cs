namespace Trowser.Automation;

/// <summary>Valid <see cref="BrowserTab.Owner"/> values.</summary>
public static class TabOwners
{
    public const string Human = "human";
    public const string Agent = "agent";
    public const string Shared = "shared";

    public static readonly string[] All = [Human, Agent, Shared];

    /// <summary>Normalize a supplied owner, or return <paramref name="fallback"/> when omitted/unknown.</summary>
    public static string Normalize(string? owner, string fallback = Human)
    {
        if (string.IsNullOrWhiteSpace(owner)) return fallback;
        var o = owner.Trim().ToLowerInvariant();
        return Array.IndexOf(All, o) >= 0 ? o : fallback;
    }

    public static bool IsKnown(string? owner) =>
        owner != null && Array.IndexOf(All, owner.Trim().ToLowerInvariant()) >= 0;

    public static string Badge(string? owner) => Normalize(owner) switch
    {
        Agent => "A",
        Shared => "S",
        _ => "H"
    };

    public static string Label(string? owner) => Normalize(owner) switch
    {
        Agent => "Agent tab",
        Shared => "Shared tab",
        _ => "Human tab"
    };
}
