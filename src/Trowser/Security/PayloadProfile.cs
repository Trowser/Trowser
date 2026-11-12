namespace Trowser.Security;

/// <summary>
/// Payload corpus breadth for fuzzers and injection scanners.
/// Orthogonal to <c>scanDepth</c> / <c>safetyMode</c> — never bypasses safety gates.
/// </summary>
public enum PayloadProfile
{
    /// <summary>Built-in curated C# catalogs (default — current behavior).</summary>
    Small,

    /// <summary>
    /// Mapped subsets from external corpora (SecLists + PayloadsAllTheThings)
    /// under <c>corpora/</c> beside the exe or <c>%TROWSER_CORPORA%</c>.
    /// Strict per-set caps still apply.
    /// </summary>
    Big
}

public static class PayloadProfileExtensions
{
    public static PayloadProfile Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return PayloadProfile.Small;
        return value.Trim().ToLowerInvariant() switch
        {
            "small" or "default" or "builtin" or "built-in" => PayloadProfile.Small,
            "big" or "large" or "extended" or "full" => PayloadProfile.Big,
            _ => PayloadProfile.Small
        };
    }

    public static string ToLabel(this PayloadProfile profile) => profile switch
    {
        PayloadProfile.Big => "big",
        _ => "small"
    };
}
