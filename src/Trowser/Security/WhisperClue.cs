using System.Text;

namespace Trowser.Security;

/// <summary>
/// A Red Team Whisper <b>clue</b> — a hypothesis for the tester or AI, not a security finding.
/// Security Shadow owns CSP, cookies, XSS, mixed content, source maps, storage, and sensitive URLs.
/// </summary>
public sealed class WhisperClue
{
    private static int _nextId;

    public int Id { get; init; } = Interlocked.Increment(ref _nextId);
    public string Kind { get; init; } = "";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string WhyItMatters { get; init; } = "";
    public string? SuggestedNext { get; init; }
    public string? Url { get; init; }

    /// <summary>Session-stable key so the same clue is not toasted again while testing.</summary>
    public string Fingerprint { get; init; } = "";

    public object ToApiObject() => new
    {
        id = Id,
        kind = Kind,
        title = Title,
        detail = Detail,
        whyItMatters = WhyItMatters,
        suggestedNext = SuggestedNext,
        url = Url,
        fingerprint = Fingerprint
    };

    public static string MakeFingerprint(string kind, string host, string? extra = null)
    {
        var h = string.IsNullOrEmpty(host) ? "_" : host.ToLowerInvariant();
        return string.IsNullOrWhiteSpace(extra)
            ? $"{kind}|{h}"
            : $"{kind}|{h}|{extra.Trim()}";
    }

    /// <summary>
    /// Toast text plus dig-deeper details — what Copy should put on the clipboard.
    /// </summary>
    public static string FormatCopy(string toastText, IReadOnlyList<WhisperClue> clues)
    {
        var sb = new StringBuilder();
        sb.AppendLine(toastText.TrimEnd());
        if (clues.Count == 0)
            return sb.ToString().TrimEnd();

        sb.AppendLine();
        foreach (var c in clues)
        {
            sb.AppendLine($"Clue: {c.Title}");
            if (!string.IsNullOrEmpty(c.Kind))
                sb.AppendLine($"Kind: {c.Kind}");
            if (!string.IsNullOrEmpty(c.Url))
                sb.AppendLine($"URL: {c.Url}");
            if (!string.IsNullOrEmpty(c.WhyItMatters))
                sb.AppendLine($"Why: {c.WhyItMatters}");
            if (!string.IsNullOrEmpty(c.Detail))
                sb.AppendLine($"Details: {c.Detail}");
            if (!string.IsNullOrEmpty(c.SuggestedNext))
                sb.AppendLine($"Next: {c.SuggestedNext}");
            sb.AppendLine();
        }

        return sb.ToString().TrimEnd();
    }
}
