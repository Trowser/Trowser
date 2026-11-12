using System.IO;

namespace Trowser.Recording;

/// <summary>
/// Snapshot of a finished recording. Writers are closed; temp files may still exist on disk
/// until <see cref="DeleteTempFiles"/> is called after destinations are applied or discarded.
/// </summary>
public sealed class RecordingStopResult
{
    public required string Script { get; init; }
    public required string Narration { get; init; }
    public required string StartUrl { get; init; }
    public required DateTime StartedAt { get; init; }
    public required int ActionCount { get; init; }
    public string? TempCsxPath { get; init; }
    public string? TempNarrationPath { get; init; }

    /// <summary>Best-effort delete of temp .csx / narration files after Save or Discard.</summary>
    public void DeleteTempFiles()
    {
        TryDelete(TempCsxPath);
        TryDelete(TempNarrationPath);
    }

    private static void TryDelete(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Recorder temp cleanup failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Insert an optional description comment after the standard header lines.
    /// </summary>
    public string ScriptWithDescription(string? description)
    {
        if (string.IsNullOrWhiteSpace(description))
            return Script;

        var line = $"// Description: {description.Trim().Replace("\r", " ").Replace("\n", " ")}";
        var text = Script;
        // Header is typically: // Recorded... \n // Start URL: ... \n \n
        var secondNewline = text.IndexOf('\n');
        if (secondNewline < 0)
            return line + "\n" + text;

        var thirdNewline = text.IndexOf('\n', secondNewline + 1);
        if (thirdNewline < 0)
            return text + "\n" + line + "\n";

        return text[..(thirdNewline + 1)] + line + "\n" + text[(thirdNewline + 1)..];
    }

    /// <summary>Sanitize description into a suggested .csx file name (no extension).</summary>
    public static string SuggestFileBaseName(string? description, DateTime startedAt)
    {
        if (string.IsNullOrWhiteSpace(description))
            return $"recording-{startedAt:yyyyMMdd-HHmmss}";

        var chars = description.Trim().ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            var c = chars[i];
            if (char.IsLetterOrDigit(c)) continue;
            chars[i] = c is ' ' or '-' or '_' ? '-' : '-';
        }

        var slug = new string(chars);
        while (slug.Contains("--", StringComparison.Ordinal))
            slug = slug.Replace("--", "-", StringComparison.Ordinal);
        slug = slug.Trim('-');
        if (slug.Length > 60) slug = slug[..60].TrimEnd('-');
        return string.IsNullOrEmpty(slug) ? $"recording-{startedAt:yyyyMMdd-HHmmss}" : slug;
    }
}
