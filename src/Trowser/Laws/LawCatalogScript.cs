using System.IO;
using System.Text.Json;
using Trowser.Security;

namespace Trowser.Laws;

/// <summary>
/// Law catalog <c>.csx</c> files (embedded <c>Quicktests/Laws</c> and <c>Documents/…/Laws</c>) are compiled
/// into the global <see cref="LawRegistry"/> for Shadow. The Script Console still loads the same source so
/// users can read and copy real Law definitions, but executing those declarations would register duplicate
/// names. Run uses a small runner that calls <c>CheckLaws</c> for Laws already loaded from that file.
/// </summary>
public static class LawCatalogScript
{
    public const string EmbeddedQuicktestsLawsResourcePrefix = "Trowser.Resources.Quicktests.Laws.";

    public static bool TryGetEmbeddedLawSourceKey(string manifestResourceName, out string sourceKey)
    {
        sourceKey = "";
        if (string.IsNullOrEmpty(manifestResourceName)
            || !manifestResourceName.StartsWith(EmbeddedQuicktestsLawsResourcePrefix, StringComparison.Ordinal)
            || !manifestResourceName.EndsWith(".csx", StringComparison.OrdinalIgnoreCase))
            return false;

        var relative = manifestResourceName[EmbeddedQuicktestsLawsResourcePrefix.Length..^4];
        var virtualPath = relative.Replace('.', Path.DirectorySeparatorChar) + ".csx";
        sourceKey = "embedded:" + virtualPath;
        return true;
    }

    public static bool TryGetUserLawSourceKey(string filePath, out string sourceKey)
    {
        sourceKey = "";
        if (string.IsNullOrWhiteSpace(filePath) || !filePath.EndsWith(".csx", StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            var lawsRoot = Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(LawService.UserLawsFolder)) + Path.DirectorySeparatorChar;
            var full = Path.GetFullPath(filePath);
            if (!full.StartsWith(lawsRoot, StringComparison.OrdinalIgnoreCase))
                return false;

            sourceKey = ShadowConfig.NormalizeLawSourceKey(full) ?? full;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Roslyn snippet for Script Console / nested quicktest runs of a Law catalog file.</summary>
    public static string BuildScriptConsoleRunner(string sourceKey) =>
        $"await CheckLaws(allLoaded: true, includeTraffic: true, sourceFile: {JsonSerializer.Serialize(sourceKey)});";

    public static bool SourceFileMatches(string? lawSource, string filterKey)
    {
        if (string.IsNullOrWhiteSpace(filterKey))
            return true;
        var normalizedLaw = ShadowConfig.NormalizeLawSourceKey(lawSource);
        var normalizedFilter = ShadowConfig.NormalizeLawSourceKey(filterKey);
        if (normalizedLaw == null || normalizedFilter == null)
            return false;
        return string.Equals(normalizedLaw, normalizedFilter, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Maps an embedded quicktest manifest name to a catalog source key, when applicable.</summary>
    public static bool TryGetQuicktestResourceLawSourceKey(string manifestResourceName, out string sourceKey) =>
        TryGetEmbeddedLawSourceKey(manifestResourceName, out sourceKey);
}