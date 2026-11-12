using System.IO;
using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.ChainEngine;
using Trowser.SessionLog;

namespace Trowser.Security.Vpx;

/// <summary>
/// In-process VPX session export/import shared by REST, MCP, and the GUI menu.
/// Builds the same document as <c>GET /api/vpx/export</c> without an HTTP round-trip.
/// </summary>
public static class VpxSessionIo
{
    public sealed class ExportResult
    {
        public required string Json { get; init; }
        public int FindingCount { get; init; }
    }

    /// <summary>
    /// Build a VPX 1.1 JSON document from the live session finding feed.
    /// </summary>
    /// <param name="profile"><c>compact</c> (default) or <c>full</c>.</param>
    /// <param name="baseUrl">Optional page URL for the document <c>target</c>; callers may await <c>GetCurrentUrl</c>.</param>
    public static ExportResult Export(
        AutomationContext context,
        SessionLogger? sessionLogger = null,
        string profile = "compact",
        string? baseUrl = null)
    {
        if (profile is not ("compact" or "full"))
            profile = "compact";

        var findings = ChainAnalysisService.CollectFindings(context, sessionLogger);
        var json = VpxExportService.ExportJson(new VpxExportService.ExportInput
        {
            Findings = findings,
            Proofs = context.GetVpxProofsSnapshot(),
            Verdicts = context.GetVpxVerdictsSnapshot(),
            ImportedSurfaces = context.GetVpxSurfacesSnapshot(),
            ImportedRuns = context.GetVpxRunsSnapshot(),
            ImportedAssessments = context.GetVpxAssessmentsSnapshot(),
            ImportedArtifacts = context.GetVpxArtifactsSnapshot(),
            ImportTarget = context.GetVpxImportTarget(),
            BaseUrl = baseUrl,
            Profile = profile,
            DocumentId = context.GetVpxImportDocumentId()
        });

        return new ExportResult { Json = json, FindingCount = findings.Count };
    }

    /// <summary>Write a session VPX document to disk. Returns the same result as <see cref="Export"/>.</summary>
    public static ExportResult ExportToFile(
        AutomationContext context,
        string path,
        SessionLogger? sessionLogger = null,
        string profile = "compact",
        string? baseUrl = null)
    {
        var result = Export(context, sessionLogger, profile, baseUrl);
        File.WriteAllText(path, result.Json);
        return result;
    }

    /// <summary>
    /// Import a VPX JSON file into the session (default <c>merge</c> — same as <c>POST /api/vpx/import</c>).
    /// </summary>
    public static VpxImportService.ImportResult ImportFromFile(
        AutomationContext context,
        string path,
        string mode = "merge")
    {
        var text = File.ReadAllText(path);
        using var doc = JsonDocument.Parse(text);
        return VpxImportService.ImportDocument(context, doc.RootElement, mode);
    }

    /// <summary>Suggest a SaveFileDialog file name from an optional page URL.</summary>
    public static string SuggestFileName(string? baseUrl)
    {
        var host = "session";
        if (!string.IsNullOrWhiteSpace(baseUrl) && Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri)
            && !string.IsNullOrWhiteSpace(uri.Host))
        {
            host = uri.Host;
            foreach (var c in Path.GetInvalidFileNameChars())
                host = host.Replace(c, '_');
        }

        return $"vpx-{host}-{DateTime.Now:yyyyMMdd_HHmmss}.vpx.json";
    }
}
