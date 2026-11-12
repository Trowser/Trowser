using Trowser.Automation;
using Trowser.Security.Vpx;

namespace Trowser.Security.XsLeaks;

/// <summary>Attach watermarked XS-Leak PoC HTML to the session VPX artifact feed (local export only).</summary>
internal static class XsLeakVpxArtifacts
{
    public static void RegisterPocHtml(
        AutomationContext ctx,
        string findingId,
        string technique,
        string runId,
        string pocHtml)
    {
        if (string.IsNullOrWhiteSpace(pocHtml)) return;

        var normalizedFindingId = VpxExportService.NormalizeFindingId(findingId);
        var artifactId = $"artifact-{normalizedFindingId}-poc";

        ctx.AddVpxArtifact(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["id"] = artifactId,
            ["kind"] = "xs-leak-poc",
            ["mimeType"] = "text/html",
            ["findingId"] = normalizedFindingId,
            ["technique"] = technique,
            ["runId"] = runId,
            ["content"] = pocHtml,
            ["producedByRunId"] = VpxExportService.SessionRunId,
            ["note"] = "Session-local evidence; do not host or serve outside the test session."
        });
    }
}
