namespace Trowser.Security.XsLeaks;

/// <summary>
/// Cross-check posture headers against oracle outcomes (CORP/COOP effectiveness, SameSite feasibility).
/// </summary>
internal static class XsLeakPostureCorrelator
{
    public static void Apply(XsLeakScanner.XsLeakResult result)
    {
        if (result.Posture == null) return;

        var dedupe = result.Posture.Controls
            .Select(c => c.Control + "|" + (c.Detail ?? ""))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var corpPresent = result.Posture.Controls.Any(c =>
            c.Control == "CORP" && c.Status is "present");
        var coopPresent = result.Posture.Controls.Any(c =>
            c.Control == "COOP" && c.Status is "present");

        foreach (var tech in result.Techniques)
        {
            if (tech.Tier != SecurityFindingTier.Exploitable) continue;
            if (tech.Verdict is not ("distinguishable" or "probable")) continue;

            if (corpPresent && !tech.Mitigated
                && tech.Category is "load-error" or "media" or "cache" or "status")
            {
                AddControl(result.Posture.Controls, dedupe, new XsLeakPostureAnalyzer.ControlVerdict
                {
                    Control = "CORP-effectiveness",
                    Status = "partial",
                    Detail =
                        $"CORP is present on victim traffic but {tech.Technique} still distinguishes states — " +
                        "header may not cover this resource, mocks may bypass isolation, or CORP value is too permissive."
                });
            }

            if (coopPresent && tech.Technique is "popup-closed" or "window-open-length" && !tech.Mitigated)
            {
                AddControl(result.Posture.Controls, dedupe, new XsLeakPostureAnalyzer.ControlVerdict
                {
                    Control = "COOP-effectiveness",
                    Status = "partial",
                    Detail = "COOP header present but window/popup oracle still distinguishes states."
                });
            }

            var cookieNote = SameSiteFeasibilityNote(tech.Technique, result.CookieMode);
            if (cookieNote != null)
            {
                AddControl(result.Posture.Controls, dedupe, new XsLeakPostureAnalyzer.ControlVerdict
                {
                    Control = "SameSite-feasibility",
                    Status = "observed",
                    Detail = cookieNote
                });
            }
        }
    }

    private static void AddControl(
        List<XsLeakPostureAnalyzer.ControlVerdict> controls,
        HashSet<string> dedupe,
        XsLeakPostureAnalyzer.ControlVerdict verdict)
    {
        var key = verdict.Control + "|" + (verdict.Detail ?? "");
        if (!dedupe.Add(key)) return;
        controls.Add(verdict);
    }

    private static string? SameSiteFeasibilityNote(string techniqueId, string cookieMode)
    {
        var subresource = techniqueId is "script-error" or "img-error" or "link-stylesheet-error"
            or "object-load" or "audio-error" or "track-error" or "script-module-error"
            or "media-dimensions" or "resource-transfer-size" or "cache-prime-probe";
        var navigation = techniqueId is "iframe-load" or "iframe-framecount" or "performance-timing"
            or "postmessage-listen" or "popup-closed" or "window-open-length";
        var credentialedFetch = techniqueId is "fetch-redirect-type" or "status-bucket-oracle"
            or "redirect-count-oracle";

        if (cookieMode.Contains("strict", StringComparison.OrdinalIgnoreCase) && subresource)
            return $"{techniqueId}: subresource oracle — Strict SameSite cookies typically do not ride on cross-site embeds.";
        if (cookieMode.Contains("none", StringComparison.OrdinalIgnoreCase) && credentialedFetch)
            return $"{techniqueId}: credentialed fetch/no-cors may include None cookies on cross-site requests.";
        if (navigation && cookieMode.Contains("lax", StringComparison.OrdinalIgnoreCase))
            return $"{techniqueId}: top-level navigation or framing may carry Lax cookies depending on user gesture.";
        return null;
    }
}
