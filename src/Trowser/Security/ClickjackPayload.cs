namespace Trowser.Security;

public static class ClickjackPayload
{
    public static object Serialize(ClickjackSweep.SweepResult result, bool sweepMode)
    {
        var findings = CollectFindings(result.Document, result.Endpoints);
        return new
    {
        isClean = result.IsClean,
        issueCount = result.IssueCount,
        documentUrl = result.DocumentUrl,
        urlsSwept = result.UrlsSwept,
        findings,
        document = SerializeUrlResult(result.Document),
        sweep = sweepMode
            ? result.Endpoints.Where(e => !e.IsDocumentBaseline).Select(SerializeUrlResult).ToList()
            : null,
        endpoints = sweepMode ? null : result.Endpoints.Select(SerializeUrlResult).ToList()
    };
    }

    private static List<object> CollectFindings(
        ClickjackTester.UrlTestResult document,
        IReadOnlyList<ClickjackTester.UrlTestResult> endpoints)
    {
        var list = new List<object>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(ClickjackTester.UrlTestResult row)
        {
            if (!row.FrameProtection.MissingProtection) return;
            foreach (var pf in row.PassiveFindings)
            {
                var key = $"{row.Url}|{pf.Header}|{pf.Description}";
                if (!seen.Add(key)) continue;
                list.Add(new
                {
                    url = row.Url,
                    severity = pf.Severity.ToString().ToLowerInvariant(),
                    description = pf.Description,
                    activeOracle = row.Active?.FrameOracle,
                    activeInconclusive = row.Active is { Attempted: true, LikelyVulnerable: false }
                });
            }
        }

        Add(document);
        foreach (var e in endpoints.Where(e => !ReferenceEquals(e, document)))
            Add(e);
        return list;
    }

    public static object SerializeUrlResult(ClickjackTester.UrlTestResult row) => new
    {
        url = row.Url,
        isDocumentBaseline = row.IsDocumentBaseline,
        isSensitivePage = row.IsSensitivePage,
        isVulnerable = row.IsVulnerable,
        frameProtection = new
        {
            row.FrameProtection.HasXFrameOptions,
            row.FrameProtection.HasCspFrameAncestors,
            xFrameOptions = row.FrameProtection.XFrameOptions,
            cspFrameAncestors = row.FrameProtection.CspFrameAncestorsDirective,
            missingProtection = row.FrameProtection.MissingProtection
        },
        passiveFindings = row.PassiveFindings.Select(f => new
        {
            header = f.Header,
            severity = f.Severity.ToString().ToLower(),
            description = f.Description,
            recommendation = f.Recommendation
        }).ToList(),
        active = row.Active == null ? null : new
        {
            row.Active.Attempted,
            testedUrl = row.Active.TestedUrl,
            frameOracle = row.Active.FrameOracle,
            row.Active.CrossOriginFrameLoaded,
            row.Active.LikelyVulnerable,
            row.Active.Detail,
            row.Active.Error
        },
        overlay = row.Overlay == null ? null : new
        {
            row.Overlay.Attempted,
            row.Overlay.Ref,
            row.Overlay.TargetVisible,
            row.Overlay.OverlayFramed,
            row.Overlay.Detail
        }
    };
}
