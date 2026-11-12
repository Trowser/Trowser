using System.Globalization;
using System.Text;

namespace Trowser.Security.Authz;

/// <summary>One access-model resource cross-referenced with any Live Authz Shadow findings for it.</summary>
public sealed class BacCoverageFinding
{
    public required string Method { get; init; }
    public required string UrlTemplate { get; init; }
    public required string Peer { get; init; }
    public required string Verdict { get; init; }
    public required string Confidence { get; init; }
    public required string Reason { get; init; }
    public string? ExpectedOutcome { get; init; }
    public required string Url { get; init; }
    public required DateTime Timestamp { get; init; }

    public int OwnerStatus { get; init; }
    public int PeerStatus { get; init; }
    public int OwnerBodyLength { get; init; }
    public int PeerBodyLength { get; init; }
    public string? PeerFinalUrl { get; init; }
    public int OwnerTokenCount { get; init; }
    public string? PeerAuthApplied { get; init; }
    public bool OwnerBodyMissing { get; init; }
    public bool HtmlShell { get; init; }
    public bool DuplicateHtmlShell { get; init; }
    public bool PeerMutated { get; init; }

    /// <summary>
    /// <c>violation</c> (reality contradicts declared intent), <c>consistent</c>, <c>unresolved</c>
    /// (different content on a resource that should have been denied — not proof either way),
    /// <c>needs-classification</c>, or <c>unclassified</c>.
    /// </summary>
    public string IntentAlignment { get; init; } = "unclassified";
}

/// <summary>One attack-surface resource with no access-model classification and no shadow coverage yet.</summary>
public sealed class BacCoverageGap
{
    public required string Method { get; init; }
    public required string UrlTemplate { get; init; }
    public required bool AuthRequired { get; init; }
    public required string TestPriority { get; init; }
    public required string Reason { get; init; }

    /// <summary>
    /// <c>safety</c>, <c>nonSuccess</c>, <c>resourceType</c>, or <c>thirdParty</c> when the browser
    /// saw the request and the shadow deliberately did not replay it. Null means it was never seen.
    /// </summary>
    public string? SkipKind { get; init; }
}

/// <summary>
/// A point-in-time snapshot of how much of a host's attack surface has a declared intent
/// (<see cref="AccessModel"/>) and/or has actually been cross-identity tested
/// (<see cref="LiveAuthzShadow"/>), with findings grouped by verdict and provenance, and the remaining gaps.
/// </summary>
public sealed class BacCoverageReport
{
    public required string Host { get; init; }
    public required DateTime GeneratedAt { get; init; }

    /// <summary>Identities the access model knows about for this host.</summary>
    public required List<AccessModelIdentity> Identities { get; init; }

    /// <summary>Total known (method, urlTemplate) resources from the attack surface map.</summary>
    public required int AttackSurfaceEndpointCount { get; init; }

    /// <summary>Resources that are either classified in the access model or covered by a shadow result.</summary>
    public required int CoverageNumerator { get; init; }

    /// <summary>Total resources considered for coverage (attack surface ∪ access model).</summary>
    public required int CoverageDenominator { get; init; }

    public double CoveragePercent => CoverageDenominator == 0
        ? 0
        : Math.Round(100.0 * CoverageNumerator / CoverageDenominator, 1);

    public required Dictionary<string, List<BacCoverageFinding>> FindingsByVerdict { get; init; }
    public required List<BacCoverageGap> Gaps { get; init; }
    public required List<string> NextActions { get; init; }

    /// <summary>Build the report from the access model, the attack surface map, and shadow results already scoped to the host.</summary>
    public static BacCoverageReport Build(
        AccessModel model,
        IReadOnlyList<AttackSurfaceEndpoint> endpoints,
        IReadOnlyList<LiveAuthzShadowResult> shadowResults,
        IReadOnlyList<AuthzShadowSkip>? skips = null,
        string? pageHost = null)
    {
        // Expand (urlTemplate, methods[]) attack-surface endpoints into per-(method,urlTemplate) keys —
        // the same granularity AccessModelResource and LiveAuthzShadowResult use.
        var surfaceKeys = new Dictionary<string, AttackSurfaceEndpoint>(StringComparer.OrdinalIgnoreCase);
        foreach (var ep in endpoints)
        {
            var template = string.IsNullOrWhiteSpace(ep.UrlTemplate) ? ep.Url : ep.UrlTemplate;
            var methods = ep.Methods.Count > 0 ? ep.Methods : ["GET"];
            foreach (var method in methods)
                surfaceKeys[AccessModelResource.KeyOf(method, template)] = ep;
        }

        var resultsByKey = shadowResults
            .GroupBy(r => AccessModelResource.KeyOf(r.Method, r.UrlTemplate), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        var skipsByKey = new Dictionary<string, AuthzShadowSkip>(StringComparer.OrdinalIgnoreCase);
        foreach (var skip in skips ?? [])
        {
            var skipKey = AccessModelResource.KeyOf(skip.Method, NormalizeTemplate(skip.UrlTemplate));
            skipsByKey.TryAdd(skipKey, skip);
        }

        var allKeys = new HashSet<string>(surfaceKeys.Keys, StringComparer.OrdinalIgnoreCase);
        allKeys.UnionWith(model.Resources.Keys);
        allKeys.UnionWith(resultsByKey.Keys);

        var numerator = 0;
        var gaps = new List<BacCoverageGap>();
        foreach (var key in allKeys)
        {
            var classified = model.Resources.TryGetValue(key, out var resource) && !resource.IsUnclassified;
            var tested = resultsByKey.ContainsKey(key);
            if (classified || tested)
            {
                numerator++;
                continue;
            }

            if (!surfaceKeys.TryGetValue(key, out var ep))
                continue; // known only from a stale model/result entry — nothing to report as a gap

            var parts = key.Split(' ', 2);
            var method = parts.Length > 0 ? parts[0] : "GET";
            var template = parts.Length > 1 ? parts[1] : key;
            var normalized = AccessModelResource.KeyOf(method, NormalizeTemplate(template));
            skipsByKey.TryGetValue(normalized, out var skip);
            gaps.Add(DescribeGap(method, template, ep, skip));
        }

        var findingsByVerdict = shadowResults
            .GroupBy(r => r.Verdict.ToString())
            .ToDictionary(
                g => g.Key,
                g => g.Select(r => new BacCoverageFinding
                {
                    Method = r.Method,
                    UrlTemplate = r.UrlTemplate,
                    Peer = r.Peer,
                    Verdict = r.Verdict.ToString(),
                    Confidence = r.Confidence,
                    Reason = r.Reason,
                    Url = r.Url,
                    Timestamp = r.Timestamp,
                    OwnerStatus = r.OwnerStatus,
                    PeerStatus = r.PeerStatus,
                    OwnerBodyLength = r.OwnerBodyLength,
                    PeerBodyLength = r.PeerBodyLength,
                    PeerFinalUrl = r.PeerFinalUrl,
                    OwnerTokenCount = r.OwnerTokenCount,
                    PeerAuthApplied = r.PeerAuthApplied,
                    OwnerBodyMissing = r.OwnerBodyMissing,
                    HtmlShell = r.HtmlShell,
                    DuplicateHtmlShell = r.DuplicateHtmlShell,
                    PeerMutated = r.PeerMutated,
                    ExpectedOutcome = CurrentExpected(model, r),
                    IntentAlignment = AlignIntent(CurrentExpected(model, r), r.Verdict.ToString())
                }).OrderByDescending(f => f.Timestamp).ToList());

        var nextActions = BuildNextActions(findingsByVerdict, gaps);
        if (shadowResults.Count == 0)
        {
            nextActions.RemoveAll(a => a.Contains("No outstanding BAC gaps", StringComparison.Ordinal));
            nextActions.Insert(0, EmptyHostAction(model.Host, pageHost));
        }

        return new BacCoverageReport
        {
            Host = model.Host,
            GeneratedAt = DateTime.UtcNow,
            Identities = model.Identities,
            AttackSurfaceEndpointCount = surfaceKeys.Count,
            CoverageNumerator = numerator,
            CoverageDenominator = allKeys.Count,
            FindingsByVerdict = findingsByVerdict,
            Gaps = gaps.OrderByDescending(g => g.AuthRequired).ThenBy(g => g.UrlTemplate, StringComparer.OrdinalIgnoreCase).ToList(),
            NextActions = nextActions
        };
    }

    private static List<string> BuildNextActions(
        Dictionary<string, List<BacCoverageFinding>> findingsByVerdict, List<BacCoverageGap> gaps)
    {
        var actions = new List<string>();

        if (findingsByVerdict.TryGetValue(AuthzVerdictKind.ConfirmedLeak.ToString(), out var leaks) && leaks.Count > 0)
            actions.Add($"Fix {leaks.Count} confirmed cross-identity leak(s) first: " +
                string.Join(", ", leaks.Take(3).Select(f => $"{f.Method} {f.UrlTemplate}")) +
                (leaks.Count > 3 ? $" (+{leaks.Count - 3} more)" : "") + ".");

        var mutated = findingsByVerdict.Values.SelectMany(f => f).Where(f => f.PeerMutated).ToList();
        if (mutated.Count > 0)
            actions.Add($"{mutated.Count} write(s) were executed as the peer (peerMutated). " +
                "Check that account for a new row before treating a 201 as a leak: " +
                string.Join(", ", mutated.Take(3).Select(f => $"{f.Method} {f.UrlTemplate}")) +
                (mutated.Count > 3 ? $" (+{mutated.Count - 3} more)" : "") + ".");

        var unauthenticated = findingsByVerdict.Values
            .SelectMany(f => f)
            .Where(f => string.Equals(f.PeerAuthApplied, "none", StringComparison.OrdinalIgnoreCase)
                || f.Verdict == AuthzVerdictKind.PeerUnauthenticated.ToString())
            .ToList();
        var missingAuth = unauthenticated.Where(f => f.PeerStatus is >= 200 and < 300).ToList();
        var denied = unauthenticated.Where(f => f.PeerStatus is < 200 or >= 300).ToList();
        if (missingAuth.Count > 0)
            actions.Add($"{missingAuth.Count} replay(s) had no peer credential (peerAuthApplied: none) and still returned 200. " +
                "That is missing authentication, not a public page. Log the peer in, or treat the 200 as the bug: " +
                string.Join(", ", missingAuth.Take(3).Select(f => $"{f.Method} {f.UrlTemplate}")) +
                (missingAuth.Count > 3 ? $" (+{missingAuth.Count - 3} more)" : "") + ".");
        if (denied.Count > 0)
            actions.Add($"{denied.Count} replay(s) had no peer credential (peerAuthApplied: none) and were denied. " +
                "Those denials are inconclusive. Log the peer in.");

        if (findingsByVerdict.TryGetValue(AuthzVerdictKind.BolaSuspected.ToString(), out var bola))
        {
            var open = bola.Where(f => f.IntentAlignment != "consistent" && !f.DuplicateHtmlShell && !f.HtmlShell
                && LiveAuthzShadow.TemplateHasIdentity(f.UrlTemplate)).ToList();
            if (open.Count > 0)
                actions.Add($"Investigate {open.Count} BOLA/IDOR-suspected endpoint(s): " +
                    string.Join(", ", open.Take(3).Select(f => $"{f.Method} {f.UrlTemplate}")) +
                    (open.Count > 3 ? $" (+{open.Count - 3} more)" : "") + ".");

            var shells = bola.Where(f => f.DuplicateHtmlShell).ToList();
            if (shells.Count > 0)
                actions.Add($"{shells.Count} route(s) returned the same HTML bytes as another route. " +
                    "Those are one document. A route with its own body is not.");

            var noId = bola.Where(f => f.IntentAlignment != "consistent" && !f.HtmlShell && !f.DuplicateHtmlShell
                && !LiveAuthzShadow.TemplateHasIdentity(f.UrlTemplate)).ToList();
            if (noId.Count > 0)
                actions.Add($"{noId.Count} identical response(s) have no id in the path. " +
                    "The Live Authz Shadow dialog recommends public unless the body is actually per-user: " +
                    string.Join(", ", noId.Take(3).Select(f => $"{f.Method} {f.UrlTemplate}")) +
                    (noId.Count > 3 ? $" (+{noId.Count - 3} more)" : "") + ".");
        }

        if (findingsByVerdict.TryGetValue(AuthzVerdictKind.FilteredResponse.ToString(), out var filtered))
        {
            var applied = filtered.Where(f => f.PeerAuthApplied is "cookie" or "bearer" or "both").ToList();
            if (applied.Count > 0)
                actions.Add($"{applied.Count} response(s) differed and the peer credential was applied. Compare before closing: " +
                    string.Join(", ", applied.Take(3).Select(f => $"{f.Method} {f.UrlTemplate}")) +
                    (applied.Count > 3 ? $" (+{applied.Count - 3} more)" : "") + ".");
        }

        if (findingsByVerdict.TryGetValue(AuthzVerdictKind.SameShapeDifferentData.ToString(), out var sameShape))
        {
            var open = sameShape.Where(f => f.IntentAlignment != "consistent").ToList();
            if (open.Count > 0)
                actions.Add($"Classify {open.Count} resource(s) returning same-shaped data to other identities " +
                    "in the Live Authz Shadow dialog, or via PUT /api/authz/model.");
        }

        var unresolved = findingsByVerdict.Values
            .SelectMany(f => f)
            .Where(f => f.IntentAlignment == "unresolved")
            .ToList();
        if (unresolved.Count > 0)
            actions.Add($"{unresolved.Count} resource(s) that should be denied returned different 2xx content to another identity. " +
                "Different content is not proof of scoping — compare the bodies (owner/peer status and lengths are on each finding) " +
                "or set identity ownerTags so a leaked name or id can confirm it.");

        var realGaps = gaps.Where(g => g.SkipKind == null).ToList();
        var authGaps = realGaps.Count(g => g.AuthRequired);
        var otherGaps = realGaps.Count - authGaps;
        if (authGaps > 0)
            actions.Add($"{authGaps} authenticated endpoint(s) have no declared intent and have not been cross-identity tested — " +
                "browse them while a peer identity is registered, or classify them directly via PUT /api/authz/model.");
        if (otherGaps > 0)
            actions.Add($"{otherGaps} other endpoint(s) have no declared intent and have not been cross-identity tested.");

        var safetySkips = gaps.Count(g => g.SkipKind == "safety");
        if (safetySkips > 0)
            actions.Add($"{safetySkips} request(s) were skipped because safetyMode is safe. " +
                "Raise to active only if this write should be compared. They are not untested work.");

        var nonSuccess = gaps.Count(g => g.SkipKind == "nonSuccess");
        if (nonSuccess > 0)
            actions.Add($"{nonSuccess} endpoint(s) were called, but the owner response was not a success, so they were not replayed.");

        var typed = gaps.Count(g => g.SkipKind == "resourceType");
        if (typed > 0)
            actions.Add($"{typed} request(s) were seen and skipped because of resource type.");

        var thirdParty = gaps.Count(g => g.SkipKind == "thirdParty");
        if (thirdParty > 0)
            actions.Add($"{thirdParty} request(s) were skipped as a third-party host (skippedThirdParty).");

        if (actions.Count == 0)
            actions.Add("No outstanding BAC gaps or unresolved findings for this host.");

        return actions;
    }

    internal static string EmptyHostAction(string host, string? pageHost)
    {
        var page = string.IsNullOrWhiteSpace(pageHost) ? "unknown" : pageHost;
        var note = LoopbackAliasMismatch(host, page)
            ? " localhost and 127.0.0.1 are different keys."
            : "";
        return $"No replay results for {host}. The page host is {page}.{note}";
    }

    private static bool LoopbackAliasMismatch(string host, string page)
    {
        static string Name(string value)
        {
            var bare = value.Split(':')[0].Trim().Trim('[', ']');
            return bare;
        }

        var a = Name(host);
        var b = Name(page);
        var aLoop = a is "localhost" or "127.0.0.1" or "::1";
        var bLoop = b is "localhost" or "127.0.0.1" or "::1";
        return aLoop && bLoop && !a.Equals(b, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Declared intent at coverage-read time. The value stored on the replay is whatever the model
    /// said when the request was captured; a review answer after that must still show up here.
    /// </summary>
    internal static string? CurrentExpected(AccessModel model, LiveAuthzShadowResult result)
    {
        var resource = FindCurrentResource(model, result.Method, result.UrlTemplate);
        if (resource == null || resource.IsUnclassified) return null;
        return resource.ExpectedCrossIdentityOutcome;
    }

    internal static AccessModelResource? FindCurrentResource(AccessModel model, string method, string urlTemplate)
    {
        var direct = model.FindResource(method, urlTemplate);
        if (direct != null && !direct.IsUnclassified) return direct;

        var norm = NormalizeTemplate(urlTemplate);
        AccessModelResource? unclassified = direct;
        foreach (var resource in model.Resources.Values)
        {
            if (!resource.Method.Equals(method, StringComparison.OrdinalIgnoreCase)) continue;
            if (!NormalizeTemplate(resource.UrlTemplate).Equals(norm, StringComparison.OrdinalIgnoreCase)) continue;
            if (!resource.IsUnclassified) return resource;
            unclassified ??= resource;
        }

        return unclassified;
    }

    /// <summary>Compare a shadow verdict with the access model's expected cross-identity outcome.</summary>
    internal static string AlignIntent(string? expected, string verdict)
    {
        var leaky = verdict is "ConfirmedLeak" or "BolaSuspected" or "SameShapeDifferentData";
        var denied = verdict is "ProperlyDenied";
        var different = verdict is "FilteredResponse";

        if (string.IsNullOrWhiteSpace(expected) || expected == "unknown")
            return leaky || different ? "needs-classification" : "unclassified";

        if (expected == "allow")
        {
            if (verdict == "ConfirmedLeak") return "violation";
            if (leaky || different || denied) return "consistent";
            return "unclassified";
        }

        if (expected.StartsWith("deny", StringComparison.Ordinal))
        {
            if (leaky) return "violation";
            if (denied) return "consistent";
            if (different) return "unresolved";
            return "unclassified";
        }

        return "unclassified";
    }

    internal static string NormalizeTemplate(string? template)
    {
        if (string.IsNullOrWhiteSpace(template)) return "";
        var path = template.Trim();
        if (path.Contains("://", StringComparison.Ordinal) && Uri.TryCreate(path, UriKind.Absolute, out var uri))
            path = string.IsNullOrEmpty(uri.Query) ? uri.AbsolutePath : uri.AbsolutePath + uri.Query;
        return AttackSurfaceMapper.TemplatizePath(path);
    }

    private static BacCoverageGap DescribeGap(
        string method, string template, AttackSurfaceEndpoint ep, AuthzShadowSkip? skip)
    {
        var reason = ep.Auth.Required
            ? "Requires auth but has no declared intent and no cross-identity replay yet."
            : "No declared intent and no cross-identity replay yet.";
        var priority = ep.TestPriority;

        switch (skip?.Kind)
        {
            case "safety":
                reason = "Skipped because safetyMode is safe; raise to active only if this write should be compared.";
                priority = "low";
                break;
            case "nonSuccess":
                reason = "The browser called this endpoint but the owner response was not a success, so it was not replayed.";
                priority = "low";
                break;
            case "resourceType":
                reason = "Seen in traffic but skipped because of resource type.";
                priority = "low";
                break;
            case "thirdParty":
                reason = "Skipped as a third-party host (skippedThirdParty).";
                priority = "low";
                break;
        }

        return new BacCoverageGap
        {
            Method = method,
            UrlTemplate = template,
            AuthRequired = ep.Auth.Required,
            TestPriority = priority,
            Reason = reason,
            SkipKind = skip?.Kind
        };
    }

    public string ToMarkdown()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# BAC Coverage Report — {Host}");
        sb.AppendLine();
        sb.AppendLine($"Generated: {GeneratedAt:u}");
        sb.AppendLine();
        sb.AppendLine("## Scope");
        sb.AppendLine($"- Attack surface endpoints (method+template): {AttackSurfaceEndpointCount}");
        sb.AppendLine($"- Identities known to the access model: {Identities.Count}" +
            (Identities.Count > 0 ? $" ({string.Join(", ", Identities.Select(i => i.Name))})" : ""));
        sb.AppendLine();
        sb.AppendLine("## Coverage");
        sb.AppendLine($"- {CoverageNumerator} / {CoverageDenominator} resources classified and/or cross-identity tested (testedPercent {CoveragePercent.ToString("0.0", CultureInfo.InvariantCulture)}%)");
        sb.AppendLine();
        sb.AppendLine("## Findings by verdict");
        if (FindingsByVerdict.Count == 0)
        {
            sb.AppendLine("- No Live Authz Shadow results yet.");
        }
        else
        {
            foreach (var (verdict, findings) in FindingsByVerdict.OrderByDescending(kv => kv.Value.Count))
            {
                sb.AppendLine($"### {verdict} ({findings.Count})");
                foreach (var f in findings.Take(20))
                    sb.AppendLine($"- {f.Method} {f.UrlTemplate} — via peer \"{f.Peer}\" ({f.Confidence}, {f.IntentAlignment}): owner {f.OwnerStatus}/{f.OwnerBodyLength}b vs peer {f.PeerStatus}/{f.PeerBodyLength}b. {f.Reason}");
                if (findings.Count > 20)
                    sb.AppendLine($"- (+{findings.Count - 20} more)");
                sb.AppendLine();
            }
        }
        sb.AppendLine("## Gaps");
        if (Gaps.Count == 0)
        {
            sb.AppendLine("- No gaps — every known resource is classified or has been tested.");
        }
        else
        {
            foreach (var g in Gaps.Take(30))
                sb.AppendLine($"- {g.Method} {g.UrlTemplate}{(g.AuthRequired ? " (auth required)" : "")} — priority {g.TestPriority} — {g.Reason}");
            if (Gaps.Count > 30)
                sb.AppendLine($"- (+{Gaps.Count - 30} more)");
        }
        sb.AppendLine();
        sb.AppendLine("## Next actions");
        foreach (var action in NextActions)
            sb.AppendLine($"- {action}");

        return sb.ToString();
    }
}
