namespace Trowser.Security.RaceLab;

public static class RaceLabAnalyzer
{
    public static List<UnifiedSecurityFinding> Analyze(
        RaceLabProfile profile,
        IReadOnlyList<RaceLabTimelineEntry> baseline,
        IReadOnlyList<RaceLabTimelineEntry> timeline,
        RaceLabSyncResult? sync)
    {
        var findings = new List<UnifiedSecurityFinding>();
        findings.AddRange(AnalyzeReliability(baseline, timeline, profile.Name));
        findings.AddRange(AnalyzeDuplicateActions(baseline, timeline, profile.Name, sync));
        findings.AddRange(AnalyzeReadbackSideEffects(baseline, timeline, profile.Name, sync));
        findings.AddRange(AnalyzeCompetingActions(baseline, timeline, profile.Name, sync));
        findings.AddRange(AnalyzeCheckUseInterference(baseline, timeline, profile.Name, sync));
        findings.AddRange(AnalyzeResponsePatterns(baseline, timeline, profile.Name, sync));

        return findings;
    }

    private static IEnumerable<UnifiedSecurityFinding> AnalyzeResponsePatterns(
        IReadOnlyList<RaceLabTimelineEntry> baseline,
        IReadOnlyList<RaceLabTimelineEntry> timeline,
        string profileName,
        RaceLabSyncResult? sync)
    {
        foreach (var entry in baseline.Concat(timeline))
        {
            if (string.IsNullOrWhiteSpace(entry.ResponsePattern))
                continue;

            if (!string.IsNullOrWhiteSpace(entry.ResponsePatternError))
            {
                yield return UnifiedSecurityFinding.Create(
                    "response-pattern",
                    "Invalid response pattern regex",
                    "low",
                    SecurityConfidence.Tentative,
                    entry.Url,
                    entry.Method,
                    evidence: entry.ResponsePatternError,
                    tier: SecurityFindingTier.Informational,
                    extra: MergeExtra(PatternExtra(entry), profileName, sync));
                continue;
            }

            if (entry.ResponsePatternMatched == false)
            {
                yield return UnifiedSecurityFinding.Create(
                    "response-pattern",
                    "Response body did not match expected pattern",
                    "medium",
                    SecurityConfidence.Likely,
                    entry.Url,
                    entry.Method,
                    evidence: $"Pattern \"{entry.ResponsePattern}\" not found in {entry.Phase} response (HTTP {entry.Status}).",
                    tier: SecurityFindingTier.Exploitable,
                    extra: MergeExtra(PatternExtra(entry), profileName, sync));
            }
        }

        foreach (var group in timeline
                     .Where(e => e.Phase == "burst" && !string.IsNullOrWhiteSpace(e.ResponsePattern))
                     .GroupBy(e => KeyForRequest(e)))
        {
            var matched = group.Count(e => e.ResponsePatternMatched == true);
            var failed = group.Count(e => e.ResponsePatternMatched == false);
            if (matched <= 0 || failed <= 0)
                continue;

            var first = group.First();
            yield return UnifiedSecurityFinding.Create(
                "response-pattern",
                "Inconsistent response pattern under concurrent burst",
                "medium",
                SecurityConfidence.Likely,
                first.Url,
                first.Method,
                evidence:
                    $"Pattern \"{first.ResponsePattern}\" matched {matched}/{group.Count()} burst response(s) " +
                    $"({failed} mismatch(es)) — possible race/thread-safety issue.",
                tier: SecurityFindingTier.Exploitable,
                extra: MergeExtra(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["requestKey"] = group.Key,
                    ["matchedCount"] = matched,
                    ["mismatchCount"] = failed,
                    ["pattern"] = first.ResponsePattern
                }, profileName, sync));
        }
    }

    private static Dictionary<string, object?> PatternExtra(RaceLabTimelineEntry entry) =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["session"] = entry.Session,
            ["phase"] = entry.Phase,
            ["pattern"] = entry.ResponsePattern,
            ["matched"] = entry.ResponsePatternMatched
        };

    private static IEnumerable<UnifiedSecurityFinding> AnalyzeReliability(
        IReadOnlyList<RaceLabTimelineEntry> baseline,
        IReadOnlyList<RaceLabTimelineEntry> timeline,
        string profileName)
    {
        foreach (var entry in baseline.Concat(timeline))
        {
            if (entry.Status >= 500)
            {
                yield return UnifiedSecurityFinding.Create(
                    "reliability",
                    "Server error during Race Lab request",
                    "medium",
                    SecurityConfidence.Tentative,
                    entry.Url,
                    entry.Method,
                    evidence: $"HTTP {entry.Status} in {entry.Phase} (session {entry.Session}).",
                    tier: SecurityFindingTier.Exploitable,
                    extra: MergeExtra(TimelineExtra(entry), profileName, null));
            }

            if (entry.Error != null)
            {
                yield return UnifiedSecurityFinding.Create(
                    "reliability",
                    "Transport error during Race Lab request",
                    "low",
                    SecurityConfidence.Tentative,
                    entry.Url,
                    entry.Method,
                    evidence: entry.Error,
                    tier: SecurityFindingTier.Informational,
                    extra: MergeExtra(TimelineExtra(entry), profileName, null));
            }
        }

        foreach (var group in timeline
                     .Where(e => e.Phase == "burst" && e.Accepted)
                     .GroupBy(e => KeyForRequest(e)))
        {
            var baselineEntry = baseline.FirstOrDefault(b => KeyForRequest(b) == group.Key);
            if (baselineEntry != null && !baselineEntry.Accepted)
            {
                yield return UnifiedSecurityFinding.Create(
                    "reliability",
                    "Accepted in burst but rejected in baseline",
                    "medium",
                    SecurityConfidence.Likely,
                    group.First().Url,
                    group.First().Method,
                    evidence: "Baseline was not 2xx but burst accepted one or more responses.",
                    tier: SecurityFindingTier.Exploitable,
                    extra: MergeExtra(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["baselineStatus"] = baselineEntry.Status,
                        ["burstAcceptedCount"] = group.Count()
                    }, profileName, null));
            }
        }
    }

    private static IEnumerable<UnifiedSecurityFinding> AnalyzeDuplicateActions(
        IReadOnlyList<RaceLabTimelineEntry> baseline,
        IReadOnlyList<RaceLabTimelineEntry> timeline,
        string profileName,
        RaceLabSyncResult? sync)
    {
        var mutateGroups = timeline
            .Where(e => e.Phase == "burst" && RaceLabRoles.IsRaceCandidate(e.Role))
            .GroupBy(e => KeyForRequest(e))
            .Where(g => g.Count() > 1);

        foreach (var group in mutateGroups)
        {
            var accepted = group.Where(e => e.Accepted).ToList();
            var baselineEntry = baseline.FirstOrDefault(b =>
                RaceLabRoles.IsRaceCandidate(b.Role)
                && KeyForRequest(b) == group.Key);
            var baselineAccepted = baseline.Count(b =>
                RaceLabRoles.IsRaceCandidate(b.Role)
                && KeyForRequest(b) == group.Key
                && b.Accepted);

            if (!ExceedsBaseline(accepted.Count, baselineAccepted))
                continue;

            var distinctHashes = accepted.Select(a => a.BodyHash).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var varyingIds = SideEffectIds.Varying(accepted.Select(IdsOf).ToList());

            if (varyingIds.Count == 0
                && distinctHashes <= 1
                && baselineEntry != null
                && baselineEntry.Accepted
                && accepted.All(a => string.Equals(a.BodyHash, baselineEntry.BodyHash, StringComparison.OrdinalIgnoreCase)))
                continue;

            var (confidence, severity, title) = GradeDuplicateFinding(
                accepted.Count, baselineAccepted, distinctHashes, varyingIds.Count);

            var idNote = varyingIds.Count == 0
                ? "no varying side-effect ids"
                : "varying side-effect ids: " + string.Join(", ", varyingIds.Take(6));

            yield return UnifiedSecurityFinding.Create(
                "race-condition",
                title,
                severity,
                confidence,
                group.First().Url,
                group.First().Method,
                evidence:
                    $"Baseline accepted {baselineAccepted}; burst accepted {accepted.Count}/{group.Count()} " +
                    $"(distinct body hashes: {distinctHashes}, {idNote}).",
                tier: SecurityFindingTier.Exploitable,
                extra: MergeExtra(BurstGroupExtra(group.Key, accepted, baselineAccepted, varyingIds), profileName, sync));
        }
    }

    /// <summary>
    /// Mutate responses are often a fixed <c>{"ok":true}</c> while the new order id only shows up on a later read.
    /// A check-role readback that lists more side-effect ids than the sequential baseline is that signal.
    /// </summary>
    private static IEnumerable<UnifiedSecurityFinding> AnalyzeReadbackSideEffects(
        IReadOnlyList<RaceLabTimelineEntry> baseline,
        IReadOnlyList<RaceLabTimelineEntry> timeline,
        string profileName,
        RaceLabSyncResult? sync)
    {
        var acceptedMutates = timeline.Count(e =>
            e.Phase == "burst" && e.Role == RaceLabRoles.Mutate && e.Accepted);
        if (acceptedMutates < 2)
            yield break;

        var mutateVarying = SideEffectIds.Varying(
            timeline.Where(e => e.Phase == "burst" && e.Role == RaceLabRoles.Mutate && e.Accepted)
                .Select(IdsOf).ToList());
        if (mutateVarying.Count > 0)
            yield break;

        foreach (var group in timeline.Where(e => e.Phase == "burst" && e.Role == RaceLabRoles.Check && e.Accepted)
                     .GroupBy(KeyForRequest))
        {
            var baselineIds = new HashSet<string>(
                baseline.Where(b => b.Role == RaceLabRoles.Check && b.Accepted && KeyForRequest(b) == group.Key)
                    .SelectMany(IdsOf),
                StringComparer.OrdinalIgnoreCase);
            var burstIds = new HashSet<string>(group.SelectMany(IdsOf), StringComparer.OrdinalIgnoreCase);
            var added = burstIds.Where(id => !baselineIds.Contains(id)).ToList();
            var flag = added.Count >= 2 || (added.Count >= 1 && baselineIds.Count > 0);
            if (!flag)
                continue;

            var shown = added.Take(8).ToList();
            var sample = group.First();
            yield return UnifiedSecurityFinding.Create(
                "race-condition",
                "Readback listed more side-effect ids than the sequential baseline",
                added.Count >= 2 ? "high" : "medium",
                added.Count >= 2 ? SecurityConfidence.Confirmed : SecurityConfidence.Likely,
                sample.Url,
                sample.Method,
                evidence:
                    $"Check readback gained {added.Count} side-effect id(s) during a burst with {acceptedMutates} accepted mutate(s): " +
                    string.Join(", ", shown) + ".",
                tier: SecurityFindingTier.Exploitable,
                extra: MergeExtra(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["requestKey"] = group.Key,
                    ["baselineIdCount"] = baselineIds.Count,
                    ["burstIdCount"] = burstIds.Count,
                    ["addedIds"] = added
                }, profileName, sync));
        }
    }

    private static IEnumerable<UnifiedSecurityFinding> AnalyzeCompetingActions(
        IReadOnlyList<RaceLabTimelineEntry> baseline,
        IReadOnlyList<RaceLabTimelineEntry> timeline,
        string profileName,
        RaceLabSyncResult? sync)
    {
        foreach (var batch in timeline.Where(e => e.Phase == "burst").GroupBy(e => e.BatchIndex))
        {
            var acceptedMutates = batch
                .Where(e => e.Role == RaceLabRoles.Mutate && e.Accepted)
                .GroupBy(e => KeyForRequest(e))
                .ToList();

            if (acceptedMutates.Count < 2)
                continue;

            var confidence = acceptedMutates.Any(g => SideEffectIds.Varying(g.Select(IdsOf).ToList()).Count >= 1)
                ? SecurityConfidence.Confirmed
                : SecurityConfidence.Likely;

            yield return UnifiedSecurityFinding.Create(
                "race-condition",
                "Competing mutate actions both accepted in the same batch",
                "high",
                confidence,
                endpoint: batch.First().Url,
                method: batch.First().Method,
                evidence: $"{acceptedMutates.Count} distinct mutate request(s) accepted concurrently in batch {batch.Key}.",
                tier: SecurityFindingTier.Exploitable,
                extra: MergeExtra(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["batchIndex"] = batch.Key,
                    ["acceptedEndpoints"] = acceptedMutates.Select(g => g.First().Url).ToList()
                }, profileName, sync));
        }
    }

    private static IEnumerable<UnifiedSecurityFinding> AnalyzeCheckUseInterference(
        IReadOnlyList<RaceLabTimelineEntry> baseline,
        IReadOnlyList<RaceLabTimelineEntry> timeline,
        string profileName,
        RaceLabSyncResult? sync)
    {
        var checkBaseline = baseline
            .Where(b => b.Role == RaceLabRoles.Check)
            .ToDictionary(KeyForRequest, b => b, StringComparer.OrdinalIgnoreCase);

        foreach (var batch in timeline.Where(e => e.Phase == "burst").GroupBy(e => e.BatchIndex))
        {
            var checkEntries = batch.Where(e => e.Role == RaceLabRoles.Check).ToList();
            if (checkEntries.Count == 0)
                continue;

            foreach (var check in checkEntries)
            {
                var key = KeyForRequest(check);
                if (!checkBaseline.TryGetValue(key, out var before))
                    continue;

                var afterBatch = timeline
                    .Where(e => e.Phase == "burst" && e.BatchIndex > batch.Key && e.Role == RaceLabRoles.Check)
                    .LastOrDefault(e => KeyForRequest(e) == key);

                var after = afterBatch ?? check;

                if (before.Accepted == check.Accepted && check.Accepted == after.Accepted)
                    continue;

                yield return UnifiedSecurityFinding.Create(
                    "toctou",
                    "Check/use state changed during concurrent burst",
                    "medium",
                    SecurityConfidence.Likely,
                    check.Url,
                    check.Method,
                    evidence:
                        $"Check request acceptance shifted (baseline={before.Accepted}, during={check.Accepted}, after={after.Accepted}).",
                    tier: SecurityFindingTier.Exploitable,
                    extra: MergeExtra(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["batchIndex"] = batch.Key,
                        ["baselineAccepted"] = before.Accepted,
                        ["duringAccepted"] = check.Accepted,
                        ["afterAccepted"] = after.Accepted
                    }, profileName, sync));
            }
        }
    }

    private static Dictionary<string, object?> MergeExtra(
        Dictionary<string, object?> extra,
        string profileName,
        RaceLabSyncResult? sync)
    {
        extra["profile"] = profileName;
        if (sync != null)
            extra["dispatchOffsetMs"] = sync.DispatchOffsetMs;
        return extra;
    }

    private static bool ExceedsBaseline(int concurrentAccepted, int sequentialAccepted) =>
        concurrentAccepted > sequentialAccepted
        || (concurrentAccepted >= 2 && sequentialAccepted <= 1);

    private static (string confidence, string severity, string title) GradeDuplicateFinding(
        int acceptedCount,
        int baselineAccepted,
        int distinctHashes,
        int distinctResources)
    {
        if (distinctResources >= 1)
            return (SecurityConfidence.Confirmed, "high", "Duplicate single-use action produced distinct resources");

        if (distinctHashes >= 2 || acceptedCount >= baselineAccepted + 2)
            return (SecurityConfidence.Likely, "medium", "Duplicate action accepted more often than baseline");

        return (SecurityConfidence.Tentative, "medium", "Possible duplicate action (identical success responses)");
    }

    private static string KeyForRequest(RaceLabTimelineEntry e) =>
        $"{e.Session}|{e.Method}|{e.Url}|{e.Role}";

    private static Dictionary<string, object?> TimelineExtra(RaceLabTimelineEntry entry) =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["session"] = entry.Session,
            ["phase"] = entry.Phase,
            ["status"] = entry.Status,
            ["latencyMs"] = entry.LatencyMs
        };

    private static IReadOnlyList<string> IdsOf(RaceLabTimelineEntry e)
    {
        if (e.SideEffectIds is { Count: > 0 })
            return e.SideEffectIds;
        if (!string.IsNullOrWhiteSpace(e.ResourceId))
            return [e.ResourceId];
        return [];
    }

    private static Dictionary<string, object?> BurstGroupExtra(
        string key,
        IReadOnlyList<RaceLabTimelineEntry> accepted,
        int baselineAccepted,
        IReadOnlyList<string> varyingIds) =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["requestKey"] = key,
            ["baselineAcceptedCount"] = baselineAccepted,
            ["burstAcceptedCount"] = accepted.Count,
            ["varyingSideEffectIds"] = varyingIds,
            ["timeline"] = accepted.Select(RaceLabJson.TimelineEntryToApi).ToList()
        };
}
