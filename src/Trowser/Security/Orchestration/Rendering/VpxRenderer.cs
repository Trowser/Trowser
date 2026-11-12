using System.Text;
using System.Text.Json;
using Trowser.Security.ChainEngine;
using Trowser.Security.Vpx;

namespace Trowser.Security.Orchestration.Rendering;

/// <summary>
/// Single rendering pipeline: VPX document → compact / summary / markdown / SARIF.
/// All playbook output passes through here.
/// </summary>
public static class VpxRenderer
{
    /// <summary>Render to vpx-compact: evidence summarised, no raw bodies.</summary>
    public static object ToCompact(object vpxFull)
    {
        if (vpxFull is not Dictionary<string, object?> doc)
            return vpxFull;

        var compact = new Dictionary<string, object?>(doc);
        var findings = ExtractFindings(doc);

        compact["findings"] = findings.Select(fd =>
        {
            var slim = new Dictionary<string, object?>(fd);
            slim.Remove("trace");
            return (object)slim;
        }).ToList();

        return compact;
    }

    /// <summary>
    /// Render to vpx-summary: per-category counts, top-N findings
    /// (id, severity, title, suggestedProof.workflowId), nextActions. No evidence.
    /// Target: &lt; 2 KB for LLM first call.
    /// </summary>
    public static object ToSummary(object vpxFull, List<NextAction>? nextActions = null, int topN = 10)
    {
        if (vpxFull is not Dictionary<string, object?> doc)
            return new Dictionary<string, object?> { ["error"] = "Invalid VPX document" };

        var findings = ExtractFindings(doc);

        var bySeverity = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in findings)
        {
            var sev = GetString(f, "severity") ?? "info";
            bySeverity.TryGetValue(sev, out var c);
            bySeverity[sev] = c + 1;
        }

        var byKind = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in findings)
        {
            var kind = GetString(f, "kind") ?? "unknown";
            byKind.TryGetValue(kind, out var c);
            byKind[kind] = c + 1;
        }

        var topFindings = findings
            .OrderByDescending(f => SeverityRank(GetString(f, "severity")))
            .Take(topN)
            .Select(f => new Dictionary<string, object?>
            {
                ["id"] = GetString(f, "id"),
                ["severity"] = GetString(f, "severity"),
                ["title"] = GetString(f, "title"),
                ["kind"] = GetString(f, "kind"),
                ["owasp"] = GetString(f, "owasp"),
                ["cwe"] = f.TryGetValue("cwe", out var cweVal) ? cweVal : null,
                ["surfaceId"] = GetString(f, "surfaceId")
            })
            .ToList();

        var summary = new Dictionary<string, object?>
        {
            ["vpxVersion"] = "1.1",
            ["profile"] = "summary",
            ["totalFindings"] = findings.Count,
            ["bySeverity"] = bySeverity,
            ["byKind"] = byKind,
            ["topFindings"] = topFindings
        };

        if (doc.TryGetValue("target", out var target))
            summary["target"] = target;

        if (nextActions is { Count: > 0 })
            summary["nextActions"] = nextActions;

        return summary;
    }

    /// <summary>Render to markdown: human-readable report with severities and evidence.</summary>
    public static string ToMarkdown(object vpxFull, string playbookTitle = "Security Assessment", int suppressedCount = 0)
    {
        if (vpxFull is not Dictionary<string, object?> doc)
            return "## Error\n\nInvalid VPX document.";

        var sb = new StringBuilder();
        var findings = ExtractFindings(doc);
        var scan = ExtractScan(doc);
        var title = GetString(scan, "playbookTitle") ?? playbookTitle;
        var host = ExtractTargetHost(doc);
        var bySeverity = CountBySeverity(findings);

        sb.AppendLine($"# Security Assessment{(host != null ? $": {host}" : "")}");
        sb.AppendLine();

        var metaParts = new List<string> { $"**Scan:** {title}" };
        var scanDate = FormatScanDate(scan, doc);
        if (scanDate != null) metaParts.Add($"**Date:** {scanDate}");
        var duration = FormatDuration(scan, doc);
        if (duration != null) metaParts.Add($"**Duration:** {duration}");
        sb.AppendLine(string.Join(" | ", metaParts));

        var detailParts = new List<string>();
        var safetyMode = GetString(scan, "safetyMode");
        if (safetyMode != null) detailParts.Add($"**Safety Mode:** {safetyMode}");
        var depth = GetString(scan, "depth");
        if (depth != null) detailParts.Add($"**Depth:** {depth}");
        var coverage = FormatCoverage(scan);
        if (coverage != null) detailParts.Add($"**Coverage:** {coverage}");
        if (detailParts.Count > 0)
            sb.AppendLine(string.Join(" | ", detailParts));

        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine("| Severity | Count |");
        sb.AppendLine("|----------|-------|");
        foreach (var sev in new[] { "critical", "high", "medium", "low", "info" })
            sb.AppendLine($"| {char.ToUpper(sev[0]) + sev[1..]} | {bySeverity.GetValueOrDefault(sev)} |");

        var riskScore = ComputeRiskScore(bySeverity);
        var rawScore = ComputeRawRiskScore(findings);
        sb.AppendLine();
        sb.AppendLine($"**Risk score:** {riskScore} (weighted reporting severities; cache-map indications capped to info/low until confirmed)");
        if (rawScore > riskScore)
            sb.AppendLine($"**Scanner-weighted score (uncapped):** {rawScore} — use only for triage; confirm cache-map with cache-pollution-scan before escalating.");

        AppendStepExecutionSection(sb, scan);

        if (suppressedCount > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"*{suppressedCount} finding(s) suppressed by cross-playbook deduplication — see earlier playbook results.*");
        }

        sb.AppendLine();
        sb.AppendLine("## Findings");
        sb.AppendLine();

        if (findings.Count == 0)
        {
            sb.AppendLine(suppressedCount > 0
                ? "No new findings (all deduplicated)."
                : "No findings discovered.");
            return sb.ToString();
        }

        foreach (var f in findings.OrderByDescending(f => SeverityRank(GetString(f, "severity"))))
        {
            var sev = (GetString(f, "severity") ?? "info").ToUpperInvariant();
            var kind = GetString(f, "kind") ?? "unknown";
            var titleText = TextEncodingFix.FixMojibake(GetString(f, "title")) ?? GetString(f, "title") ?? "Untitled";
            var param = GetString(f, "param");
            var headingSuffix = param ?? GetString(f, "surfaceId") ?? "";
            var heading = string.IsNullOrEmpty(headingSuffix)
                ? $"### [{sev}] {FormatKind(kind)} — {titleText}"
                : $"### [{sev}] {FormatKind(kind)} — {headingSuffix}";

            sb.AppendLine(heading);
            sb.AppendLine();
            sb.AppendLine($"- {SeverityBadge(sev.ToLowerInvariant())} **{titleText}**");

            var owasp = GetString(f, "owasp");
            if (owasp != null) sb.AppendLine($"  - **OWASP:** {owasp}");

            var surfaceId = GetString(f, "surfaceId");
            if (surfaceId != null) sb.AppendLine($"  - **Surface:** `{surfaceId}`");
            if (param != null) sb.AppendLine($"  - **Parameter:** `{param}`");

            var description = TextEncodingFix.FixMojibake(GetString(f, "description"));
            if (description != null)
                sb.AppendLine($"  - **Details:** {description}");

            var status = GetString(f, "status");
            if (!string.IsNullOrEmpty(status))
                sb.AppendLine($"  - **Status:** {status}");

            var claimedSeverity = GetString(f, "claimedSeverity");
            if (!string.IsNullOrEmpty(claimedSeverity))
                sb.AppendLine($"  - **Scanner severity (before cap):** {claimedSeverity.ToUpperInvariant()}");

            var remediation = GetString(f, "remediation");
            if (remediation != null)
                sb.AppendLine($"  - **Fix:** {remediation}");

            var reference = GetString(f, "reference");
            if (reference != null)
                sb.AppendLine($"  - **Reference:** {reference}");

            sb.AppendLine();
        }

        return sb.ToString();
    }

    /// <summary>Render to SARIF 2.1.0 — VPX findings → SARIF runs[].results[].</summary>
    public static object ToSarif(object vpxFull, string playbookId = "trowser", int suppressedCount = 0)
    {
        if (vpxFull is not Dictionary<string, object?> doc)
            return new Dictionary<string, object?> { ["error"] = "Invalid VPX document" };

        var findings = ExtractFindings(doc);
        var surfaces = ExtractSurfaces(doc);
        var proofs = ExtractProofs(doc);
        var baseUrl = ExtractBaseUrl(doc);
        var scan = ExtractScan(doc);
        var rules = BuildSarifRules(findings);
        var taxonomies = BuildSarifTaxonomies(findings);

        var results = new List<object>();
        foreach (var f in findings)
        {
            var kind = GetString(f, "kind") ?? "unknown";
            var surfaceId = GetString(f, "surfaceId");
            var param = GetString(f, "param");
            var endpointUri = ResolveEndpointUri(baseUrl, surfaces, surfaceId);
            var fqn = BuildFullyQualifiedName(surfaces, surfaceId, param);
            var description = GetString(f, "description");
            var remediation = GetString(f, "remediation");
            var findingId = GetString(f, "id");

            var location = new Dictionary<string, object?>
            {
                ["logicalLocations"] = new List<object>
                {
                    new Dictionary<string, object?>
                    {
                        ["name"] = surfaceId ?? endpointUri ?? "unknown",
                        ["fullyQualifiedName"] = fqn,
                        ["kind"] = "endpoint"
                    }
                }
            };

            if (endpointUri != null)
            {
                location["physicalLocation"] = new Dictionary<string, object?>
                {
                    ["artifactLocation"] = new Dictionary<string, object?>
                    {
                        ["uri"] = endpointUri,
                        ["uriBaseId"] = "%BASEURL%"
                    }
                };
            }

            var result = new Dictionary<string, object?>
            {
                ["ruleId"] = kind,
                ["level"] = SarifLevel(GetString(f, "severity")),
                ["message"] = new Dictionary<string, object?>
                {
                    ["text"] = GetString(f, "title"),
                    ["markdown"] = BuildResultMarkdown(f)
                },
                ["locations"] = new List<object> { location },
                ["properties"] = new Dictionary<string, object?>
                {
                    ["id"] = findingId,
                    ["param"] = param,
                    ["severity"] = GetString(f, "severity"),
                    ["owasp"] = GetString(f, "owasp"),
                    ["cwe"] = f.TryGetValue("cwe", out var cweVal) ? cweVal : null,
                    ["surfaceId"] = surfaceId,
                    ["vpxFingerprint"] = f.TryGetValue("fingerprint", out var fp) ? fp : null
                }
            };

            if (fp is Dictionary<string, object?> fpDict &&
                fpDict.TryGetValue("value", out var fpVal) && fpVal is string fpStr)
            {
                result["partialFingerprints"] = new Dictionary<string, object?>
                {
                    ["vpx-fingerprint-1"] = fpStr
                };
            }

            var taxa = BuildResultTaxa(f);
            if (taxa.Count > 0)
                result["taxa"] = taxa;

            if (remediation != null)
            {
                result["fixes"] = new List<object>
                {
                    new Dictionary<string, object?>
                    {
                        ["description"] = new Dictionary<string, object?>
                        {
                            ["text"] = remediation,
                            ["markdown"] = remediation
                        }
                    }
                };
            }

            var related = BuildRelatedLocations(f, proofs, endpointUri, findingId);
            if (related.Count > 0)
                result["relatedLocations"] = related;

            results.Add(result);
        }

        var driver = new Dictionary<string, object?>
        {
            ["name"] = "Trowser",
            ["informationUri"] = "https://trowser.dev",
            ["semanticVersion"] = "1.0.0",
            ["rules"] = rules
        };

        var run = new Dictionary<string, object?>
        {
            ["tool"] = new Dictionary<string, object?> { ["driver"] = driver },
            ["results"] = results,
            ["taxonomies"] = taxonomies,
            ["invocations"] = BuildInvocations(scan, doc, results.Count == 0 && suppressedCount == 0),
            ["originalUriBaseIds"] = baseUrl != null
                ? new Dictionary<string, object?>
                {
                    ["BASEURL"] = new Dictionary<string, object?> { ["uri"] = baseUrl.TrimEnd('/') + "/" }
                }
                : null
        };

        if (suppressedCount > 0)
        {
            run["properties"] = new Dictionary<string, object?>
            {
                ["trowser:deduplication"] = new Dictionary<string, object?>
                {
                    ["suppressedCount"] = suppressedCount,
                    ["suppressedFindings"] = suppressedCount,
                    ["note"] = $"{suppressedCount} finding(s) were suppressed by cross-playbook deduplication. " +
                               $"Run this playbook first (or in isolation) to see all findings. " +
                               $"See response.suppressedFindings[] for ids/titles."
                }
            };

            if (results.Count == 0)
            {
                results.Add(new Dictionary<string, object?>
                {
                    ["ruleId"] = "trowser/dedup-info",
                    ["level"] = "none",
                    ["message"] = new Dictionary<string, object?>
                    {
                        ["text"] = $"All {suppressedCount} finding(s) were suppressed by cross-playbook deduplication. " +
                                   $"These findings were already reported by a previous playbook run in this session."
                    },
                    ["suppressions"] = new List<object>
                    {
                        new Dictionary<string, object?>
                        {
                            ["kind"] = "inSource",
                            ["justification"] = "Cross-playbook deduplication: findings already reported by a prior playbook run."
                        }
                    }
                });
            }
        }

        return new Dictionary<string, object?>
        {
            ["version"] = "2.1.0",
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["runs"] = new List<object> { run }
        };
    }

    /// <summary>Merge multiple VPX documents into one for rendering or export.</summary>
    public static Dictionary<string, object?> MergeDocuments(IEnumerable<object> documents)
    {
        var merged = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["vpxVersion"] = "1.0",
            ["documentId"] = Guid.NewGuid().ToString(),
            ["createdAt"] = DateTime.UtcNow.ToString("o"),
            ["updatedAt"] = DateTime.UtcNow.ToString("o"),
            ["surfaces"] = new List<object>(),
            ["findings"] = new List<object>(),
            ["proofs"] = new List<object>(),
            ["verdicts"] = new List<object>()
        };

        var seenFindingIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenSurfaceIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var surfaces = (List<object>)merged["surfaces"]!;
        var findings = (List<object>)merged["findings"]!;
        var proofs = (List<object>)merged["proofs"]!;
        var verdicts = (List<object>)merged["verdicts"]!;

        foreach (var docObj in documents)
        {
            if (docObj is not Dictionary<string, object?> doc) continue;

            if (merged["target"] == null && doc.TryGetValue("target", out var target))
                merged["target"] = target;

            foreach (var s in ExtractSurfaceList(doc))
            {
                var id = GetString(s, "id");
                if (id == null || !seenSurfaceIds.Add(id)) continue;
                surfaces.Add(s);
            }

            foreach (var f in ExtractFindings(doc))
            {
                var id = GetString(f, "id");
                if (id == null || !seenFindingIds.Add(id)) continue;
                findings.Add(f);
            }

            foreach (var p in ExtractProofs(doc))
            {
                proofs.Add(p);
            }

            foreach (var v in ExtractVerdicts(doc))
            {
                verdicts.Add(v);
            }
        }

        return merged;
    }

    #region Helpers

    private static List<Dictionary<string, object?>> ExtractFindings(Dictionary<string, object?> doc)
    {
        if (!doc.TryGetValue("findings", out var findingsObj) || findingsObj == null)
            return [];

        if (findingsObj is IEnumerable<Dictionary<string, object?>> typedList)
            return typedList.ToList();

        if (findingsObj is List<object> list)
            return list.OfType<Dictionary<string, object?>>().ToList();

        if (findingsObj is JsonElement { ValueKind: JsonValueKind.Array } jsonArr)
        {
            var result = new List<Dictionary<string, object?>>();
            foreach (var item in jsonArr.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object)
                    result.Add(JsonElementToDict(item));
            }
            return result;
        }

        return [];
    }

    private static List<Dictionary<string, object?>> ExtractProofs(Dictionary<string, object?> doc)
    {
        if (!doc.TryGetValue("proofs", out var proofsObj) || proofsObj == null)
            return [];

        if (proofsObj is IEnumerable<Dictionary<string, object?>> typedList)
            return typedList.ToList();

        if (proofsObj is List<object> list)
            return list.OfType<Dictionary<string, object?>>().ToList();

        if (proofsObj is JsonElement { ValueKind: JsonValueKind.Array } jsonArr)
        {
            var result = new List<Dictionary<string, object?>>();
            foreach (var item in jsonArr.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object)
                    result.Add(JsonElementToDict(item));
            }
            return result;
        }

        return [];
    }

    private static List<Dictionary<string, object?>> ExtractVerdicts(Dictionary<string, object?> doc)
    {
        if (!doc.TryGetValue("verdicts", out var verdictsObj) || verdictsObj == null)
            return [];

        if (verdictsObj is IEnumerable<Dictionary<string, object?>> typedList)
            return typedList.ToList();

        if (verdictsObj is List<object> list)
            return list.OfType<Dictionary<string, object?>>().ToList();

        if (verdictsObj is JsonElement { ValueKind: JsonValueKind.Array } jsonArr)
        {
            var result = new List<Dictionary<string, object?>>();
            foreach (var item in jsonArr.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object)
                    result.Add(JsonElementToDict(item));
            }
            return result;
        }

        return [];
    }

    private static List<Dictionary<string, object?>> ExtractSurfaceList(Dictionary<string, object?> doc)
    {
        if (!doc.TryGetValue("surfaces", out var surfacesObj) || surfacesObj == null)
            return [];

        if (surfacesObj is IEnumerable<Dictionary<string, object?>> typedList)
            return typedList.ToList();

        if (surfacesObj is List<object> list)
            return list.OfType<Dictionary<string, object?>>().ToList();

        if (surfacesObj is JsonElement { ValueKind: JsonValueKind.Array } jsonArr)
        {
            var result = new List<Dictionary<string, object?>>();
            foreach (var item in jsonArr.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object)
                    result.Add(JsonElementToDict(item));
            }
            return result;
        }

        return [];
    }

    private static Dictionary<string, Dictionary<string, object?>> ExtractSurfaces(Dictionary<string, object?> doc)
    {
        var map = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in ExtractSurfaceList(doc))
        {
            var id = GetString(s, "id");
            if (id != null)
                map[id] = s;
        }
        return map;
    }

    private static Dictionary<string, object?> ExtractScan(Dictionary<string, object?> doc)
    {
        if (doc.TryGetValue("scan", out var scanObj) && scanObj is Dictionary<string, object?> scan)
            return scan;
        if (doc.TryGetValue("scan", out scanObj) && scanObj is JsonElement { ValueKind: JsonValueKind.Object } je)
            return JsonElementToDict(je);
        return new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
    }

    private static string? ExtractBaseUrl(Dictionary<string, object?> doc)
    {
        if (!doc.TryGetValue("target", out var targetObj) || targetObj == null)
            return null;

        if (targetObj is Dictionary<string, object?> target)
            return GetString(target, "baseUrl");

        if (targetObj is JsonElement { ValueKind: JsonValueKind.Object } je &&
            je.TryGetProperty("baseUrl", out var bu) && bu.ValueKind == JsonValueKind.String)
            return bu.GetString();

        return null;
    }

    private static string? ExtractTargetHost(Dictionary<string, object?> doc)
    {
        var baseUrl = ExtractBaseUrl(doc);
        if (baseUrl == null) return null;
        return Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) ? uri.Host : baseUrl;
    }

    private static Dictionary<string, int> CountBySeverity(IReadOnlyList<Dictionary<string, object?>> findings)
    {
        var bySeverity = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["critical"] = 0,
            ["high"] = 0,
            ["medium"] = 0,
            ["low"] = 0,
            ["info"] = 0
        };

        foreach (var f in findings)
        {
            var sev = (GetString(f, "severity") ?? "info").ToLowerInvariant();
            if (!bySeverity.ContainsKey(sev))
                bySeverity[sev] = 0;
            bySeverity[sev]++;
        }

        return bySeverity;
    }

    private static int ComputeRiskScore(Dictionary<string, int> bySeverity) =>
        bySeverity.GetValueOrDefault("critical") * 10 +
        bySeverity.GetValueOrDefault("high") * 5 +
        bySeverity.GetValueOrDefault("medium") * 2 +
        bySeverity.GetValueOrDefault("low");

    private static int ComputeRawRiskScore(IReadOnlyList<Dictionary<string, object?>> findings)
    {
        var byClaimed = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["critical"] = 0,
            ["high"] = 0,
            ["medium"] = 0,
            ["low"] = 0,
            ["info"] = 0
        };

        foreach (var f in findings)
        {
            var sev = GetString(f, "claimedSeverity") ?? GetString(f, "severity") ?? "info";
            sev = sev.ToLowerInvariant();
            if (!byClaimed.ContainsKey(sev))
                sev = "info";
            byClaimed[sev]++;
        }

        return ComputeRiskScore(byClaimed);
    }

    private static string? FormatScanDate(Dictionary<string, object?> scan, Dictionary<string, object?> doc)
    {
        var startedAt = GetString(scan, "startedAt") ?? GetString(doc, "createdAt");
        if (startedAt == null) return null;
        return DateTime.TryParse(startedAt, out var dt)
            ? dt.ToString("yyyy-MM-dd")
            : startedAt[..Math.Min(10, startedAt.Length)];
    }

    private static string? FormatDuration(Dictionary<string, object?> scan, Dictionary<string, object?> doc)
    {
        var startedAt = GetString(scan, "startedAt") ?? GetString(doc, "createdAt");
        var finishedAt = GetString(scan, "finishedAt") ?? GetString(doc, "updatedAt");
        if (startedAt != null && finishedAt != null &&
            DateTime.TryParse(startedAt, out var start) &&
            DateTime.TryParse(finishedAt, out var end))
        {
            var seconds = Math.Max(0, (int)Math.Round((end - start).TotalSeconds));
            return seconds < 60 ? $"{seconds}s" : $"{seconds / 60}m {seconds % 60}s";
        }

        if (scan.TryGetValue("budgetUsed", out var budgetObj))
        {
            var budget = budgetObj as Dictionary<string, object?>;
            if (budget != null && budget.TryGetValue("seconds", out var secObj))
            {
                if (secObj is int sec) return $"{sec}s";
                if (secObj is double dSec) return $"{(int)Math.Round(dSec)}s";
                if (secObj is JsonElement { ValueKind: JsonValueKind.Number } je && je.TryGetInt32(out var jSec))
                    return $"{jSec}s";
            }
        }

        return null;
    }

    private static string? FormatCoverage(Dictionary<string, object?> scan)
    {
        if (scan.TryGetValue("coverageCompleted", out var completedObj) &&
            scan.TryGetValue("coverageTotal", out var totalObj))
        {
            var completed = ToInt(completedObj);
            var total = ToInt(totalObj);
            if (total > 0)
                return $"{completed}/{total} steps completed";
        }

        var steps = ExtractSteps(scan);
        if (steps.Count == 0) return null;
        var ok = steps.Count(s => GetString(s, "status")?.Equals("ok", StringComparison.OrdinalIgnoreCase) == true);
        return $"{ok}/{steps.Count} steps completed";
    }

    private static void AppendStepExecutionSection(StringBuilder sb, Dictionary<string, object?> scan)
    {
        var steps = ExtractSteps(scan);
        if (steps.Count == 0) return;

        sb.AppendLine();
        sb.AppendLine("## Step Execution");
        sb.AppendLine();
        sb.AppendLine("| Step | Status | Duration |");
        sb.AppendLine("|------|--------|----------|");

        foreach (var step in steps)
        {
            var name = GetString(step, "name") ?? "unknown";
            var status = GetString(step, "status") ?? "unknown";
            var durationMs = ToInt(step.GetValueOrDefault("durationMs"));
            var duration = durationMs > 0 ? $"{durationMs}ms" : "—";
            sb.AppendLine($"| {name} | {status} | {duration} |");
        }
    }

    private static List<Dictionary<string, object?>> ExtractSteps(Dictionary<string, object?> scan)
    {
        if (!scan.TryGetValue("stepsExecuted", out var stepsObj) || stepsObj == null)
            return [];

        if (stepsObj is IEnumerable<Dictionary<string, object?>> typedList)
            return typedList.ToList();

        if (stepsObj is List<object> list)
            return list.OfType<Dictionary<string, object?>>().ToList();

        if (stepsObj is JsonElement { ValueKind: JsonValueKind.Array } jsonArr)
        {
            var result = new List<Dictionary<string, object?>>();
            foreach (var item in jsonArr.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object)
                    result.Add(JsonElementToDict(item));
            }
            return result;
        }

        return [];
    }

    private static List<object> BuildSarifRules(IReadOnlyList<Dictionary<string, object?>> findings)
    {
        var rules = new List<object>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var f in findings)
        {
            var kind = GetString(f, "kind") ?? "unknown";
            if (!seen.Add(kind)) continue;

            var title = GetString(f, "title") ?? FormatKind(kind);
            var description = GetString(f, "description") ?? title;
            var reference = GetString(f, "reference");
            var helpUri = reference ?? OwaspHelpUri(GetString(f, "owasp"));

            rules.Add(new Dictionary<string, object?>
            {
                ["id"] = kind,
                ["name"] = FormatKind(kind),
                ["shortDescription"] = new Dictionary<string, object?> { ["text"] = title },
                ["fullDescription"] = new Dictionary<string, object?> { ["text"] = description, ["markdown"] = description },
                ["helpUri"] = helpUri,
                ["defaultConfiguration"] = new Dictionary<string, object?>
                {
                    ["level"] = SarifLevel(GetString(f, "severity"))
                },
                ["properties"] = new Dictionary<string, object?>
                {
                    ["owasp"] = GetString(f, "owasp"),
                    ["tags"] = new[] { "security", "trowser" }
                }
            });
        }

        return rules;
    }

    private static List<object> BuildSarifTaxonomies(IReadOnlyList<Dictionary<string, object?>> findings)
    {
        var cweIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in findings)
        {
            foreach (var cwe in ExtractCweIds(f))
                cweIds.Add(cwe);
        }

        if (cweIds.Count == 0)
            return [];

        var taxa = cweIds.OrderBy(id => id, StringComparer.OrdinalIgnoreCase)
            .Select(id => new Dictionary<string, object?>
            {
                ["id"] = id,
                ["name"] = $"CWE-{id}"
            })
            .Cast<object>()
            .ToList();

        return
        [
            new Dictionary<string, object?>
            {
                ["name"] = "CWE",
                ["version"] = "4.14",
                ["informationUri"] = "https://cwe.mitre.org/",
                ["downloadUri"] = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
                ["organization"] = "MITRE",
                ["shortDescription"] = new Dictionary<string, object?> { ["text"] = "MITRE Common Weakness Enumeration" },
                ["isComprehensive"] = false,
                ["taxa"] = taxa
            }
        ];
    }

    private static List<object> BuildResultTaxa(Dictionary<string, object?> finding)
    {
        return ExtractCweIds(finding)
            .Select(id => (object)new Dictionary<string, object?> { ["id"] = id })
            .ToList();
    }

    private static IEnumerable<string> ExtractCweIds(Dictionary<string, object?> finding)
    {
        if (!finding.TryGetValue("cwe", out var cweVal) || cweVal == null)
            yield break;

        if (cweVal is string single)
        {
            foreach (var id in ParseCweId(single))
                yield return id;
            yield break;
        }

        if (cweVal is IEnumerable<string> strings)
        {
            foreach (var s in strings)
            {
                foreach (var id in ParseCweId(s))
                    yield return id;
            }
            yield break;
        }

        if (cweVal is List<object> list)
        {
            foreach (var item in list)
            {
                if (item is string s)
                {
                    foreach (var id in ParseCweId(s))
                        yield return id;
                }
            }
            yield break;
        }

        if (cweVal is JsonElement { ValueKind: JsonValueKind.Array } arr)
        {
            foreach (var item in arr.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    foreach (var id in ParseCweId(item.GetString()!))
                        yield return id;
                }
            }
        }
    }

    private static IEnumerable<string> ParseCweId(string raw)
    {
        var trimmed = raw.Trim();
        if (trimmed.StartsWith("CWE-", StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed[4..];
        if (int.TryParse(trimmed, out _))
            yield return trimmed;
    }

    private static List<object> BuildRelatedLocations(
        Dictionary<string, object?> finding,
        IReadOnlyList<Dictionary<string, object?>> proofs,
        string? endpointUri,
        string? findingId)
    {
        var related = new List<object>();
        var index = 1;

        var description = GetString(finding, "description");
        if (description != null)
        {
            related.Add(new Dictionary<string, object?>
            {
                ["id"] = index++,
                ["message"] = new Dictionary<string, object?> { ["text"] = description },
                ["physicalLocation"] = endpointUri != null
                    ? new Dictionary<string, object?> { ["artifactLocation"] = new Dictionary<string, object?> { ["uri"] = endpointUri } }
                    : null
            });
        }

        if (finding.TryGetValue("trace", out var traceObj) && traceObj is IEnumerable<object> traceList)
        {
            foreach (var item in traceList)
            {
                if (item is not string line || string.IsNullOrWhiteSpace(line)) continue;
                related.Add(new Dictionary<string, object?>
                {
                    ["id"] = index++,
                    ["message"] = new Dictionary<string, object?> { ["text"] = line },
                    ["physicalLocation"] = endpointUri != null
                        ? new Dictionary<string, object?> { ["artifactLocation"] = new Dictionary<string, object?> { ["uri"] = endpointUri } }
                        : null
                });
            }
        }

        foreach (var proof in proofs.Where(p => GetString(p, "findingId") == findingId))
        {
            var oracleEvidence = GetNestedString(proof, "oracle", "evidence");
            if (oracleEvidence == null) continue;
            related.Add(new Dictionary<string, object?>
            {
                ["id"] = index++,
                ["message"] = new Dictionary<string, object?> { ["text"] = $"Proof evidence: {oracleEvidence}" },
                ["physicalLocation"] = endpointUri != null
                    ? new Dictionary<string, object?> { ["artifactLocation"] = new Dictionary<string, object?> { ["uri"] = endpointUri } }
                    : null
            });
        }

        return related;
    }

    private static List<object> BuildInvocations(
        Dictionary<string, object?> scan,
        Dictionary<string, object?> doc,
        bool _)
    {
        var startedAt = GetString(scan, "startedAt") ?? GetString(doc, "createdAt");
        var finishedAt = GetString(scan, "finishedAt") ?? GetString(doc, "updatedAt") ?? DateTime.UtcNow.ToString("o");

        return
        [
            new Dictionary<string, object?>
            {
                ["startTimeUtc"] = startedAt ?? DateTime.UtcNow.ToString("o"),
                ["endTimeUtc"] = finishedAt,
                ["executionSuccessful"] = true
            }
        ];
    }

    private static string? ResolveEndpointUri(
        string? baseUrl,
        IReadOnlyDictionary<string, Dictionary<string, object?>> surfaces,
        string? surfaceId)
    {
        if (surfaceId != null && surfaces.TryGetValue(surfaceId, out var surface))
        {
            var route = GetString(surface, "route");
            var method = GetString(surface, "method") ?? "GET";
            if (route != null && route.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                return route;
            if (route != null && baseUrl != null)
                return CombineUrl(baseUrl, route);
        }

        if (surfaceId != null && baseUrl != null)
        {
            if (surfaceId.StartsWith("surf-", StringComparison.OrdinalIgnoreCase))
            {
                var rest = surfaceId[5..];
                var dashIdx = rest.IndexOf('-');
                if (dashIdx > 0)
                    return CombineUrl(baseUrl, "/" + rest[(dashIdx + 1)..]);
            }

            return baseUrl;
        }

        return baseUrl;
    }

    private static string? BuildFullyQualifiedName(
        IReadOnlyDictionary<string, Dictionary<string, object?>> surfaces,
        string? surfaceId,
        string? param)
    {
        if (surfaceId == null) return param;

        if (surfaces.TryGetValue(surfaceId, out var surface))
        {
            var method = GetString(surface, "method") ?? "GET";
            var route = GetString(surface, "route") ?? surfaceId;
            return param != null ? $"{method} {route} (param: {param})" : $"{method} {route}";
        }

        return param != null ? $"{surfaceId} (param: {param})" : surfaceId;
    }

    private static string CombineUrl(string baseUrl, string route)
    {
        if (route.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            return route;

        var baseTrimmed = baseUrl.TrimEnd('/');
        var routePart = route.StartsWith('/') ? route : $"/{route}";
        return $"{baseTrimmed}{routePart}";
    }

    private static string BuildResultMarkdown(Dictionary<string, object?> finding)
    {
        var parts = new List<string>();
        var title = GetString(finding, "title");
        if (title != null) parts.Add($"**{title}**");

        var description = GetString(finding, "description");
        if (description != null) parts.Add(description);

        var param = GetString(finding, "param");
        if (param != null) parts.Add($"Parameter: `{param}`");

        return string.Join("\n\n", parts);
    }

    private static string? OwaspHelpUri(string? owasp) => owasp switch
    {
        "A01" => "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/",
        "A02" => "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/",
        "A03" => "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/",
        "A04" => "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/",
        "A05" => "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/",
        _ => "https://owasp.org/www-project-top-ten/"
    };

    private static string? GetString(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var val) || val == null)
            return null;
        if (val is string s) return s;
        if (val is JsonElement { ValueKind: JsonValueKind.String } je) return je.GetString();
        return null;
    }

    private static string? GetNestedString(Dictionary<string, object?> dict, string key1, string key2)
    {
        if (!dict.TryGetValue(key1, out var val) || val == null)
            return null;

        if (val is Dictionary<string, object?> nested)
            return GetString(nested, key2);

        if (val is JsonElement { ValueKind: JsonValueKind.Object } je &&
            je.TryGetProperty(key2, out var prop) && prop.ValueKind == JsonValueKind.String)
            return prop.GetString();

        return null;
    }

    private static int ToInt(object? val)
    {
        if (val == null) return 0;
        if (val is int i) return i;
        if (val is long l) return (int)l;
        if (val is double d) return (int)Math.Round(d);
        if (val is JsonElement { ValueKind: JsonValueKind.Number } je && je.TryGetInt32(out var j))
            return j;
        return int.TryParse(val.ToString(), out var parsed) ? parsed : 0;
    }

    private static Dictionary<string, object?> JsonElementToDict(JsonElement el)
    {
        var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in el.EnumerateObject())
            dict[prop.Name] = JsonElementToValue(prop.Value);
        return dict;
    }

    private static object? JsonElementToValue(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.String => el.GetString(),
        JsonValueKind.Number => el.TryGetInt64(out var l) ? l : el.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        JsonValueKind.Object => JsonElementToDict(el),
        JsonValueKind.Array => el.EnumerateArray().Select(JsonElementToValue).Cast<object>().ToList(),
        _ => el.ToString()
    };

    private static int SeverityRank(string? severity) => (severity ?? "info").ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    private static string SeverityBadge(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🔵",
        _ => "⚪"
    };

    private static string FormatKind(string kind) =>
        string.Concat(kind.Replace('-', ' ').Replace('_', ' ').Split(' ')
            .Select(w => w.Length > 0 ? char.ToUpper(w[0]) + w[1..] : w));

    private static string SarifLevel(string? severity) => (severity ?? "info").ToLowerInvariant() switch
    {
        "critical" or "high" => "error",
        "medium" => "warning",
        "low" => "note",
        _ => "none"
    };

    #endregion
}
