using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security.Vpx;

public static class VpxImportService
{
    public sealed class ImportResult
    {
        public int FindingsImported { get; set; }
        public int FindingsSkipped { get; set; }
        public int ProofsImported { get; set; }
        public int VerdictsImported { get; set; }
        public int SurfacesImported { get; set; }
        public int RunsImported { get; set; }
        public int AssessmentsImported { get; set; }
        public int ArtifactsImported { get; set; }
        public string? DocumentId { get; set; }
        public List<string> Warnings { get; set; } = [];
    }

    public static bool IsSupportedVpxVersion(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return false;
        if (version == "1.0") return true;
        return System.Text.RegularExpressions.Regex.IsMatch(version, @"^1\.[1-9][0-9]*$");
    }

    public static ImportResult ImportDocument(AutomationContext context, JsonElement root, string mode = "merge")
    {
        var version = root.TryGetProperty("vpxVersion", out var ver) ? ver.GetString() : null;
        if (!IsSupportedVpxVersion(version))
            throw new InvalidOperationException(
                $"Unsupported vpxVersion \"{version}\"; expected \"1.0\" or a 1.x version >= 1.1.");

        if (mode.Equals("replace", StringComparison.OrdinalIgnoreCase))
            context.ClearVpxImportState();

        var result = new ImportResult { DocumentId = root.TryGetProperty("documentId", out var did) ? did.GetString() : null };
        var warnings = new List<string>();

        var surfaceIndex = BuildSurfaceIndex(root);
        result.SurfacesImported = RegisterSurfaces(context, root, surfaceIndex);

        var existingIds = CollectExistingFindingIds(context);
        (result.FindingsImported, result.FindingsSkipped) = ImportFindings(context, root, surfaceIndex, existingIds, warnings);

        result.ProofsImported = ImportProofs(context, root);
        result.VerdictsImported = ImportVerdicts(context, root);
        result.RunsImported = ImportObjectArray(root, "runs", context.AddVpxRun);
        result.AssessmentsImported = ImportObjectArray(root, "assessments", context.AddVpxAssessment);
        result.ArtifactsImported = ImportObjectArray(root, "artifacts", context.AddVpxArtifact);

        if (root.TryGetProperty("target", out var target) && target.ValueKind == JsonValueKind.Object)
            context.SetVpxImportTarget(ParseObject(target));

        if (!string.IsNullOrEmpty(result.DocumentId))
            context.SetVpxImportDocumentId(result.DocumentId);

        result.Warnings.AddRange(warnings);
        return result;
    }

    private static Dictionary<string, JsonElement> BuildSurfaceIndex(JsonElement root)
    {
        var index = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        if (!root.TryGetProperty("surfaces", out var surfaces) || surfaces.ValueKind != JsonValueKind.Array)
            return index;
        foreach (var s in surfaces.EnumerateArray())
        {
            if (s.TryGetProperty("id", out var idEl))
            {
                var id = idEl.GetString();
                if (!string.IsNullOrWhiteSpace(id))
                    index[id] = s;
            }
        }
        return index;
    }

    private static int RegisterSurfaces(AutomationContext context, JsonElement root, Dictionary<string, JsonElement> surfaceIndex)
    {
        var count = 0;
        foreach (var (id, surface) in surfaceIndex)
        {
            context.UpsertVpxSurface(id, ParseObject(surface));
            count++;
        }
        return count;
    }

    private static HashSet<string> CollectExistingFindingIds(AutomationContext context)
    {
        var ids = ChainAnalysisService.CollectFindings(context)
            .Select(f => VpxExportService.NormalizeFindingId(f.Id))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var id in context.GetVpxImportedFindingIds())
            ids.Add(id);
        return ids;
    }

    private static (int imported, int skipped) ImportFindings(
        AutomationContext context,
        JsonElement root,
        Dictionary<string, JsonElement> surfaceIndex,
        HashSet<string> existingIds,
        List<string> warnings)
    {
        if (!root.TryGetProperty("findings", out var findings) || findings.ValueKind != JsonValueKind.Array)
            return (0, 0);

        var imported = 0;
        var skipped = 0;
        var baseUrl = root.TryGetProperty("target", out var t) && t.TryGetProperty("baseUrl", out var bu)
            ? bu.GetString()
            : null;

        foreach (var f in findings.EnumerateArray())
        {
            var id = f.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
            if (string.IsNullOrWhiteSpace(id))
            {
                warnings.Add("Skipped finding without id.");
                skipped++;
                continue;
            }

            var normId = VpxExportService.NormalizeFindingId(id);
            if (!existingIds.Add(normId))
            {
                warnings.Add($"Skipped duplicate finding id '{normId}'.");
                skipped++;
                continue;
            }

            var kind = f.TryGetProperty("kind", out var k) ? k.GetString() ?? "other" : "other";
            var category = MapKindToCategory(kind, f);
            if (!FindingNormalizer.IsKnownCategory(category))
                category = "other";

            var title = f.TryGetProperty("title", out var ti) ? ti.GetString() ?? kind : kind;
            var severity = f.TryGetProperty("severity", out var sev) ? sev.GetString() ?? "medium" : "medium";

            string? endpoint = null;
            string? method = null;
            var sid = f.TryGetProperty("surfaceId", out var sidEl) ? sidEl.GetString() : null;
            if (string.IsNullOrWhiteSpace(sid) &&
                f.TryGetProperty("surfaceIds", out var sidsEl) && sidsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in sidsEl.EnumerateArray())
                {
                    sid = item.GetString();
                    if (!string.IsNullOrWhiteSpace(sid)) break;
                }
            }
            if (!string.IsNullOrWhiteSpace(sid) &&
                surfaceIndex.TryGetValue(sid!, out var surface))
            {
                var route = surface.TryGetProperty("route", out var r) ? r.GetString() : null;
                method = surface.TryGetProperty("method", out var m) ? m.GetString() : "GET";
                if (!string.IsNullOrWhiteSpace(route))
                {
                    endpoint = route.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                        ? route
                        : CombineUrl(baseUrl, route);
                }
            }

            var param = f.TryGetProperty("param", out var p) ? p.GetString() : null;

            var description = f.TryGetProperty("description", out var desc) ? desc.GetString() : null;

            var detailParts = new List<string>();
            if (description != null)
                detailParts.Add(description);
            if (f.TryGetProperty("trace", out var trace) && trace.ValueKind == JsonValueKind.Array)
            {
                foreach (var step in trace.EnumerateArray())
                {
                    if (step.GetString() is { } s)
                        detailParts.Add(s);
                }
            }
            if (f.TryGetProperty("origin", out var origin) && origin.TryGetProperty("snippet", out var sn))
                detailParts.Add(sn.GetString() ?? "");

            var tags = new List<string> { "vpx-import", kind };
            if (f.TryGetProperty("tags", out var tagsEl) && tagsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var tag in tagsEl.EnumerateArray())
                {
                    if (tag.GetString() is { } tagStr && !tags.Contains(tagStr, StringComparer.OrdinalIgnoreCase))
                        tags.Add(tagStr);
                }
            }

            context.AddManualChainFinding(new ChainableFinding
            {
                Id = normId,
                Source = "vpx-import",
                Category = category,
                Severity = severity,
                Title = title,
                Endpoint = endpoint,
                Method = method,
                Parameter = param,
                Detail = detailParts.Count > 0 ? string.Join(" → ", detailParts) : null,
                Tags = tags
            });
            context.RegisterVpxImportedFindingId(normId);
            imported++;
        }

        return (imported, skipped);
    }

    private static int ImportProofs(AutomationContext context, JsonElement root)
    {
        if (!root.TryGetProperty("proofs", out var proofs) || proofs.ValueKind != JsonValueKind.Array)
            return 0;

        var count = 0;
        foreach (var p in proofs.EnumerateArray())
        {
            var findingId = p.TryGetProperty("findingId", out var fid) ? fid.GetString() : null;
            if (string.IsNullOrWhiteSpace(findingId)) continue;

            var executedAt = DateTime.UtcNow;
            if (p.TryGetProperty("executedAt", out var ea) && DateTime.TryParse(ea.GetString(), out var parsed))
                executedAt = parsed.ToUniversalTime();

            var outcome = p.TryGetProperty("outcome", out var oc) ? oc.GetString() : null;
            bool? observed = null;
            var oraclePassed = false;
            if (p.TryGetProperty("oracle", out var oracle))
            {
                if (oracle.TryGetProperty("observed", out var obs) &&
                    (obs.ValueKind is JsonValueKind.True or JsonValueKind.False))
                {
                    observed = obs.GetBoolean();
                    oraclePassed = observed.Value;
                }
                else if (oracle.TryGetProperty("passed", out var op) &&
                         (op.ValueKind is JsonValueKind.True or JsonValueKind.False))
                {
                    oraclePassed = op.GetBoolean();
                    observed = oraclePassed;
                }
            }

            if (string.IsNullOrWhiteSpace(outcome))
                outcome = oraclePassed ? "exploited" : "not-reproduced";

            List<string>? limitations = null;
            if (p.TryGetProperty("limitations", out var lim) && lim.ValueKind == JsonValueKind.Array)
            {
                limitations = lim.EnumerateArray()
                    .Select(x => x.GetString())
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Cast<string>()
                    .ToList();
            }

            List<string>? artifactIds = null;
            if (p.TryGetProperty("artifactIds", out var aids) && aids.ValueKind == JsonValueKind.Array)
            {
                artifactIds = aids.EnumerateArray()
                    .Select(x => x.GetString())
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Cast<string>()
                    .ToList();
            }

            context.AddVpxProof(new VpxProofRecord
            {
                Id = p.TryGetProperty("id", out var id) ? id.GetString() ?? Guid.NewGuid().ToString("N")[..8] : Guid.NewGuid().ToString("N")[..8],
                FindingId = VpxExportService.NormalizeFindingId(findingId),
                RunId = p.TryGetProperty("runId", out var rid) ? rid.GetString() : null,
                Outcome = outcome,
                ExecutedAtUtc = executedAt,
                WorkflowType = p.TryGetProperty("workflow", out var wf) && wf.TryGetProperty("type", out var wt)
                    ? wt.GetString() ?? "verify-workflow"
                    : "verify-workflow",
                TemplateId = p.TryGetProperty("workflow", out wf) && wf.TryGetProperty("templateId", out var tid)
                    ? tid.GetString()
                    : null,
                OraclePassed = oraclePassed,
                OracleObserved = observed,
                OracleType = p.TryGetProperty("oracle", out oracle) && oracle.TryGetProperty("type", out var ot)
                    ? ot.GetString() ?? "none"
                    : "none",
                OracleEvidence = p.TryGetProperty("oracle", out oracle) && oracle.TryGetProperty("actualSignal", out var sig)
                    ? ReadOracleActualSignal(sig)
                    : p.TryGetProperty("oracle", out oracle) && oracle.TryGetProperty("evidence", out var ev)
                    ? JsonSerializer.Deserialize<object>(ev.GetRawText())
                    : p.TryGetProperty("evidenceSummary", out var sum) ? sum.GetString() : null,
                EvidenceBundlePath = p.TryGetProperty("evidenceBundle", out var eb) ? eb.GetString() : null,
                SurfaceId = p.TryGetProperty("injection", out var inj) && inj.TryGetProperty("surfaceId", out var si) ? si.GetString() : null,
                Param = p.TryGetProperty("injection", out inj) && inj.TryGetProperty("param", out var pr) ? pr.GetString() : null,
                Payload = p.TryGetProperty("injection", out inj) && inj.TryGetProperty("payload", out var pl) ? pl.GetString() : null,
                Limitations = limitations,
                ArtifactIds = artifactIds,
                ElapsedMs = p.TryGetProperty("elapsedMs", out var em) && em.TryGetInt32(out var ms) ? ms : 0
            });
            count++;
        }
        return count;
    }

    private static int ImportVerdicts(AutomationContext context, JsonElement root)
    {
        if (!root.TryGetProperty("verdicts", out var verdicts) || verdicts.ValueKind != JsonValueKind.Array)
            return 0;

        var count = 0;
        foreach (var v in verdicts.EnumerateArray())
        {
            var findingId = v.TryGetProperty("findingId", out var fid) ? fid.GetString() : null;
            if (string.IsNullOrWhiteSpace(findingId)) continue;

            DateTime? updated = null;
            if (v.TryGetProperty("updatedAt", out var ua) && DateTime.TryParse(ua.GetString(), out var parsed))
                updated = parsed.ToUniversalTime();

            Dictionary<string, object?>? remediation = null;
            if (v.TryGetProperty("remediation", out var rem) && rem.ValueKind == JsonValueKind.Object)
                remediation = ParseObject(rem);

            List<string>? basedOnProofs = ReadStringList(v, "basedOnProofIds");
            var proofId = v.TryGetProperty("proofId", out var pid) ? pid.GetString() : null;
            if ((basedOnProofs == null || basedOnProofs.Count == 0) && !string.IsNullOrWhiteSpace(proofId))
                basedOnProofs = [proofId];

            var verdictId = v.TryGetProperty("id", out var vid) ? vid.GetString() : null;
            if (string.IsNullOrWhiteSpace(verdictId))
                verdictId = $"verdict-{VpxExportService.NormalizeFindingId(findingId)}";

            context.UpsertVpxVerdict(new VpxVerdictRecord
            {
                Id = verdictId,
                FindingId = VpxExportService.NormalizeFindingId(findingId),
                RunId = v.TryGetProperty("runId", out var vrun) ? vrun.GetString() : null,
                ProofId = proofId,
                BasedOnProofIds = basedOnProofs,
                BasedOnAssessmentIds = ReadStringList(v, "basedOnAssessmentIds"),
                SupersedesVerdictId = v.TryGetProperty("supersedesVerdictId", out var sup) ? sup.GetString() : null,
                Exploitability = v.TryGetProperty("exploitability", out var ex) ? ex.GetString() ?? "hypothesis" : "hypothesis",
                Disposition = v.TryGetProperty("disposition", out var disp) ? disp.GetString() : null,
                Justification = v.TryGetProperty("justification", out var jus) ? jus.GetString() : null,
                EffectiveSeverity = v.TryGetProperty("effectiveSeverity", out var es) ? es.GetString() : null,
                Confidence = v.TryGetProperty("confidence", out var conf) && conf.TryGetDouble(out var c) ? c : null,
                RerunToken = v.TryGetProperty("rerunToken", out var rt) ? rt.GetString() : null,
                UpdatedAtUtc = updated,
                Remediation = remediation
            });
            count++;
        }
        return count;
    }

    private static int ImportObjectArray(JsonElement root, string name, Action<Dictionary<string, object?>> add)
    {
        if (!root.TryGetProperty(name, out var arr) || arr.ValueKind != JsonValueKind.Array)
            return 0;
        var count = 0;
        foreach (var item in arr.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) continue;
            add(ParseObject(item));
            count++;
        }
        return count;
    }

    private static List<string>? ReadStringList(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.Array)
            return null;
        var list = el.EnumerateArray()
            .Select(x => x.GetString())
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Cast<string>()
            .ToList();
        return list.Count == 0 ? null : list;
    }

    private static string MapKindToCategory(string kind, JsonElement finding)
    {
        if (finding.TryGetProperty("proofHints", out var ph) && ph.TryGetProperty("category", out var cat))
        {
            var c = cat.GetString();
            if (!string.IsNullOrWhiteSpace(c)) return c.ToLowerInvariant();
        }
        return kind.ToLowerInvariant() switch
        {
            "sqli" => "sqli",
            "xss" => "xss",
            "csrf" => "csrf",
            "idor" => "idor",
            "ssrf" => "ssrf",
            "open-redirect" => "open-redirect",
            "path-traversal" => "path-traversal",
            "mass-assignment" => "mass-assignment",
            "ssti" => "ssti-confirmed",
            "command-injection" => "command-injection",
            "deserialization" => "deserialization-suspected",
            "misconfiguration" => "weak-headers",
            "info-leak" => "info-leak",
            _ => kind
        };
    }

    private static string? CombineUrl(string? baseUrl, string route)
    {
        if (string.IsNullOrWhiteSpace(baseUrl)) return route;
        if (Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
            return new Uri(baseUri, route.StartsWith('/') ? route : $"/{route}").ToString();
        return route;
    }

    private static Dictionary<string, object?> ParseObject(JsonElement el)
    {
        var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in el.EnumerateObject())
            dict[prop.Name] = ParseValue(prop.Value);
        return dict;
    }

    private static object? ParseValue(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.String => el.GetString(),
        JsonValueKind.Number => el.TryGetInt64(out var l) ? l : el.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        JsonValueKind.Array => el.EnumerateArray().Select(ParseValue).ToList(),
        JsonValueKind.Object => ParseObject(el),
        _ => el.GetRawText()
    };

    internal static string? ReadOracleActualSignal(JsonElement sig) => sig.ValueKind switch
    {
        JsonValueKind.String => sig.GetString(),
        JsonValueKind.Null => null,
        _ => sig.GetRawText()
    };
}
