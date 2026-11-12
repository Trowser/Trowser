using System.Linq;
using System.Text;

namespace Trowser.Security;

/// <summary>
/// Builds JSON-friendly firewall test payloads: a compact <see cref="Results"/> + <see cref="Summary"/> in non-verbose mode,
/// and full per-defense evidence when <c>verbose</c> is true.
/// </summary>
public static class FirewallApiPayload
{
    public static object Build(FirewallResult result, bool verbose)
    {
        if (verbose)
        {
            return new
            {
                result.ElapsedMs,
                overallVerdict = result.OverallVerdict,
                result.DefensesTested,
                result.DefensesEffective,
                result.DefensesIneffective,
                result.DefensesAbsent,
                defenses = new
                {
                    csp = FormatDefenseFull(result.Csp),
                    sri = FormatDefenseFull(result.Sri),
                    sandbox = FormatDefenseFull(result.Sandbox),
                    permissionsPolicy = FormatDefenseFull(result.PermissionsPolicy)
                },
                unknownCspProbes = result.UnknownCspProbes.Count > 0 ? result.UnknownCspProbes : null,
                summary = BuildSummaryLine(result)
            };
        }

        return new
        {
            result.ElapsedMs,
            overallVerdict = result.OverallVerdict,
            result.DefensesTested,
            result.DefensesEffective,
            result.DefensesIneffective,
                result.DefensesAbsent,
                unknownCspProbes = result.UnknownCspProbes.Count > 0 ? result.UnknownCspProbes : null,
                results = BuildConciseResults(result).Select(r => new
                {
                    r.Test,
                    r.Blocked,
                    r.Result,
                    r.Method,
                    r.Category
                }),
                summary = BuildSummaryLine(result)
        };
    }

    public static IReadOnlyList<ConciseRow> BuildConciseResults(FirewallResult result)
    {
        var list = new List<ConciseRow>();
        void AddDefense(DefenseResult? def, string category)
        {
            if (def == null) return;
            if (!def.Present)
            {
                list.Add(new ConciseRow($"{category}-absent", false, "absent",
                    category switch
                    {
                        "csp" => "CSP not present (no Content-Security-Policy)",
                        "sri" => "SRI not applicable (no third-party resources or empty page)",
                        "sandbox" => "No iframes to evaluate (or empty page)",
                        "permissions" => "Permissions-Policy not present",
                        _ => "Defense not present"
                    },
                    category));
                return;
            }

            if (string.Equals(category, "sri", StringComparison.OrdinalIgnoreCase))
            {
                var missing = def.Findings.Count(f => f.Technique == "missing-sri-external");
                var anyBypass = def.Findings.Count > 0;
                list.Add(new ConciseRow("third-party-sri", !anyBypass, anyBypass ? "bypassed" : "blocked",
                    missing > 0
                        ? $"external script/style without integrity ({missing} asset(s))"
                        : "third-party script/style have integrity (sampled)",
                    category));
                return;
            }

            foreach (var f in def.Findings)
            {
                var method = MapMethod(f.Technique, f.Detail, isFinding: true);
                list.Add(new ConciseRow(f.Technique, f.Result == "blocked", f.Result, method, category));
            }

            var addedAnyProbe = def.Findings.Count > 0;
            foreach (var t in def.Tests)
            {
                if (t.Result == "error") continue;
                if (def.Findings.Any(x => x.Technique == t.Technique)) continue;
                if (t.Technique == "sri-present" && string.Equals(category, "sri", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (t.Technique.StartsWith("sandbox-enforced", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(category, "sandbox", StringComparison.OrdinalIgnoreCase))
                    continue;
                var method = MapMethod(t.Technique, t.Detail, isFinding: false);
                list.Add(new ConciseRow(t.Technique, t.Result == "blocked", t.Result, method, category));
                addedAnyProbe = true;
            }

            if (string.Equals(category, "sandbox", StringComparison.OrdinalIgnoreCase) && def.Present && def.Findings.Count == 0
                && !addedAnyProbe)
            {
                list.Add(new ConciseRow("sandbox-ok", true, "blocked", "no high-risk sandbox flags on iframes", category));
            }
        }

        AddDefense(result.Csp, "csp");
        AddDefense(result.Sri, "sri");
        AddDefense(result.Sandbox, "sandbox");
        AddDefense(result.PermissionsPolicy, "permissions");

        return list;
    }

    public static string BuildSummaryLine(FirewallResult result)
    {
        var byCat = new List<string>();
        foreach (var (def, label) in new[]
                 {
                     (result.Csp, "CSP"), (result.Sri, "SRI"), (result.Sandbox, "sandbox"), (result.PermissionsPolicy, "Permissions-Policy")
                 })
        {
            if (def == null) continue;
            if (!def.Present) { byCat.Add($"{label}: not deployed"); continue; }
            var failed = def.Findings.Count;
            if (string.Equals(label, "SRI", StringComparison.Ordinal) && def.Present)
            {
                var n = def.Findings.Count(f => f.Technique == "missing-sri-external");
                if (n > 0) byCat.Add($"SRI: {n} third-party load(s) without integrity");
                else byCat.Add("SRI: third-party resources sampled with integrity");
                continue;
            }

            if (def.Tests.Count + def.Findings.Count == 0) continue;
            if (string.Equals(label, "sandbox", StringComparison.Ordinal) && def.Present)
            {
                if (failed > 0) byCat.Add($"sandbox: {failed} issue(s)");
                else byCat.Add("sandbox: configured on iframes (no high-risk flag)");
                continue;
            }

            if (def.Tests.Count == 0 && failed == 0) { byCat.Add($"{label}: policy present, no live probes run"); continue; }
            var probeRelevant = def.Findings.Count + def.Tests.Count(t => t.Result is "blocked" or "bypassed");
            byCat.Add(failed > 0 ? $"{label}: {failed} bypass / {probeRelevant} probe(s)" : $"{label}: 0 bypass ({probeRelevant} probe(s))");
        }

        var sb = new StringBuilder();
        foreach (var s in byCat) sb.AppendLine(s);
        sb.Append(
            $"Overall: {result.OverallVerdict} — {result.DefensesEffective} effective, {result.DefensesIneffective} bypassed, {result.DefensesAbsent} absent, {result.DefensesTested} categories tested");
        return sb.ToString().Trim();
    }

    private static string MapMethod(string technique, string detail, bool isFinding)
    {
        return technique switch
        {
            "inline-script" => "inline <script> injection",
            "eval" => "eval()",
            "event-handler" => "inline event handler (e.g. onerror)",
            "nonce-reuse" => "reused script nonce",
            "base-uri-injection" => "<base> URL injection",
            "script-src-data" => "script src=data: URL",
            "script-src-blob" => "script src=blob: URL",
            "javascript-url" => "javascript: URL",
            "form-action" => "cross-origin form submit",
            "frame-src" => "cross-origin iframe",
            "worker-blob" => "blob: Worker",
            "missing-sri-external" => "external script/style without Subresource Integrity",
            "sri-present" => "SRI on external asset (hardening)",
            "sandbox-escape" => "iframe sandbox allow-scripts+allow-same-origin",
            "missing-sandbox-external" => "cross-origin iframe without sandbox",
            "sandbox-enforced" => "iframe sandbox in effect",
            _ when technique.StartsWith("permissions-", StringComparison.OrdinalIgnoreCase)
                => $"Permissions-Policy: {technique["permissions-".Length..]}",
            _ => isFinding ? (detail.Length > 120 ? detail[..120] + "…" : detail) : (detail.Length > 120 ? detail[..120] + "…" : detail)
        };
    }

    private static object? FormatDefenseFull(DefenseResult? def)
    {
        if (def == null) return null;
        return new
        {
            def.Present,
            policy = def.Policy,
            def.Verdict,
            findings = def.Findings.Select(f => new
            {
                f.Technique,
                f.Directive,
                f.Result,
                severity = f.Severity?.ToString().ToLowerInvariant(),
                f.Detail
            }),
            tests = def.Tests.Select(t => new
            {
                t.Technique,
                t.Directive,
                t.Result,
                t.Detail
            })
        };
    }
}

public readonly record struct ConciseRow(string Test, bool Blocked, string Result, string Method, string Category);
