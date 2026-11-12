namespace Trowser.Security.XsLeaks;

public sealed class XsLeakTechniquePlanner
{
    public sealed class PlanEntry
    {
        public string TechniqueId { get; init; } = "";
        public string Reason { get; init; } = "";
        public bool Selected { get; init; }
    }

    public sealed class PlanResult
    {
        public List<PlanEntry> Entries { get; init; } = [];
        public List<string> Warnings { get; init; } = [];
        public bool NothingEligible { get; init; }

        public IReadOnlyList<XsLeakTechniques.TechniqueDef> SelectedTechniques { get; init; } = [];

        public object ToApiObject() => new
        {
            selected = Entries.Where(e => e.Selected).Select(e => new { e.TechniqueId, e.Reason }),
            skipped = Entries.Where(e => !e.Selected).Select(e => new { e.TechniqueId, e.Reason }),
            warnings = Warnings.Count > 0 ? Warnings : null,
            nothingEligible = NothingEligible ? (object)true : null
        };
    }

    public static PlanResult Build(
        bool active,
        bool hypothesisMode,
        int maxSeconds,
        string attackerSite,
        XsLeakStateValidator.ValidationResult validation,
        XsLeakSessionProfile sessionProfile,
        XsLeakCredentialObservation.DeliveryResult delivery,
        IReadOnlyList<string>? explicitFilter,
        bool fullCatalog)
    {
        var warnings = new List<string>();
        var all = XsLeakTechniques.Catalog.ToList();
        var entries = new List<PlanEntry>();
        var eligible = new List<XsLeakTechniques.TechniqueDef>();

        var credDiff = validation.CredentialedDiff;
        var anonDiff = validation.AnonymousDiff;
        var tao = validation.States.FirstOrDefault()?.TimingAllowOrigin == true;

        foreach (var t in all)
        {
            if (t.RequiresActive && !active)
            {
                entries.Add(new PlanEntry { TechniqueId = t.Id, Selected = false, Reason = "requires active mode" });
                continue;
            }

            if (t.Experimental)
            {
                entries.Add(new PlanEntry { TechniqueId = t.Id, Selected = false, Reason = "experimental" });
                continue;
            }

            if (t.RequiresTimingAllowOrigin && !tao)
            {
                entries.Add(new PlanEntry { TechniqueId = t.Id, Selected = false, Reason = "no Timing-Allow-Origin" });
                continue;
            }

            var ctx = t.CredentialContext;
            var needsCookie = credDiff != "none" && anonDiff == "none";
            if (needsCookie && ctx == XsLeakTechniques.CredentialContext.Subresource)
            {
                if (!delivery.Subresource.StartsWith("sent", StringComparison.OrdinalIgnoreCase))
                {
                    entries.Add(new PlanEntry
                    {
                        TechniqueId = t.Id,
                        Selected = false,
                        Reason = "subresource cookie not sent: " + delivery.Subresource
                    });
                    if (delivery.Subresource.StartsWith("blocked:", StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(attackerSite, "same-site", StringComparison.OrdinalIgnoreCase))
                    {
                        warnings.Add(
                            "Auth cookie blocked on cross-site subresource probes — try attackerSite same-site or active top-level probes.");
                    }
                    continue;
                }
            }

            if (needsCookie && ctx == XsLeakTechniques.CredentialContext.TopLevel)
            {
                if (!active)
                {
                    entries.Add(new PlanEntry { TechniqueId = t.Id, Selected = false, Reason = "top-level requires active" });
                    continue;
                }
                if (!delivery.TopLevel.StartsWith("sent", StringComparison.OrdinalIgnoreCase)
                    && delivery.TopLevel != "not-run")
                {
                    entries.Add(new PlanEntry { TechniqueId = t.Id, Selected = false, Reason = "top-level cookie not sent" });
                    continue;
                }
            }

            if (string.Equals(sessionProfile.AuthMechanism, "bearer-localStorage", StringComparison.OrdinalIgnoreCase)
                && ctx != XsLeakTechniques.CredentialContext.None
                && anonDiff == "none")
            {
                entries.Add(new PlanEntry { TechniqueId = t.Id, Selected = false, Reason = "bearer-only session" });
                continue;
            }

            eligible.Add(t);
            entries.Add(new PlanEntry { TechniqueId = t.Id, Selected = false, Reason = "candidate" });
        }

        IEnumerable<XsLeakTechniques.TechniqueDef> ordered = eligible;
        if (explicitFilter is { Count: > 0 })
        {
            ordered = eligible.Where(t =>
                explicitFilter.Any(f => t.Id.Equals(f, StringComparison.OrdinalIgnoreCase)
                                        || t.Category.Equals(f, StringComparison.OrdinalIgnoreCase)));
        }
        else if (!fullCatalog)
        {
            ordered = RankByDiff(eligible, credDiff, anonDiff, validation);
            var maxTech = hypothesisMode ? 3 : 5;
            if (maxSeconds > 0 && maxSeconds < 45)
                maxTech = 2;
            ordered = ordered.Take(maxTech);
        }

        var selectedList = ordered.ToList();
        if (active && !fullCatalog && explicitFilter is not { Count: > 0 })
        {
            foreach (var boostId in new[] { "popup-closed", "window-open-length", "named-window-reuse", "form-post-frame" })
            {
                if (selectedList.Any(t => t.Id == boostId)) continue;
                var def = XsLeakTechniques.Catalog.FirstOrDefault(t => t.Id == boostId);
                if (def == null || !eligible.Any(e => e.Id == def.Id)) continue;
                if (def.RequiresActive && !active) continue;
                selectedList.Add(def);
            }
        }

        for (var i = 0; i < entries.Count; i++)
        {
            if (entries[i].Reason != "candidate") continue;
            var sel = selectedList.Any(t => t.Id == entries[i].TechniqueId);
            entries[i] = new PlanEntry
            {
                TechniqueId = entries[i].TechniqueId,
                Selected = sel,
                Reason = sel ? "selected" : "budget/priority"
            };
        }

        var nothing = selectedList.Count == 0;
        if (nothing)
            warnings.Add("No eligible XS-Leak techniques for this session and attacker mode.");

        return new PlanResult
        {
            Entries = entries,
            Warnings = warnings,
            NothingEligible = nothing,
            SelectedTechniques = selectedList
        };
    }

    private static IEnumerable<XsLeakTechniques.TechniqueDef> RankByDiff(
        List<XsLeakTechniques.TechniqueDef> eligible,
        string credDiff,
        string anonDiff,
        XsLeakStateValidator.ValidationResult validation)
    {
        int Score(XsLeakTechniques.TechniqueDef t)
        {
            var diff = anonDiff != "none" ? anonDiff : credDiff;
            return diff switch
            {
                "status" when t.Id is "status-bucket-oracle" or "img-error" or "script-error" => 100,
                "redirect" when t.Category == "redirect" => 90,
                "length" when t.Id == "status-bucket-oracle" => 70,
                "headers" when t.Category is "load-error" or "popup" => 80,
                "iframe" when t.Id == "iframe-framecount" => 85,
                _ when validation.LatencyGap && t.IsTiming => 75,
                _ => 10
            };
        }

        return eligible.OrderByDescending(Score).ThenBy(t => t.Id);
    }
}
