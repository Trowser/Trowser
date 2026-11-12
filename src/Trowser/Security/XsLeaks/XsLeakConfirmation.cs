namespace Trowser.Security.XsLeaks;

internal static class XsLeakConfirmation
{
    public const int ScreeningTrials = 3;
    public const int ConfirmTrials = 3;

    public static IReadOnlyList<XsLeakScanner.StateSpec> ScreeningStates(IReadOnlyList<XsLeakScanner.StateSpec> states)
    {
        var hit = states.FirstOrDefault(s =>
            string.Equals(s.Role, "hit", StringComparison.OrdinalIgnoreCase));
        var miss = states.FirstOrDefault(s =>
            string.Equals(s.Role, "miss", StringComparison.OrdinalIgnoreCase));
        if (hit != null && miss != null)
            return [hit, miss];
        if (states.Count >= 2)
            return [states[0], states[1]];
        return states;
    }

    public static XsLeakScanner.StateSpec? TryBuildControlState(
        IReadOnlyList<XsLeakScanner.StateSpec> states,
        XsLeakHypothesis.HypothesisSpec? hypothesis)
    {
        var misses = states
            .Where(s => string.Equals(s.Role, "miss", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (misses.Count >= 2)
        {
            var m = misses[1];
            return new XsLeakScanner.StateSpec
            {
                Label = "control-miss",
                Url = m.Url,
                Identity = m.Identity,
                SetupUrl = m.SetupUrl,
                Role = "control",
                Method = m.Method,
                Body = m.Body,
                ContentType = m.ContentType,
                Form = m.Form
            };
        }

        if (hypothesis is { MissValues.Count: >= 2, UrlTemplate: not null and not "" })
        {
            var second = hypothesis.MissValues[1];
            var expanded = XsLeakHypothesis.ExpandStates([], new XsLeakHypothesis.HypothesisSpec
            {
                UrlTemplate = hypothesis.UrlTemplate,
                Method = hypothesis.Method,
                FormFields = hypothesis.FormFields,
                HitValues = [],
                MissValues = [second]
            });
            if (expanded.Count == 1)
            {
                var s = expanded[0];
                return new XsLeakScanner.StateSpec
                {
                    Label = "control-miss",
                    Url = s.Url,
                    Role = "control",
                    Method = s.Method,
                    Form = s.Form
                };
            }
        }

        return null;
    }

    public static bool ControlInvalidatesSecret(
        XsLeakTechniques.TechniqueDef tech,
        Dictionary<string, List<string?>> valuesByState,
        string missLabel,
        string controlLabel)
    {
        if (!valuesByState.TryGetValue(missLabel, out var missVals)
            || !valuesByState.TryGetValue(controlLabel, out var ctrlVals))
            return false;

        if (tech.IsTiming)
            return false;

        return XsLeakStats.DeterministicDistinct(missVals, ctrlVals);
    }

    public static string ResolveConfirmationStatus(
        bool hypothesisMode,
        string screeningVerdict,
        string? confirmVerdict,
        bool controlFailed,
        bool explainable,
        bool mitigatedExploitable,
        bool sessionHealthy,
        bool ranConfirmation)
    {
        if (screeningVerdict is not ("distinguishable" or "probable"))
            return "none";

        if (!hypothesisMode)
            return mitigatedExploitable ? "confirmed-mitigated" : "confirmed";

        if (!sessionHealthy)
            return "candidate-session-expired";
        if (controlFailed)
            return "candidate-control-failed";
        if (!explainable)
            return "candidate-unexplained";
        if (!ranConfirmation)
            return "candidate-unconfirmed";
        if (confirmVerdict is not ("distinguishable" or "probable"))
            return "candidate-unconfirmed";

        return mitigatedExploitable ? "confirmed-mitigated" : "confirmed";
    }

    public static bool ShouldEmitFinding(string confirmationStatus) =>
        confirmationStatus is "confirmed" or "confirmed-mitigated";
}
