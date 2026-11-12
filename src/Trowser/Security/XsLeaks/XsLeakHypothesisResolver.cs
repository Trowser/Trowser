using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

public sealed class XsLeakHypothesisResolver
{
    public sealed class ResolveResult
    {
        public List<XsLeakScanner.StateSpec> States { get; init; } = [];
        public XsLeakHypothesis.HypothesisSpec? Hypothesis { get; init; }
        public bool HypothesisRequested { get; init; }
        public bool HypothesisExpanded { get; init; }
        public string? StateGenerationStrategy { get; init; }
        public string? StateGenerationDetail { get; init; }
        public List<string> Warnings { get; init; } = [];
    }

    public static async Task<ResolveResult> ResolveAsync(
        AutomationContext ctx,
        IdentityStore identities,
        XsLeakScanner.XsLeakOptions options)
    {
        var warnings = new List<string>();
        var hypothesis = options.Hypothesis;
        var hypothesisRequested = hypothesis != null
                                  || options.States.Any(s => !string.IsNullOrWhiteSpace(s.Role));

        if (hypothesis != null)
            ValidateHypothesis(hypothesis, warnings);

        var fromExplicit = options.States.Count >= 2;
        var states = fromExplicit
            ? options.States.ToList()
            : XsLeakHypothesis.ExpandStates(options.States, hypothesis);

        var expanded = !fromExplicit && hypothesisRequested && states.Count >= 2;

        if (hypothesisRequested && !expanded && options.States.Count < 2)
        {
            warnings.Add(
                "hypothesis was provided but did not yield two states — need urlTemplate plus hitValues and missValues " +
                "(placeholder {value} in urlTemplate or form fields), or pass explicit states[].");
        }

        string? genStrategy = expanded ? "hypothesis-template" : null;
        string? genDetail = expanded
            ? $"Expanded {states.Count} states from hypothesis template (kind={hypothesis?.Kind ?? "value"})."
            : null;

        // Match REST/MCP: auto-derive when states are omitted unless hypothesis expansion already applied.
        var defaultAutoStates = options.Hypothesis == null && options.States.Count < 2;
        var shouldAuto = (options.AutoStates || defaultAutoStates) && states.Count < 2 && !expanded;
        if (hypothesisRequested && states.Count >= 2 && expanded)
            shouldAuto = false;

        if (shouldAuto)
        {
            var generated = await new XsLeakStateGenerator(ctx, identities).TryGenerateAsync();
            genStrategy = generated.Strategy;
            genDetail = generated.Detail;
            if (generated.States.Count >= 2)
            {
                if (hypothesisRequested)
                {
                    warnings.Add(
                        "autoStates replaced hypothesis expansion — set autoStates:false when using hypothesis, " +
                        "or pass explicit states[] derived from the template.");
                }

                states = generated.States;
                expanded = false;
            }
        }

        XsLeakSearchPostOracle.AppendWarningsIfNeeded(ctx, states, warnings);

        return new ResolveResult
        {
            States = states,
            Hypothesis = hypothesis,
            HypothesisRequested = hypothesisRequested,
            HypothesisExpanded = expanded,
            StateGenerationStrategy = genStrategy,
            StateGenerationDetail = genDetail,
            Warnings = warnings
        };
    }

    private static void ValidateHypothesis(XsLeakHypothesis.HypothesisSpec h, List<string> warnings)
    {
        if (string.IsNullOrWhiteSpace(h.Secret))
            warnings.Add("hypothesis.secret is empty — set a short description of the secret under test.");

        var hasTemplate = !string.IsNullOrWhiteSpace(h.UrlTemplate);
        var hasValues = h.HitValues.Count > 0 || h.MissValues.Count > 0;
        if (!hasTemplate && hasValues)
            warnings.Add("hypothesis has hitValues/missValues but no urlTemplate — nothing to expand.");

        if (hasTemplate && !hasValues)
            warnings.Add("hypothesis.urlTemplate set but hitValues and missValues are empty — need at least one hit and one miss value.");

        if (hasTemplate && hasValues
            && !h.UrlTemplate!.Contains("{value}", StringComparison.Ordinal)
            && h.FormFields.Count == 0
            && string.IsNullOrWhiteSpace(h.BodyTemplate))
        {
            warnings.Add(
                "urlTemplate does not contain {value} and formFields/bodyTemplate is empty — values cannot be injected. " +
                "Use https://host/search?q={value}, formFields, or bodyTemplate with {value}.");
        }

        if (string.Equals(h.Method, "POST", StringComparison.OrdinalIgnoreCase)
            && h.FormFields.Count == 0
            && string.IsNullOrWhiteSpace(h.BodyTemplate))
        {
            warnings.Add(
                "hypothesis.method is POST but formFields and bodyTemplate are empty — add formFields or bodyTemplate with {value}.");
        }

        if (!string.IsNullOrWhiteSpace(h.BodyTemplate)
            && !h.BodyTemplate.Contains("{value}", StringComparison.Ordinal))
        {
            warnings.Add("bodyTemplate does not contain {value} — hit/miss values cannot be injected.");
        }
    }
}
