using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

public static class XsLeakHypothesis
{
    public sealed class HypothesisSpec
    {
        public string? Secret { get; init; }
        /// <summary>value | login-state | cross-user | diagnosis</summary>
        public string Kind { get; init; } = "value";
        public string? UrlTemplate { get; init; }
        public string Method { get; init; } = "GET";
        /// <summary>Form fields for POST; values may contain {value}.</summary>
        public Dictionary<string, string> FormFields { get; init; } = new(StringComparer.Ordinal);
        /// <summary>JSON (or raw) POST body template; may contain {value}. Use with contentType.</summary>
        public string? BodyTemplate { get; init; }
        public string? ContentType { get; init; }
        public List<string> HitValues { get; init; } = [];
        public List<string> MissValues { get; init; } = [];
    }

    public static bool CanExpandFromHypothesis(HypothesisSpec? hypothesis) =>
        hypothesis != null
        && !string.IsNullOrWhiteSpace(hypothesis.UrlTemplate)
        && hypothesis.HitValues.Count > 0
        && hypothesis.MissValues.Count > 0;

    public sealed class Suggestion
    {
        public string Strategy { get; init; } = "";
        public HypothesisSpec Hypothesis { get; init; } = new();
        public List<XsLeakScanner.StateSpec> States { get; init; } = [];
        public string Detail { get; init; } = "";
    }

    public static object ToApiObject(HypothesisSpec? h, bool expanded, bool requested = true) =>
        !requested && h == null
            ? new { requested = false }
            : new
            {
                requested = true,
                expanded,
                mode = h == null ? "role-states" : (string?)null,
                secret = h?.Secret,
                kind = h?.Kind ?? "value",
                method = h?.Method ?? "GET",
                urlTemplate = h?.UrlTemplate,
                formFields = h is { FormFields.Count: > 0 } ? h.FormFields : null,
                bodyTemplate = h?.BodyTemplate,
                contentType = h?.ContentType,
                hitValues = h?.HitValues,
                missValues = h?.MissValues,
                placeholder = "{value}"
            };

    public static List<XsLeakScanner.StateSpec> ExpandStates(
        IReadOnlyList<XsLeakScanner.StateSpec> explicitStates,
        HypothesisSpec? hypothesis)
    {
        if (explicitStates.Count >= 2)
            return explicitStates.ToList();

        if (hypothesis == null || !CanExpandFromHypothesis(hypothesis))
            return explicitStates.ToList();

        var method = string.IsNullOrWhiteSpace(hypothesis.Method) ? "GET" : hypothesis.Method.Trim().ToUpperInvariant();
        var list = new List<XsLeakScanner.StateSpec>();
        var i = 0;
        foreach (var v in hypothesis.HitValues)
        {
            list.Add(BuildState($"hit-{i++}", v, hypothesis, method, "hit"));
        }

        i = 0;
        foreach (var v in hypothesis.MissValues)
        {
            list.Add(BuildState($"miss-{i++}", v, hypothesis, method, "miss"));
        }

        return list.Count >= 2 ? list : explicitStates.ToList();
    }

    private static XsLeakScanner.StateSpec BuildState(
        string label,
        string value,
        HypothesisSpec hypothesis,
        string method,
        string role)
    {
        var url = hypothesis.UrlTemplate!.Contains("{value}", StringComparison.Ordinal)
            ? InjectValue(hypothesis.UrlTemplate!, value, urlEncode: true)
            : hypothesis.UrlTemplate!;
        Dictionary<string, string>? form = null;
        if (hypothesis.FormFields.Count > 0)
        {
            form = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var (k, template) in hypothesis.FormFields)
                form[k] = InjectValue(template, value, urlEncode: false);
        }
        else if (method == "POST" && url.Contains('?', StringComparison.Ordinal))
        {
            form = ParseQueryToForm(url, out var action);
            url = action;
        }

        string? jsonBody = null;
        string? contentType = null;
        if (!string.IsNullOrWhiteSpace(hypothesis.BodyTemplate))
        {
            jsonBody = InjectValue(hypothesis.BodyTemplate, value, urlEncode: false);
            contentType = string.IsNullOrWhiteSpace(hypothesis.ContentType)
                ? "application/json"
                : hypothesis.ContentType;
        }

        return new XsLeakScanner.StateSpec
        {
            Label = label,
            Url = url,
            Method = method,
            Form = form,
            Body = jsonBody,
            ContentType = contentType,
            Role = role
        };
    }

    private static string InjectValue(string template, string value, bool urlEncode)
    {
        var injected = urlEncode ? Uri.EscapeDataString(value) : value;
        return template.Replace("{value}", injected, StringComparison.Ordinal);
    }

    private static Dictionary<string, string> ParseQueryToForm(string url, out string action)
    {
        action = url;
        var form = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return form;
        action = uri.GetLeftPart(UriPartial.Path);
        foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var name = Uri.UnescapeDataString(part[..eq]);
            var val = Uri.UnescapeDataString(part[(eq + 1)..]);
            form[name] = val;
        }
        return form;
    }

    public static async Task<List<Suggestion>> SuggestAsync(
        AutomationContext ctx,
        IdentityStore identities)
    {
        var generated = await new XsLeakStateGenerator(ctx, identities).TryGenerateAsync();
        if (generated.States.Count < 2)
            return [];

        return
        [
            new Suggestion
            {
                Strategy = generated.Strategy,
                Detail = generated.Detail ?? "",
                States = generated.States,
                Hypothesis = new HypothesisSpec
                {
                    Secret = generated.Strategy switch
                    {
                        "search-hit-miss" => "Search query has results",
                        "identity-pair" => "Authenticated session state",
                        "protected-vs-synthetic-miss" => "Protected resource exists",
                        _ => "Victim state differs"
                    },
                    Kind = generated.Strategy switch
                    {
                        "identity-pair" => "login-state",
                        _ => "value"
                    }
                }
            }
        ];
    }
}
