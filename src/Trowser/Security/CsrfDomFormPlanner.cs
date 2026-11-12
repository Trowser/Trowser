namespace Trowser.Security;

/// <summary>
/// Turns live HTML forms into CSRF probe plans. A hidden token field (for example name="csrf")
/// is a token to test, not evidence that the form has no token.
/// </summary>
public static class CsrfDomFormPlanner
{
    public sealed class PlannedPost
    {
        public string Url { get; init; } = "";
        public string Path { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string Body { get; init; } = "";
        public string? CsrfField { get; init; }
    }

    public static List<PlannedPost> Plan(IEnumerable<FormProbeCloner.CapturedForm> forms, string? hostFilter)
    {
        var list = new List<PlannedPost>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var form in forms)
        {
            if (form.Method is not ("POST" or "PUT" or "PATCH"))
                continue;
            if (!Uri.TryCreate(form.Action, UriKind.Absolute, out var actionUri))
                continue;
            if (hostFilter != null && !SecurityHostScope.Matches(actionUri.Host, hostFilter))
                continue;

            var key = $"{form.Method}|{actionUri.GetLeftPart(UriPartial.Path)}";
            if (!seen.Add(key))
                continue;

            string? csrf = null;
            foreach (var field in form.Fields)
            {
                if (!CsrfTokenHeuristics.IsCsrfFieldCandidate(field.Name, field.Type, field.Value))
                    continue;
                csrf = field.Name;
                break;
            }

            list.Add(new PlannedPost
            {
                Url = actionUri.ToString(),
                Path = actionUri.AbsolutePath,
                Method = form.Method.ToUpperInvariant(),
                Body = AuthFormDiscovery.BuildFormUrlEncodedBody(form),
                CsrfField = csrf
            });
        }

        return list;
    }

    public static bool SameEndpoint(string method, string url, PlannedPost planned) =>
        method.Equals(planned.Method, StringComparison.OrdinalIgnoreCase)
        && SecurityHostScope.LogicalEndpointKey(method, url)
            .Equals(SecurityHostScope.LogicalEndpointKey(planned.Method, planned.Url), StringComparison.OrdinalIgnoreCase);
}
