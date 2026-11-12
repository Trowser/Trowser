using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Live DOM form discovery shared by auth probes (logout, rate-limit, CSRF).
/// </summary>
public static class AuthFormDiscovery
{
    public sealed class ResolvedForm
    {
        public required string Url { get; init; }
        public string Method { get; init; } = "GET";
        public string? BodyTemplate { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public string Source { get; init; } = "dom-form";
    }

    public static async Task<List<ResolvedForm>> DiscoverLogoutFormsAsync(AutomationContext ctx)
    {
        var forms = await FormProbeCloner.CaptureFormsAsync(ctx);
        var list = new List<ResolvedForm>();
        foreach (var form in forms)
        {
            if (!Uri.TryCreate(form.Action, UriKind.Absolute, out var actionUri))
                continue;
            if (!LooksLikeLogoutTarget(actionUri.AbsolutePath, form))
                continue;

            list.Add(ToResolved(form, actionUri.ToString()));
        }

        return list;
    }

    public static async Task<ResolvedForm?> FindFormForUrlAsync(AutomationContext ctx, string url, bool preferPost = true)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var targetUri))
            return null;

        var targetPath = targetUri.GetLeftPart(UriPartial.Path);
        FormProbeCloner.CapturedForm? best = null;

        foreach (var form in await FormProbeCloner.CaptureFormsAsync(ctx))
        {
            if (!Uri.TryCreate(form.Action, UriKind.Absolute, out var actionUri))
                continue;
            if (!string.Equals(actionUri.GetLeftPart(UriPartial.Path), targetPath, StringComparison.OrdinalIgnoreCase))
                continue;

            if (best == null)
            {
                best = form;
                continue;
            }

            if (preferPost && string.Equals(form.Method, "POST", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(best.Method, "POST", StringComparison.OrdinalIgnoreCase))
                best = form;
        }

        return best == null ? null : ToResolved(best, targetPath);
    }

    public static NetworkEntry? PickBestNetworkEntryForExplicitUrl(IReadOnlyList<NetworkEntry> entries, string absoluteUrl)
    {
        NetworkEntry? best = null;
        for (var i = entries.Count - 1; i >= 0; i--)
        {
            var entry = entries[i];
            if (!AvailabilityDiscovery.UrlPathMatches(entry.Url, absoluteUrl))
                continue;
            best = PickBetterNetworkEntry(best, entry);
        }

        return best;
    }

    internal static NetworkEntry? PickBetterNetworkEntry(NetworkEntry? current, NetworkEntry candidate)
    {
        if (current == null)
            return candidate;

        static int MethodRank(string method) => method.ToUpperInvariant() switch
        {
            "POST" => 4,
            "PUT" => 3,
            "PATCH" => 3,
            "DELETE" => 2,
            _ => 1
        };

        var curRank = MethodRank(current.Method);
        var candRank = MethodRank(candidate.Method);
        if (candRank != curRank)
            return candRank > curRank ? candidate : current;

        if (!string.IsNullOrEmpty(candidate.RequestBody) && string.IsNullOrEmpty(current.RequestBody))
            return candidate;

        return candidate.Timestamp > current.Timestamp ? candidate : current;
    }

    private static bool LooksLikeLogoutTarget(string path, FormProbeCloner.CapturedForm form)
    {
        if (AuthProbeDiscovery.LooksLikeLogoutPath(path))
            return true;

        foreach (var field in form.Fields)
        {
            var text = (field.Name + " " + field.Value).ToLowerInvariant();
            if (text.Contains("logout", StringComparison.Ordinal)
                || text.Contains("sign out", StringComparison.Ordinal)
                || text.Contains("signout", StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    private static ResolvedForm ToResolved(FormProbeCloner.CapturedForm form, string url)
    {
        var method = form.Method.ToUpperInvariant();
        Dictionary<string, string>? headers = null;
        string? body = null;
        if (method is "POST" or "PUT" or "PATCH")
        {
            body = BuildFormUrlEncodedBody(form);
            headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/x-www-form-urlencoded"
            };
        }

        return new ResolvedForm
        {
            Url = url,
            Method = method,
            BodyTemplate = body,
            Headers = headers
        };
    }

    public static string BuildFormUrlEncodedBody(FormProbeCloner.CapturedForm form)
    {
        var parts = new List<string>();
        foreach (var field in form.Fields.Where(f => !string.IsNullOrWhiteSpace(f.Name)))
        {
            var val = string.IsNullOrEmpty(field.Value) && field.IsSubmit ? field.Name : field.Value;
            parts.Add($"{Uri.EscapeDataString(field.Name)}={Uri.EscapeDataString(val)}");
        }

        return string.Join("&", parts);
    }
}
