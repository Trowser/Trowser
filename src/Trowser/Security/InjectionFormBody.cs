namespace Trowser.Security;

/// <summary>application/x-www-form-urlencoded body field substitution for injection probes.</summary>
public static class InjectionFormBody
{
    public static string ReplaceFormField(string body, string fieldName, string value)
    {
        var qs = System.Web.HttpUtility.ParseQueryString(body);
        var parts = new List<string>();
        var replaced = false;
        foreach (string? key in qs)
        {
            if (key == null) continue;
            if (key.Equals(fieldName, StringComparison.OrdinalIgnoreCase))
            {
                parts.Add($"{Uri.EscapeDataString(key)}={RequestMarkerSubstitute.EscapeDataStringPreservingMarkers(value)}");
                replaced = true;
            }
            else
                parts.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(qs[key] ?? "")}");
        }

        if (!replaced)
            parts.Add($"{Uri.EscapeDataString(fieldName)}={RequestMarkerSubstitute.EscapeDataStringPreservingMarkers(value)}");

        return string.Join("&", parts);
    }
}
