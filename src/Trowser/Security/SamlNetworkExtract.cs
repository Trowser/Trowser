using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Extract SAML payloads from network entries beyond HTTP-Redirect/POST bindings.</summary>
internal static class SamlNetworkExtract
{
    private static readonly Regex XmlSamlMarker = new(
        @"<(saml(?:p)?|(?:[\w]+:)?Response\b|(?:[\w]+:)?Assertion\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool TryExtractSamlResponsePayload(NetworkEntry entry, out string rawPayload, out string sourceKind)
    {
        rawPayload = "";
        sourceKind = "";

        if (entry.RequestBody != null
            && TryExtractFormParam(entry.RequestBody, "SAMLResponse", out rawPayload))
        {
            sourceKind = "form-post";
            return true;
        }

        if (TryExtractFromQuery(entry.Url, "SAMLResponse", out rawPayload))
        {
            sourceKind = "redirect";
            return true;
        }

        if (!string.IsNullOrEmpty(entry.ResponseBody))
        {
            if (TryExtractFromJson(entry.ResponseBody, out rawPayload))
            {
                sourceKind = "json-response";
                return true;
            }

            if (entry.ResponseBody.Contains("urn:oasis:names:tc:SAML", StringComparison.OrdinalIgnoreCase)
                && XmlSamlMarker.IsMatch(entry.ResponseBody))
            {
                rawPayload = entry.ResponseBody;
                sourceKind = "xml-response";
                return true;
            }
        }

        return false;
    }

    public static bool LooksLikeModernIdpSamlTraffic(string url)
    {
        if (string.IsNullOrEmpty(url)) return false;
        return url.Contains("/api/saml/", StringComparison.OrdinalIgnoreCase)
               || url.Contains("identity-response", StringComparison.OrdinalIgnoreCase)
               || url.Contains("/SAML2/", StringComparison.OrdinalIgnoreCase)
               || url.Contains("/profile/SAML2/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryExtractFromQuery(string url, string param, out string value)
    {
        value = "";
        var q = url.IndexOf('?', StringComparison.Ordinal);
        if (q < 0) return false;
        foreach (var pair in url[(q + 1)..].Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0) continue;
            if (!pair[..eq].Equals(param, StringComparison.OrdinalIgnoreCase)) continue;
            value = pair[(eq + 1)..];
            return !string.IsNullOrEmpty(value);
        }

        return false;
    }

    private static bool TryExtractFormParam(string body, string param, out string value)
    {
        value = "";
        foreach (var pair in body.Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0) continue;
            if (!pair[..eq].Equals(param, StringComparison.OrdinalIgnoreCase)) continue;
            value = pair[(eq + 1)..];
            return !string.IsNullOrEmpty(value);
        }

        return false;
    }

    private static bool TryExtractFromJson(string json, out string payload)
    {
        payload = "";
        try
        {
            using var doc = JsonDocument.Parse(json);
            foreach (var name in new[] { "samlResponse", "SAMLResponse", "assertion", "token", "samlAssertion" })
            {
                if (!doc.RootElement.TryGetProperty(name, out var prop)) continue;
                if (prop.ValueKind == JsonValueKind.String)
                {
                    payload = prop.GetString() ?? "";
                    if (!string.IsNullOrEmpty(payload)) return true;
                }
            }
        }
        catch
        {
            // not JSON
        }

        return false;
    }
}
