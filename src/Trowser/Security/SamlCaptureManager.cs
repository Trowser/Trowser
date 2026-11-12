using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Captures SAML messages from the browser's network log during SSO flows.
/// Arms itself to watch for the next SAMLResponse POST (and optionally SAMLRequest),
/// then stores the captured data for inspection and replay testing.
///
/// Capture modes:
/// - "next-login": Arms capture, then waits for the next SAMLResponse POST to the SP's ACS endpoint.
/// - "network": Searches existing network log entries for SAML responses.
/// </summary>
public class SamlCaptureManager
{
    private static readonly XNamespace Saml = "urn:oasis:names:tc:SAML:2.0:assertion";

    private volatile bool _armed;
    private volatile bool _captureRequests;
    private SamlCapturedAssertion? _captured;
    private SamlCapturedRequest? _capturedRequest;
    private readonly object _lock = new();

    public bool IsArmed
    {
        get { lock (_lock) return _armed; }
    }

    /// <summary>
    /// Arm the capture to watch for the next SAML login.
    /// </summary>
    public void Arm(bool captureRequests = false)
    {
        lock (_lock)
        {
            _armed = true;
            _captureRequests = captureRequests;
            _captured = null;
            _capturedRequest = null;
        }
    }

    /// <summary>
    /// Disarm without capturing.
    /// </summary>
    public void Disarm()
    {
        lock (_lock)
        {
            _armed = false;
        }
    }

    /// <summary>
    /// Try to capture from a network entry if we're armed.
    /// Called from the network event handler for each request.
    /// </summary>
    public bool TryCapture(NetworkEntry entry)
    {
        lock (_lock)
        {
            if (!_armed) return false;

            // Capture SAMLRequest (outgoing) if enabled
            if (_captureRequests && _capturedRequest == null)
            {
                if (TryExtractSamlRequest(entry, out var samlRequest, out var requestBinding))
                {
                    try
                    {
                        var decoded = requestBinding == "HTTP-Redirect"
                            ? SamlDecoder.DecodeRaw(samlRequest, "redirect", entry, "HTTP-Redirect", "SAMLRequest")
                            : SamlDecoder.DecodeRaw(samlRequest, "post", entry, "HTTP-POST", "SAMLRequest");

                        _capturedRequest = new SamlCapturedRequest
                        {
                            RawSamlRequest = samlRequest,
                            Binding = requestBinding,
                            Url = entry.Url,
                            Timestamp = entry.Timestamp,
                            Decoded = decoded
                        };
                    }
                    catch
                    {
                        // Non-decodable SAMLRequest — ignore
                    }
                }
            }

            // Capture SAMLResponse (incoming)
            if (!entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)) return false;
            if (entry.RequestBody == null) return false;

            if (!TryExtractSamlResponse(entry.RequestBody, out var samlResponse, out var relayState))
                return false;

            string xml;
            try
            {
                var urlDecoded = Uri.UnescapeDataString(samlResponse);
                var bytes = Convert.FromBase64String(urlDecoded);
                xml = Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return false;
            }

            SamlDecodeResult decoded2;
            try
            {
                decoded2 = SamlDecoder.DecodeRaw(samlResponse, "post", entry, "HTTP-POST", "SAMLResponse");
            }
            catch
            {
                return false;
            }

            _captured = new SamlCapturedAssertion
            {
                RawSamlResponse = samlResponse,
                RelayState = relayState,
                Xml = xml,
                TargetUrl = entry.Url,
                Binding = "POST",
                Timestamp = entry.Timestamp,
                Decoded = decoded2
            };

            _armed = false;
            return true;
        }
    }

    /// <summary>
    /// Get the captured assertion, or null if nothing captured yet.
    /// </summary>
    public SamlCapturedAssertion? GetCaptured()
    {
        lock (_lock)
        {
            return _captured;
        }
    }

    /// <summary>
    /// Get the captured outgoing request, or null if not captured.
    /// </summary>
    public SamlCapturedRequest? GetCapturedRequest()
    {
        lock (_lock)
        {
            return _capturedRequest;
        }
    }

    /// <summary>
    /// Search existing network log for the most recent SAML Response.
    /// </summary>
    public SamlCapturedAssertion? CaptureFromNetworkLog(NetworkLog network, string? urlFilter = null)
    {
        var entries = network.Entries;
        for (var i = entries.Count - 1; i >= 0; i--)
        {
            var entry = entries[i];
            if (urlFilter != null &&
                !entry.Url.Contains(urlFilter, StringComparison.OrdinalIgnoreCase))
                continue;

            if (!SamlNetworkExtract.TryExtractSamlResponsePayload(entry, out var samlResponse, out var sourceKind))
                continue;

            var relayState = entry.RequestBody != null
                             && TryExtractSamlResponse(entry.RequestBody, out _, out var rs)
                ? rs
                : null;

            string xml;
            if (sourceKind.Equals("xml-response", StringComparison.OrdinalIgnoreCase))
            {
                xml = samlResponse;
            }
            else
            {
                try
                {
                    var urlDecoded = Uri.UnescapeDataString(samlResponse);
                    var bytes = Convert.FromBase64String(urlDecoded);
                    xml = Encoding.UTF8.GetString(bytes);
                }
                catch
                {
                    continue;
                }
            }

            SamlDecodeResult decoded;
            try
            {
                var rawForDecoder = sourceKind.Equals("xml-response", StringComparison.OrdinalIgnoreCase)
                    ? Convert.ToBase64String(Encoding.UTF8.GetBytes(xml))
                    : samlResponse;
                decoded = SamlDecoder.DecodeRaw(rawForDecoder, "post", entry, sourceKind, "SAMLResponse");
            }
            catch
            {
                continue;
            }

            var captured = new SamlCapturedAssertion
            {
                RawSamlResponse = samlResponse,
                RelayState = relayState,
                Xml = xml,
                TargetUrl = entry.Url,
                Binding = sourceKind.Equals("form-post", StringComparison.OrdinalIgnoreCase) ? "POST" : sourceKind,
                Timestamp = entry.Timestamp,
                Decoded = decoded
            };

            lock (_lock)
            {
                _captured = captured;
            }

            return captured;
        }

        return null;
    }

    /// <summary>
    /// Build a modified SAML assertion for replay testing.
    /// </summary>
    public static SamlReplayPayload BuildReplay(SamlCapturedAssertion original,
        string? targetUrl = null,
        bool removeSignature = false,
        string? changeSubject = null,
        bool expireAssertion = false,
        bool removeAudienceRestriction = false,
        string? changeIssuer = null,
        int? extendValidityMinutes = null,
        string? customXml = null)
    {
        string modifiedXml;
        var modifications = new List<string>();

        if (customXml != null)
        {
            // Validate that custom XML is parseable
            try { XDocument.Parse(customXml); }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"customXml is not valid XML: {ex.Message}");
            }
            modifiedXml = customXml;
            modifications.Add("Applied custom XML (full replacement)");
        }
        else
        {
            var doc = XDocument.Parse(original.Xml);
            var root = doc.Root!;

            if (removeSignature)
            {
                var ds = XNamespace.Get("http://www.w3.org/2000/09/xmldsig#");
                var signatures = root.Descendants(ds + "Signature").ToList();
                foreach (var sig in signatures)
                    sig.Remove();
                modifications.Add("Removed all XML signatures");
            }

            if (changeSubject != null)
            {
                var nameIds = root.Descendants(Saml + "NameID").ToList();
                foreach (var nameId in nameIds)
                {
                    var oldValue = nameId.Value;
                    nameId.Value = changeSubject;
                    modifications.Add($"Changed NameID from '{oldValue}' to '{changeSubject}'");
                }
            }

            if (expireAssertion)
            {
                var conditions = root.Descendants(Saml + "Conditions").FirstOrDefault();
                if (conditions != null)
                {
                    var expired = DateTime.UtcNow.AddHours(-24).ToString("o");
                    conditions.SetAttributeValue("NotOnOrAfter", expired);
                    modifications.Add($"Set NotOnOrAfter to expired time ({expired})");
                }
            }

            if (extendValidityMinutes.HasValue)
            {
                var conditions = root.Descendants(Saml + "Conditions").FirstOrDefault();
                if (conditions != null)
                {
                    var extended = DateTime.UtcNow.AddMinutes(extendValidityMinutes.Value).ToString("o");
                    conditions.SetAttributeValue("NotBefore", DateTime.UtcNow.AddMinutes(-5).ToString("o"));
                    conditions.SetAttributeValue("NotOnOrAfter", extended);
                    modifications.Add($"Extended validity window to {extendValidityMinutes.Value} minutes from now");
                }
            }

            if (removeAudienceRestriction)
            {
                var audienceRestrictions = root.Descendants(Saml + "AudienceRestriction").ToList();
                foreach (var ar in audienceRestrictions)
                    ar.Remove();
                modifications.Add("Removed AudienceRestriction elements");
            }

            if (changeIssuer != null)
            {
                var issuers = root.Descendants(Saml + "Issuer").ToList();
                foreach (var issuer in issuers)
                {
                    var oldValue = issuer.Value;
                    issuer.Value = changeIssuer;
                    modifications.Add($"Changed Issuer from '{oldValue}' to '{changeIssuer}'");
                }
            }

            modifiedXml = doc.ToString();
        }

        var modifiedBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(modifiedXml));

        var formBody = $"SAMLResponse={Uri.EscapeDataString(modifiedBase64)}";
        if (!string.IsNullOrEmpty(original.RelayState))
            formBody += $"&RelayState={Uri.EscapeDataString(original.RelayState)}";

        return new SamlReplayPayload
        {
            TargetUrl = targetUrl ?? original.TargetUrl,
            ModifiedXml = modifiedXml,
            ModifiedBase64 = modifiedBase64,
            FormBody = formBody,
            RelayState = original.RelayState,
            Modifications = modifications,
            OriginalTimestamp = original.Timestamp
        };
    }

    /// <summary>
    /// Execute a SAML replay using browser's fetch API.
    /// </summary>
    public static async Task<SamlReplayResult> ExecuteReplayAsync(
        AutomationContext context, SamlReplayPayload payload)
    {
        var js = $@"
(async function() {{
    try {{
        const resp = await fetch('{EscapeJs(payload.TargetUrl)}', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
            body: {EscapeJsString(payload.FormBody)},
            redirect: 'follow',
            credentials: 'include'
        }});
        const text = await resp.text();
        return JSON.stringify({{
            status: resp.status,
            statusText: resp.statusText,
            url: resp.url,
            redirected: resp.redirected,
            bodyLength: text.length,
            bodySnippet: text.substring(0, 2000)
        }});
    }} catch (e) {{
        return JSON.stringify({{ error: e.message }});
    }}
}})()";

        var resultJson = await context.ExecuteJs(js);
        var parsed = ParseFetchReplayJson(resultJson);

        return new SamlReplayResult
        {
            TargetUrl = payload.TargetUrl,
            Modifications = payload.Modifications,
            RawResponse = parsed.BodySnippet ?? resultJson,
            ResponseStatus = parsed.Status,
            ResponseStatusText = parsed.StatusText,
            ResponseUrl = parsed.Url,
            Redirected = parsed.Redirected,
            BodyLength = parsed.BodyLength,
            Timestamp = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Parse the JSON object returned by the in-page fetch helper (may be double-encoded as a JSON string).
    /// </summary>
    private static FetchReplayParsed ParseFetchReplayJson(string resultJson)
    {
        if (string.IsNullOrWhiteSpace(resultJson))
            return default;

        try
        {
            if (TryParseFetchReplayElement(ParseReplayJsonRoot(resultJson), out var parsed))
                return parsed;
        }
        catch
        {
            // fall through — caller keeps raw JSON in RawResponse
        }

        return default;
    }

    private static JsonElement ParseReplayJsonRoot(string resultJson)
    {
        var trimmed = resultJson.Trim();
        using var doc = JsonDocument.Parse(trimmed);
        var root = doc.RootElement;
        if (root.ValueKind == JsonValueKind.String)
        {
            var inner = root.GetString();
            if (string.IsNullOrWhiteSpace(inner))
                return default;
            using var innerDoc = JsonDocument.Parse(inner);
            return innerDoc.RootElement.Clone();
        }

        return root.Clone();
    }

    private static bool TryParseFetchReplayElement(JsonElement root, out FetchReplayParsed parsed)
    {
        parsed = default;
        if (root.ValueKind != JsonValueKind.Object)
            return false;

        if (root.TryGetProperty("error", out var errProp) && errProp.ValueKind == JsonValueKind.String)
        {
            parsed.StatusText = errProp.GetString();
            return true;
        }

        if (root.TryGetProperty("status", out var statusProp))
        {
            if (statusProp.ValueKind == JsonValueKind.Number)
                parsed.Status = statusProp.GetInt32();
            else if (statusProp.ValueKind == JsonValueKind.String &&
                     int.TryParse(statusProp.GetString(), out var statusCode))
                parsed.Status = statusCode;
        }

        if (root.TryGetProperty("statusText", out var stProp) && stProp.ValueKind == JsonValueKind.String)
            parsed.StatusText = stProp.GetString();
        if (root.TryGetProperty("url", out var urlProp) && urlProp.ValueKind == JsonValueKind.String)
            parsed.Url = urlProp.GetString();
        if (root.TryGetProperty("redirected", out var redProp) && redProp.ValueKind is JsonValueKind.True or JsonValueKind.False)
            parsed.Redirected = redProp.GetBoolean();
        if (root.TryGetProperty("bodyLength", out var blProp) && blProp.ValueKind == JsonValueKind.Number)
            parsed.BodyLength = blProp.GetInt32();
        if (root.TryGetProperty("bodySnippet", out var snProp) && snProp.ValueKind == JsonValueKind.String)
            parsed.BodySnippet = snProp.GetString();

        return parsed.Status.HasValue || !string.IsNullOrEmpty(parsed.StatusText) || !string.IsNullOrEmpty(parsed.BodySnippet);
    }

    private struct FetchReplayParsed
    {
        public int? Status;
        public string? StatusText;
        public string? Url;
        public bool? Redirected;
        public int? BodyLength;
        public string? BodySnippet;
    }

    private static bool TryExtractSamlResponse(string body, out string samlResponse, out string? relayState)
    {
        samlResponse = "";
        relayState = null;

        foreach (var pair in body.Split('&'))
        {
            var eqIndex = pair.IndexOf('=');
            if (eqIndex < 0) continue;

            var key = pair[..eqIndex];
            var value = pair[(eqIndex + 1)..];

            if (key.Equals("SAMLResponse", StringComparison.OrdinalIgnoreCase))
                samlResponse = value;
            else if (key.Equals("RelayState", StringComparison.OrdinalIgnoreCase))
                relayState = Uri.UnescapeDataString(value);
        }

        return !string.IsNullOrEmpty(samlResponse);
    }

    private static bool TryExtractSamlRequest(NetworkEntry entry, out string samlRequest, out string binding)
    {
        samlRequest = "";
        binding = "";

        // Check query string (HTTP-Redirect)
        var qIndex = entry.Url.IndexOf('?');
        if (qIndex >= 0)
        {
            var query = entry.Url[(qIndex + 1)..];
            foreach (var pair in query.Split('&'))
            {
                var eqIndex = pair.IndexOf('=');
                if (eqIndex < 0) continue;
                var key = pair[..eqIndex];
                if (key.Equals("SAMLRequest", StringComparison.OrdinalIgnoreCase))
                {
                    samlRequest = pair[(eqIndex + 1)..];
                    binding = "HTTP-Redirect";
                    return true;
                }
            }
        }

        // Check POST body (HTTP-POST)
        if (entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase) && entry.RequestBody != null)
        {
            foreach (var pair in entry.RequestBody.Split('&'))
            {
                var eqIndex = pair.IndexOf('=');
                if (eqIndex < 0) continue;
                var key = pair[..eqIndex];
                if (key.Equals("SAMLRequest", StringComparison.OrdinalIgnoreCase))
                {
                    samlRequest = pair[(eqIndex + 1)..];
                    binding = "HTTP-POST";
                    return true;
                }
            }
        }

        return false;
    }

    private static string EscapeJs(string s) =>
        s.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\n", "\\n").Replace("\r", "\\r");

    private static string EscapeJsString(string s)
    {
        var escaped = s
            .Replace("\\", "\\\\")
            .Replace("'", "\\'")
            .Replace("\n", "\\n")
            .Replace("\r", "\\r");
        return $"'{escaped}'";
    }
}

/// <summary>
/// A SAML assertion captured from a login flow.
/// </summary>
public class SamlCapturedAssertion
{
    public string RawSamlResponse { get; init; } = "";
    public string? RelayState { get; init; }
    public string Xml { get; init; } = "";
    public string TargetUrl { get; init; } = "";
    public string Binding { get; init; } = "";
    public DateTime Timestamp { get; init; }
    public SamlDecodeResult Decoded { get; init; } = null!;

    public string Format(bool includeXml = true)
    {
        var lines = new List<string>
        {
            "=== Captured SAML Assertion ===",
            $"Target URL:   {TargetUrl}",
            $"Binding:      {Binding}",
            $"Captured at:  {Timestamp:yyyy-MM-dd HH:mm:ss}",
            $"RelayState:   {RelayState ?? "(none)"}"
        };

        lines.Add("");
        lines.Add(Decoded.Format(includeXml));
        lines.Add("===============================");

        return string.Join(Environment.NewLine, lines);
    }
}

/// <summary>
/// A captured outgoing SAMLRequest.
/// </summary>
public class SamlCapturedRequest
{
    public string RawSamlRequest { get; init; } = "";
    public string Binding { get; init; } = "";
    public string Url { get; init; } = "";
    public DateTime Timestamp { get; init; }
    public SamlDecodeResult Decoded { get; init; } = null!;

    public string Format(bool includeXml = true)
    {
        var lines = new List<string>
        {
            "=== Captured SAMLRequest (Outgoing) ===",
            $"URL:         {Url}",
            $"Binding:     {Binding}",
            $"Captured at: {Timestamp:yyyy-MM-dd HH:mm:ss}"
        };

        lines.Add("");
        lines.Add(Decoded.Format(includeXml));
        lines.Add("========================================");

        return string.Join(Environment.NewLine, lines);
    }
}

/// <summary>
/// A modified SAML assertion ready for replay.
/// </summary>
public class SamlReplayPayload
{
    public string TargetUrl { get; init; } = "";
    public string ModifiedXml { get; init; } = "";
    public string ModifiedBase64 { get; init; } = "";
    public string FormBody { get; init; } = "";
    public string? RelayState { get; init; }
    public List<string> Modifications { get; init; } = new();
    public DateTime OriginalTimestamp { get; init; }
}

/// <summary>
/// Result of replaying a modified SAML assertion.
/// </summary>
public class SamlReplayResult
{
    public string TargetUrl { get; init; } = "";
    public List<string> Modifications { get; init; } = new();
    public string RawResponse { get; init; } = "";
    public int? ResponseStatus { get; init; }
    public string? ResponseStatusText { get; init; }
    public string? ResponseUrl { get; init; }
    public bool? Redirected { get; init; }
    public int? BodyLength { get; init; }
    public DateTime Timestamp { get; init; }

    public string Format()
    {
        var lines = new List<string>
        {
            "=== SAML Replay Result ===",
            $"Target URL: {TargetUrl}",
            $"Time:       {Timestamp:yyyy-MM-dd HH:mm:ss}"
        };

        if (ResponseStatus.HasValue)
        {
            lines.Add($"Status:     {ResponseStatus} {ResponseStatusText ?? ""}".TrimEnd());
            if (Redirected == true && ResponseUrl != null)
                lines.Add($"Redirected: {ResponseUrl}");
            if (BodyLength.HasValue)
                lines.Add($"Body size:  {BodyLength} chars");
        }

        lines.Add("");
        lines.Add("Modifications applied:");
        foreach (var mod in Modifications)
            lines.Add($"  - {mod}");

        lines.Add("");
        lines.Add("Response:");
        lines.Add(RawResponse);
        lines.Add("==========================");

        return string.Join(Environment.NewLine, lines);
    }
}
