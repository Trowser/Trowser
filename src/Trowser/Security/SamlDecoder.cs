using System.IO;
using System.IO.Compression;
using System.Text;
using System.Xml.Linq;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Decodes SAML messages from URL-encoded Base64+DEFLATE (HTTP-Redirect binding)
/// or plain Base64 (HTTP-POST binding), and parses the resulting XML into structured data.
/// Handles both SAMLRequest and SAMLResponse parameters.
/// </summary>
public class SamlDecoder
{
    private static readonly XNamespace Samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static readonly XNamespace Saml = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static readonly XNamespace Ds = "http://www.w3.org/2000/09/xmldsig#";

    private static readonly HashSet<string> SuspiciousBindings = new(StringComparer.OrdinalIgnoreCase)
    {
        "javascript:", "data:", "file:", "vbscript:", "blob:"
    };

    /// <summary>
    /// Decode the most recent SAML message from the network log.
    /// </summary>
    public static SamlDecodeResult DecodeFromNetwork(NetworkLog network, string? urlFilter = null)
    {
        var entries = network.Entries;
        if (entries.Count == 0)
            throw new InvalidOperationException("Network log is empty. Navigate through a SAML flow first.");

        // Search newest entries first, skip entries that fail to decode
        for (var i = entries.Count - 1; i >= 0; i--)
        {
            var entry = entries[i];
            var extracted = TryExtractSamlFromEntry(entry, urlFilter);
            if (extracted == null) continue;

            var (samlParam, samlValue, detectedBinding) = extracted.Value;
            var encoding = detectedBinding == "HTTP-Redirect" ? "redirect" : "post";

            try
            {
                return DecodeRaw(samlValue, encoding, entry, detectedBinding, samlParam);
            }
            catch
            {
                // Invalid content (fuzzing payloads, corrupted data) — skip and try next
            }
        }

        var hint = urlFilter != null ? $" matching '{urlFilter}'" : "";
        throw new InvalidOperationException(
            $"No valid SAML messages found in network log{hint}. " +
            "Navigate through a SAML login flow first, then call this endpoint. " +
            "Look for redirects to IdP URLs containing SAMLRequest parameters.");
    }

    /// <summary>
    /// Decode ALL SAML messages from the network log, returning both successes and failures.
    /// </summary>
    public static List<SamlDecodeResultOrError> DecodeAllFromNetwork(NetworkLog network, string? urlFilter = null)
    {
        var results = new List<SamlDecodeResultOrError>();
        var entries = network.Entries;

        for (var i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];
            var extracted = TryExtractSamlFromEntry(entry, urlFilter);
            if (extracted == null) continue;

            var (samlParam, samlValue, detectedBinding) = extracted.Value;
            var encoding = detectedBinding == "HTTP-Redirect" ? "redirect" : "post";

            try
            {
                var result = DecodeRaw(samlValue, encoding, entry, detectedBinding, samlParam);
                results.Add(new SamlDecodeResultOrError
                {
                    Success = true,
                    Result = result,
                    NetworkEntryId = entry.Id
                });
            }
            catch (Exception ex)
            {
                results.Add(new SamlDecodeResultOrError
                {
                    Success = false,
                    Error = $"Found {samlParam} parameter but decoding failed: {ex.Message}",
                    SourceUrl = entry.Url,
                    SourceMethod = entry.Method,
                    ParameterName = samlParam,
                    Timestamp = entry.Timestamp,
                    NetworkEntryId = entry.Id
                });
            }
        }

        return results;
    }

    /// <summary>
    /// Try to extract a SAML parameter from a network entry.
    /// Returns (paramName, paramValue, binding) or null if no SAML parameter found.
    /// </summary>
    private static (string paramName, string paramValue, string binding)? TryExtractSamlFromEntry(
        NetworkEntry entry, string? urlFilter)
    {
        if (urlFilter != null &&
            !entry.Url.Contains(urlFilter, StringComparison.OrdinalIgnoreCase))
            return null;

        // HTTP-Redirect: SAMLRequest or SAMLResponse in query string
        if (TryExtractFromQueryString(entry.Url, out var paramName, out var paramValue))
            return (paramName, paramValue, "HTTP-Redirect");

        // HTTP-POST: SAMLRequest or SAMLResponse in form-encoded request body
        if (entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase) &&
            entry.RequestBody != null &&
            TryExtractFromFormBody(entry.RequestBody, out paramName, out paramValue))
            return (paramName, paramValue, "HTTP-POST");

        return null;
    }

    /// <summary>
    /// Decode a raw SAML message string.
    /// </summary>
    public static SamlDecodeResult DecodeRaw(string raw, string encoding,
        NetworkEntry? sourceEntry = null, string? bindingOverride = null,
        string? paramNameOverride = null)
    {
        var isRedirect = encoding.Equals("redirect", StringComparison.OrdinalIgnoreCase);
        var binding = bindingOverride ?? (isRedirect ? "HTTP-Redirect" : "HTTP-POST");

        string xml;
        try
        {
            xml = isRedirect ? DecodeRedirectBinding(raw) : DecodePostBinding(raw);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Failed to decode SAML message ({binding} binding): {ex.Message}. " +
                "The data may be corrupted or use an unsupported encoding.", ex);
        }

        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Decoded content is not valid XML: {ex.Message}. " +
                "The parameter may contain non-SAML data (e.g., fuzzing payloads).", ex);
        }

        var root = doc.Root!;
        var messageType = DetermineMessageType(root);
        var parsed = ParseSamlXml(root, messageType);
        var signature = DetectSignature(root);
        var securityFindings = AnalyzeSecurity(root, messageType, signature, parsed);

        return new SamlDecodeResult
        {
            Binding = binding,
            MessageType = messageType,
            ParameterName = paramNameOverride ?? (messageType.Contains("Response") ? "SAMLResponse" : "SAMLRequest"),
            Xml = xml,
            Parsed = parsed,
            Signature = signature,
            SecurityFindings = securityFindings,
            SourceUrl = sourceEntry?.Url,
            SourceMethod = sourceEntry?.Method,
            Timestamp = sourceEntry?.Timestamp ?? DateTime.UtcNow
        };
    }

    private static string DecodeRedirectBinding(string raw)
    {
        // URL-decode → Base64-decode → raw DEFLATE-inflate (RFC 1951)
        var urlDecoded = Uri.UnescapeDataString(raw);
        var base64Bytes = Convert.FromBase64String(urlDecoded);

        using var input = new MemoryStream(base64Bytes);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress, leaveOpen: false);
        using var reader = new StreamReader(deflate, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static string DecodePostBinding(string raw)
    {
        // URL-decode (if URL-encoded) → Base64-decode
        var urlDecoded = Uri.UnescapeDataString(raw);
        var bytes = Convert.FromBase64String(urlDecoded);
        return Encoding.UTF8.GetString(bytes);
    }

    private static bool TryExtractFromQueryString(string url, out string paramName, out string paramValue)
    {
        paramName = "";
        paramValue = "";

        var qIndex = url.IndexOf('?');
        if (qIndex < 0) return false;

        var query = url[(qIndex + 1)..];
        foreach (var pair in query.Split('&'))
        {
            var eqIndex = pair.IndexOf('=');
            if (eqIndex < 0) continue;

            var key = pair[..eqIndex];
            if (key.Equals("SAMLRequest", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("SAMLResponse", StringComparison.OrdinalIgnoreCase))
            {
                paramName = key;
                paramValue = pair[(eqIndex + 1)..];
                return true;
            }
        }

        return false;
    }

    private static bool TryExtractFromFormBody(string body, out string paramName, out string paramValue)
    {
        paramName = "";
        paramValue = "";

        foreach (var pair in body.Split('&'))
        {
            var eqIndex = pair.IndexOf('=');
            if (eqIndex < 0) continue;

            var key = pair[..eqIndex];
            if (key.Equals("SAMLRequest", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("SAMLResponse", StringComparison.OrdinalIgnoreCase))
            {
                paramName = key;
                paramValue = pair[(eqIndex + 1)..];
                return true;
            }
        }

        return false;
    }

    private static string DetermineMessageType(XElement root)
    {
        var localName = root.Name.LocalName;
        return localName switch
        {
            "AuthnRequest" => "AuthnRequest",
            "Response" => "Response",
            "LogoutRequest" => "LogoutRequest",
            "LogoutResponse" => "LogoutResponse",
            "ArtifactResolve" => "ArtifactResolve",
            "ArtifactResponse" => "ArtifactResponse",
            "AttributeQuery" => "AttributeQuery",
            _ => localName
        };
    }

    private static Dictionary<string, object?> ParseSamlXml(XElement root, string messageType)
    {
        var parsed = new Dictionary<string, object?>
        {
            ["id"] = root.Attribute("ID")?.Value,
            ["version"] = root.Attribute("Version")?.Value,
            ["issueInstant"] = root.Attribute("IssueInstant")?.Value,
            ["destination"] = root.Attribute("Destination")?.Value,
            ["issuer"] = root.Element(Saml + "Issuer")?.Value
        };

        switch (messageType)
        {
            case "AuthnRequest":
                ParseAuthnRequest(root, parsed);
                break;
            case "Response":
                ParseResponse(root, parsed);
                break;
            case "LogoutRequest":
                ParseLogoutRequest(root, parsed);
                break;
            case "LogoutResponse":
                ParseLogoutResponse(root, parsed);
                break;
        }

        return parsed;
    }

    private static void ParseAuthnRequest(XElement root, Dictionary<string, object?> parsed)
    {
        parsed["assertionConsumerServiceURL"] = root.Attribute("AssertionConsumerServiceURL")?.Value;
        parsed["protocolBinding"] = root.Attribute("ProtocolBinding")?.Value;
        parsed["forceAuthn"] = ParseBoolAttr(root, "ForceAuthn");
        parsed["isPassive"] = ParseBoolAttr(root, "IsPassive");

        var nameIdPolicy = root.Element(Samlp + "NameIDPolicy");
        if (nameIdPolicy != null)
            parsed["nameIdPolicy"] = nameIdPolicy.Attribute("Format")?.Value;

        var requestedAuthnContext = root.Element(Samlp + "RequestedAuthnContext");
        if (requestedAuthnContext != null)
        {
            parsed["requestedAuthnContextComparison"] = requestedAuthnContext.Attribute("Comparison")?.Value;
            var classRefs = requestedAuthnContext.Elements(Saml + "AuthnContextClassRef")
                .Select(e => e.Value).ToList();
            if (classRefs.Count > 0)
                parsed["authnContextClassRefs"] = classRefs;
        }
    }

    private static void ParseResponse(XElement root, Dictionary<string, object?> parsed)
    {
        parsed["inResponseTo"] = root.Attribute("InResponseTo")?.Value;

        var status = root.Element(Samlp + "Status");
        var statusCode = status?.Element(Samlp + "StatusCode");
        parsed["statusCode"] = statusCode?.Attribute("Value")?.Value;

        var statusMessage = status?.Element(Samlp + "StatusMessage");
        if (statusMessage != null)
            parsed["statusMessage"] = statusMessage.Value;

        var assertion = root.Element(Saml + "Assertion");
        if (assertion != null)
        {
            var assertionData = new Dictionary<string, object?>
            {
                ["id"] = assertion.Attribute("ID")?.Value,
                ["issueInstant"] = assertion.Attribute("IssueInstant")?.Value,
                ["issuer"] = assertion.Element(Saml + "Issuer")?.Value
            };

            var subject = assertion.Element(Saml + "Subject");
            var nameId = subject?.Element(Saml + "NameID");
            if (nameId != null)
            {
                assertionData["subjectNameId"] = nameId.Value;
                assertionData["nameIdFormat"] = nameId.Attribute("Format")?.Value;
            }

            var conditions = assertion.Element(Saml + "Conditions");
            if (conditions != null)
            {
                assertionData["notBefore"] = conditions.Attribute("NotBefore")?.Value;
                assertionData["notOnOrAfter"] = conditions.Attribute("NotOnOrAfter")?.Value;

                var audienceRestriction = conditions.Element(Saml + "AudienceRestriction");
                var audiences = audienceRestriction?.Elements(Saml + "Audience")
                    .Select(e => e.Value).ToList();
                if (audiences is { Count: > 0 })
                    assertionData["audiences"] = audiences;
            }

            var authnStatement = assertion.Element(Saml + "AuthnStatement");
            if (authnStatement != null)
            {
                assertionData["sessionIndex"] = authnStatement.Attribute("SessionIndex")?.Value;
                assertionData["authnInstant"] = authnStatement.Attribute("AuthnInstant")?.Value;
                var authnContextClassRef = authnStatement
                    .Element(Saml + "AuthnContext")?
                    .Element(Saml + "AuthnContextClassRef")?.Value;
                if (authnContextClassRef != null)
                    assertionData["authnContextClassRef"] = authnContextClassRef;
            }

            var attrStatement = assertion.Element(Saml + "AttributeStatement");
            if (attrStatement != null)
            {
                var attributes = new List<Dictionary<string, object?>>();
                foreach (var attr in attrStatement.Elements(Saml + "Attribute"))
                {
                    var values = attr.Elements(Saml + "AttributeValue")
                        .Select(v => v.Value).ToList();
                    attributes.Add(new Dictionary<string, object?>
                    {
                        ["name"] = attr.Attribute("Name")?.Value,
                        ["friendlyName"] = attr.Attribute("FriendlyName")?.Value,
                        ["values"] = values
                    });
                }
                if (attributes.Count > 0)
                    assertionData["attributes"] = attributes;
            }

            parsed["assertion"] = assertionData;
        }
    }

    private static void ParseLogoutRequest(XElement root, Dictionary<string, object?> parsed)
    {
        var nameId = root.Element(Saml + "NameID");
        if (nameId != null)
        {
            parsed["nameId"] = nameId.Value;
            parsed["nameIdFormat"] = nameId.Attribute("Format")?.Value;
        }

        var sessionIndex = root.Element(Samlp + "SessionIndex");
        if (sessionIndex != null)
            parsed["sessionIndex"] = sessionIndex.Value;
    }

    private static void ParseLogoutResponse(XElement root, Dictionary<string, object?> parsed)
    {
        parsed["inResponseTo"] = root.Attribute("InResponseTo")?.Value;

        var status = root.Element(Samlp + "Status");
        var statusCode = status?.Element(Samlp + "StatusCode");
        parsed["statusCode"] = statusCode?.Attribute("Value")?.Value;
    }

    private static SamlSignatureInfo DetectSignature(XElement root)
    {
        var sig = root.Descendants(Ds + "Signature").FirstOrDefault();
        if (sig == null)
        {
            var assertion = root.Element(Saml + "Assertion");
            sig = assertion?.Element(Ds + "Signature");
        }

        if (sig == null)
            return new SamlSignatureInfo { Present = false };

        var signedInfo = sig.Element(Ds + "SignedInfo");
        var signatureMethod = signedInfo?.Element(Ds + "SignatureMethod");
        var algorithm = signatureMethod?.Attribute("Algorithm")?.Value;

        var references = signedInfo?.Elements(Ds + "Reference").ToList();
        var referenceUris = references?.Select(r => r.Attribute("URI")?.Value).ToList();

        var digestMethods = references?
            .Select(r => r.Element(Ds + "DigestMethod")?.Attribute("Algorithm")?.Value)
            .Where(d => d != null)
            .ToList();

        var sigLocation = sig.Parent?.Name.LocalName == "Assertion" ? "Assertion" : "Message";

        return new SamlSignatureInfo
        {
            Present = true,
            Algorithm = algorithm,
            DigestAlgorithm = digestMethods?.FirstOrDefault(),
            ReferenceUris = referenceUris!,
            Location = sigLocation
        };
    }

    private static List<SamlSecurityFinding> AnalyzeSecurity(XElement root, string messageType,
        SamlSignatureInfo signature, Dictionary<string, object?> parsed)
    {
        var findings = new List<SamlSecurityFinding>();

        // --- Signature checks (all message types) ---

        if (!signature.Present && messageType is "Response" or "AuthnRequest")
        {
            findings.Add(new SamlSecurityFinding
            {
                Severity = messageType == "Response" ? Severity.High : Severity.Medium,
                Category = "missing-signature",
                Description = $"SAML {messageType} has no XML signature. " +
                    (messageType == "Response"
                        ? "An unsigned Response can be forged by an attacker to impersonate any user. " +
                          "The SP must reject unsigned assertions (CVE-2025-25291/25292 ruby-saml, CVE-2025-47949 samlify)."
                        : "An unsigned AuthnRequest could be tampered with in transit.")
            });
        }

        if (signature.Present && signature.Algorithm != null)
        {
            if (signature.Algorithm.Contains("rsa-sha1") || signature.Algorithm.Contains("#sha1"))
            {
                findings.Add(new SamlSecurityFinding
                {
                    Severity = Severity.Medium,
                    Category = "weak-signature-algorithm",
                    Description = $"Signature uses SHA-1 ({signature.Algorithm}), which is cryptographically weak. " +
                                  "Upgrade to SHA-256 or SHA-512."
                });
            }
        }

        // Assertion-level vs message-level signature mismatch in Responses
        if (messageType == "Response" && signature.Present && signature.Location == "Message")
        {
            var assertion = root.Element(Saml + "Assertion");
            var assertionSig = assertion?.Element(Ds + "Signature");
            if (assertionSig == null)
            {
                findings.Add(new SamlSecurityFinding
                {
                    Severity = Severity.Medium,
                    Category = "assertion-unsigned",
                    Description = "The Response is signed but the embedded Assertion is not separately signed. " +
                                  "Signature-wrapping attacks may allow injection of a forged Assertion " +
                                  "while keeping the message-level signature valid."
                });
            }
        }

        // --- AuthnRequest-specific checks (E7-3) ---

        if (messageType == "AuthnRequest")
            AnalyzeAuthnRequest(root, parsed, findings);

        // --- Response/Assertion checks ---

        if (parsed.TryGetValue("assertion", out var assertionObj) && assertionObj is Dictionary<string, object?> assertionDict)
        {
            if (assertionDict.TryGetValue("notOnOrAfter", out var notAfter) && notAfter is string notAfterStr)
            {
                if (DateTime.TryParse(notAfterStr, out var expiry) && expiry < DateTime.UtcNow)
                {
                    findings.Add(new SamlSecurityFinding
                    {
                        Severity = Severity.Low,
                        Category = "expired-assertion",
                        Description = $"Assertion expired at {notAfterStr}. If the SP accepts this, it is vulnerable to assertion replay."
                    });
                }
            }

            if (!assertionDict.ContainsKey("audiences") || assertionDict["audiences"] == null)
            {
                findings.Add(new SamlSecurityFinding
                {
                    Severity = Severity.Medium,
                    Category = "no-audience-restriction",
                    Description = "No AudienceRestriction in the Assertion. This assertion may be replayed to other SPs."
                });
            }
        }

        return findings;
    }

    private static void AnalyzeAuthnRequest(XElement root, Dictionary<string, object?> parsed,
        List<SamlSecurityFinding> findings)
    {
        // Missing Version attribute (SAML 2.0 mandatory)
        var version = root.Attribute("Version")?.Value;
        if (string.IsNullOrEmpty(version))
        {
            findings.Add(new SamlSecurityFinding
            {
                Severity = Severity.Medium,
                Category = "missing-version",
                Description = "AuthnRequest is missing the mandatory Version attribute. " +
                              "SAML 2.0 requires Version=\"2.0\". This may cause undefined behavior at the IdP."
            });
        }
        else if (version != "2.0")
        {
            findings.Add(new SamlSecurityFinding
            {
                Severity = Severity.Low,
                Category = "unexpected-version",
                Description = $"AuthnRequest has Version=\"{version}\" (expected \"2.0\"). " +
                              "Non-standard versions may cause interoperability issues."
            });
        }

        // Old IssueInstant (potential replay)
        var issueInstant = root.Attribute("IssueInstant")?.Value;
        if (issueInstant != null && DateTime.TryParse(issueInstant, out var issued))
        {
            var age = DateTime.UtcNow - issued;
            if (age.TotalMinutes > 10)
            {
                findings.Add(new SamlSecurityFinding
                {
                    Severity = age.TotalHours > 24 ? Severity.Medium : Severity.Low,
                    Category = "old-issue-instant",
                    Description = $"AuthnRequest IssueInstant is {FormatAge(age)} old ({issueInstant}). " +
                                  "An IdP should reject requests with stale timestamps to prevent replay attacks."
                });
            }
        }
        else if (issueInstant == null)
        {
            findings.Add(new SamlSecurityFinding
            {
                Severity = Severity.Medium,
                Category = "missing-issue-instant",
                Description = "AuthnRequest is missing the IssueInstant attribute. " +
                              "Without a timestamp, the IdP cannot enforce replay protection."
            });
        }

        // Conflicting IsPassive + ForceAuthn
        var forceAuthn = ParseBoolAttr(root, "ForceAuthn");
        var isPassive = ParseBoolAttr(root, "IsPassive");
        if (forceAuthn == true && isPassive == true)
        {
            findings.Add(new SamlSecurityFinding
            {
                Severity = Severity.Medium,
                Category = "conflicting-authn-flags",
                Description = "AuthnRequest has both ForceAuthn=\"true\" and IsPassive=\"true\". " +
                              "These are contradictory: ForceAuthn requires interactive login while IsPassive " +
                              "forbids user interaction. Per SAML 2.0 spec, the IdP should return an error, " +
                              "but some IdPs silently ignore the conflict."
            });
        }

        // Suspicious ProtocolBinding values
        var protocolBinding = root.Attribute("ProtocolBinding")?.Value;
        if (protocolBinding != null)
        {
            foreach (var scheme in SuspiciousBindings)
            {
                if (protocolBinding.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new SamlSecurityFinding
                    {
                        Severity = Severity.High,
                        Category = "suspicious-protocol-binding",
                        Description = $"AuthnRequest has a suspicious ProtocolBinding value: \"{protocolBinding}\". " +
                                      $"The {scheme} scheme could indicate an injection attempt. " +
                                      "Expected values are urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST or HTTP-Redirect."
                    });
                    break;
                }
            }
        }

        // Suspicious AssertionConsumerServiceURL
        var acsUrl = root.Attribute("AssertionConsumerServiceURL")?.Value;
        if (acsUrl != null)
        {
            foreach (var scheme in SuspiciousBindings)
            {
                if (acsUrl.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new SamlSecurityFinding
                    {
                        Severity = Severity.High,
                        Category = "suspicious-acs-url",
                        Description = $"AuthnRequest has a suspicious AssertionConsumerServiceURL: \"{acsUrl}\". " +
                                      $"The {scheme} scheme in the ACS URL could be used to steal the SAML Response."
                    });
                    break;
                }
            }

            // Open redirect: ACS URL on a different domain than the Issuer
            if (parsed.TryGetValue("issuer", out var issuer) && issuer is string issuerStr &&
                Uri.TryCreate(acsUrl, UriKind.Absolute, out var acsUri) &&
                Uri.TryCreate(issuerStr, UriKind.Absolute, out var issuerUri))
            {
                if (!acsUri.Host.Equals(issuerUri.Host, StringComparison.OrdinalIgnoreCase) &&
                    !acsUri.Host.EndsWith("." + issuerUri.Host, StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new SamlSecurityFinding
                    {
                        Severity = Severity.Medium,
                        Category = "acs-domain-mismatch",
                        Description = $"AssertionConsumerServiceURL domain ({acsUri.Host}) differs from " +
                                      $"Issuer domain ({issuerUri.Host}). If the IdP does not validate " +
                                      "the ACS URL against registered SP metadata, an attacker could redirect " +
                                      "the SAML Response to a malicious endpoint."
                    });
                }
            }
        }
    }

    private static string FormatAge(TimeSpan age)
    {
        if (age.TotalDays >= 1) return $"{age.TotalDays:F0} day(s)";
        if (age.TotalHours >= 1) return $"{age.TotalHours:F0} hour(s)";
        return $"{age.TotalMinutes:F0} minute(s)";
    }

    private static bool? ParseBoolAttr(XElement el, string name)
    {
        var val = el.Attribute(name)?.Value;
        if (val == null) return null;
        return val.Equals("true", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Result of decoding a SAML message.
/// </summary>
public class SamlDecodeResult
{
    public string Binding { get; init; } = "";
    public string MessageType { get; init; } = "";
    public string ParameterName { get; init; } = "";
    public string Xml { get; init; } = "";
    public Dictionary<string, object?> Parsed { get; init; } = new();
    public SamlSignatureInfo Signature { get; init; } = new();
    public List<SamlSecurityFinding> SecurityFindings { get; init; } = new();
    public string? SourceUrl { get; init; }
    public string? SourceMethod { get; init; }
    public DateTime Timestamp { get; init; }

    public string Format(bool includeXml = true)
    {
        var lines = new List<string>
        {
            "=== SAML Message Decoded ===",
            $"Binding:      {Binding}",
            $"Message Type: {MessageType}",
            $"Parameter:    {ParameterName}",
            $"Time:         {Timestamp:yyyy-MM-dd HH:mm:ss}"
        };

        if (SourceUrl != null)
            lines.Add($"Source URL:    {SourceUrl}");

        lines.Add("");
        lines.Add("--- Parsed Fields ---");
        FormatDict(lines, Parsed, indent: 0);

        lines.Add("");
        lines.Add("--- Signature ---");
        if (Signature.Present)
        {
            lines.Add($"  Present:   Yes");
            lines.Add($"  Algorithm: {Signature.Algorithm ?? "(unknown)"}");
            lines.Add($"  Digest:    {Signature.DigestAlgorithm ?? "(unknown)"}");
            lines.Add($"  Location:  {Signature.Location}");
        }
        else
        {
            lines.Add("  Present: No (message is unsigned)");
        }

        if (SecurityFindings.Count > 0)
        {
            lines.Add("");
            lines.Add("--- Security Findings ---");
            foreach (var f in SecurityFindings.OrderByDescending(f => f.Severity))
            {
                lines.Add($"  [{f.Severity.ToString().ToUpper()}] {f.Category}: {f.Description}");
            }
        }

        if (includeXml)
        {
            lines.Add("");
            lines.Add("--- Raw XML ---");
            try
            {
                var doc = XDocument.Parse(Xml);
                lines.Add(doc.ToString());
            }
            catch
            {
                lines.Add(Xml);
            }
        }

        lines.Add("============================");
        return string.Join(Environment.NewLine, lines);
    }

    internal static void FormatDict(List<string> lines, Dictionary<string, object?> dict, int indent)
    {
        var prefix = new string(' ', indent * 2 + 2);
        foreach (var (key, value) in dict)
        {
            if (value == null) continue;
            if (value is Dictionary<string, object?> nested)
            {
                lines.Add($"{prefix}{key}:");
                FormatDict(lines, nested, indent + 1);
            }
            else if (value is List<string> list)
            {
                lines.Add($"{prefix}{key}: [{string.Join(", ", list)}]");
            }
            else if (value is List<Dictionary<string, object?>> listOfDicts)
            {
                lines.Add($"{prefix}{key}:");
                foreach (var d in listOfDicts)
                {
                    var nameVal = d.TryGetValue("name", out var n) ? n?.ToString() : "?";
                    var vals = d.TryGetValue("values", out var v) && v is List<string> vl
                        ? string.Join(", ", vl) : "";
                    var friendly = d.TryGetValue("friendlyName", out var fn) && fn != null
                        ? $" ({fn})" : "";
                    lines.Add($"{prefix}  - {nameVal}{friendly} = {vals}");
                }
            }
            else
            {
                lines.Add($"{prefix}{key}: {value}");
            }
        }
    }
}

/// <summary>
/// Wrapper for findAll mode: either a successful decode or an error for entries that couldn't be decoded.
/// </summary>
public class SamlDecodeResultOrError
{
    public bool Success { get; init; }
    public SamlDecodeResult? Result { get; init; }
    public string? Error { get; init; }
    public string? SourceUrl { get; init; }
    public string? SourceMethod { get; init; }
    public string? ParameterName { get; init; }
    public DateTime Timestamp { get; init; }
    public int NetworkEntryId { get; init; }
}

public class SamlSignatureInfo
{
    public bool Present { get; init; }
    public string? Algorithm { get; init; }
    public string? DigestAlgorithm { get; init; }
    public List<string?>? ReferenceUris { get; init; }
    public string? Location { get; init; }
}

public class SamlSecurityFinding
{
    public Severity Severity { get; init; }
    public string Category { get; init; } = "";
    public string Description { get; init; } = "";
}
