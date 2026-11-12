using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Shared false-positive filters, framework boilerplate detection, and severity calibration
/// for <see cref="SecretsHarvestPipeline"/> and related scanners.
/// </summary>
public static class SecretsHarvestHeuristics
{
    /// <summary>Literal secret values that are placeholders, not real credentials.</summary>
    public static readonly string[] FalsePositiveValues =
    [
        "true", "false", "null", "undefined", "password", "passwd", "changeme",
        "placeholder", "your_password", "your-password", "yourpassword",
        "********", "*********", "xxx", "xxxx", "xxxxx",
        "DUMMY_PASSWORD", "DUMMY_SECRET", "stubTrue", "stubFalse",
        "secret", "token", "apikey", "api_key", "access_token", "refresh_token",
        "client_secret", "client_id", "username", "user", "email", "login",
        "example", "sample", "test", "demo", "dummy", "fake", "none", "n/a",
        // UI form labels / i18n strings commonly adjacent to password fields in bundles
        "Password", "Password:", "Passwort", "Mot de passe", "Contraseña",
        "Enter password", "Your password", "Confirm password", "New password"
    ];

    /// <summary>Values that look like UI labels rather than credential material.</summary>
    public static bool IsUiLabelSecretValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return true;
        var v = value.Trim();
        if (v.EndsWith(':') && v.Length <= 24) return true;
        if (FalsePositiveValues.Any(fp => v.Equals(fp, StringComparison.OrdinalIgnoreCase)))
            return true;
        // Short alphabetic labels with spaces (e.g. "Confirm password")
        if (v.Length <= 32 && v.All(c => char.IsLetter(c) || c is ' ' or '-' or ':' or '\'')
            && v.Contains(' ', StringComparison.Ordinal))
            return true;
        return false;
    }

    /// <summary>
    /// True when a credential-like assignment lacks proof of a real secret
    /// (UI labels, mirrored key names, very low-entropy values).
    /// </summary>
    public static bool IsWeakCredentialAssignment(string? keyHint, string? value)
    {
        if (IsPlaceholderSecretValue(value) || IsUiLabelSecretValue(value))
            return true;
        if (string.IsNullOrWhiteSpace(value)) return true;
        var v = value.Trim();
        if (!string.IsNullOrEmpty(keyHint)
            && v.Equals(keyHint, StringComparison.OrdinalIgnoreCase))
            return true;
        // Require some entropy for high-severity claims: reject pure dictionary words ≤ 12 chars.
        if (v.Length <= 12 && v.All(char.IsLetter))
            return true;
        return false;
    }

    /// <summary>Snippet context from library internals (lodash FP maps, etc.).</summary>
    public static readonly string[] FalsePositiveContextPatterns =
    [
        "stubTrue", "stubFalse", "allPass", "anyPass", "overEvery", "overSome",
        "\"T\":\"stub", "'T':'stub",
        "noop", "thru", "identity", "iteratee",
        "conforms", "cloneDeep", "flowRight"
    ];

    private static readonly Regex QuotedValue = new(
        @"(?<=[=:]\s*['""])([^'""\n]{2,200})(?=['""])",
        RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    /// <summary>
    /// ALL_CAPS identifier assignments like AUTOSTARTTOKEN="auto" — the generic secret regex
    /// false-positives on the TOKEN= suffix inside compound names.
    /// </summary>
    private static readonly Regex CompoundIdentifierAssignment = new(
        @"\b([A-Z][A-Z0-9_]{2,}(?:TOKEN|SECRET|KEY|PASSWORD))\s*[=:]\s*['""]([^'""\n]{1,200})['""]",
        RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    /// <summary>Short literal values typical of client-side feature flags, not credentials.</summary>
    private static readonly string[] IdentifierConstantValues =
    [
        "auto", "multicard", "none", "default", "true", "false", "enabled", "disabled",
        "bankid", "siths", "freja", "mock", "test", "dev", "prod", "qa"
    ];

    public static bool IsPlaceholderSecretValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return true;
        if (value.Length < 2) return true;
        if (FalsePositiveValues.Any(fp => value.Equals(fp, StringComparison.OrdinalIgnoreCase)))
            return true;
        if (value.All(c => c == '*' || c == 'x' || c == 'X' || c == '#'))
            return true;
        if (value.StartsWith("{{", StringComparison.Ordinal) && value.EndsWith("}}", StringComparison.Ordinal))
            return true;
        if (value.StartsWith("${", StringComparison.Ordinal) && value.EndsWith('}'))
            return true;
        return false;
    }

    public static bool IsFalsePositiveSnippet(string snippet) =>
        FalsePositiveContextPatterns.Any(fp =>
            snippet.Contains(fp, StringComparison.OrdinalIgnoreCase));

    /// <summary>Retina filenames like <c>hero@2x.png</c> match email regex (@2x as faux domain).</summary>
    public static bool IsRetinaAssetEmailFalsePositive(string match)
    {
        if (string.IsNullOrEmpty(match)) return false;
        return Regex.IsMatch(
            match,
            @"@[23]x\.(png|jpe?g|webp|gif|svg|avif)$",
            RegexOptions.IgnoreCase,
            TimeSpan.FromSeconds(1));
    }

    public static bool IsLicenseComment(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        return text.Contains("license", StringComparison.OrdinalIgnoreCase)
            || text.Contains("copyright", StringComparison.OrdinalIgnoreCase)
            || text.Contains("(c) ", StringComparison.OrdinalIgnoreCase)
            || text.Contains("mit ", StringComparison.OrdinalIgnoreCase)
            || text.Contains("apache ", StringComparison.OrdinalIgnoreCase)
            || text.Contains("bsd ", StringComparison.OrdinalIgnoreCase)
            || text.Contains("gpl", StringComparison.OrdinalIgnoreCase)
            || text.Contains("proprietary", StringComparison.OrdinalIgnoreCase)
            || text.Contains("all rights reserved", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsStandardFrameworkConfig(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        var lower = text.ToLowerInvariant();
        return lower.Contains("xsrf-token")
            || lower.Contains("csrf-token")
            || lower.Contains("x-xsrf")
            || lower.Contains("x-csrf")
            || lower.Contains("__requestverificationtoken")
            || lower.Contains("antiforgerytoken")
            || lower.Contains("__nonce")
            || lower.Contains("webpackjsonp")
            || lower.Contains("__webpack")
            || lower.Contains("__next_f")
            || lower.Contains("next-flight")
            || lower.Contains("__secret_internals")
            || lower.Contains("__vue__")
            || lower.Contains("ngdevmode")
            || lower.Contains("redux_devtools")
            || lower.Contains("grant_type")
            || lower.Contains("client_id")
            || (lower.Contains("angular") && lower.Contains("config"))
            || (lower.Contains("react") && lower.Contains("refresh"));
    }

    public static bool IsFrameworkBoilerplate(SecretsHarvestPipeline.SecretFinding f)
    {
        var snippet = f.Snippet ?? "";
        var desc = f.Description ?? "";
        var loc = f.Location ?? "";
        var combined = $"{snippet} {desc} {loc}";
        return IsStandardFrameworkConfig(combined)
            || IsLicenseComment(snippet)
            || IsLicenseComment(desc);
    }

    public static bool IsBinaryGarbage(string text)
    {
        if (string.IsNullOrEmpty(text) || text.Length < 10) return false;
        var nonPrintable = text.Count(c => c < 0x20 && c != '\n' && c != '\r' && c != '\t');
        return nonPrintable > text.Length / 4;
    }

    /// <summary>Third-party or vendor bundles — downgrade severity one step.</summary>
    public static bool IsVendorBundleUrl(string? url)
    {
        if (string.IsNullOrEmpty(url)) return false;
        var lower = url.ToLowerInvariant();
        return lower.Contains("/vendor")
            || lower.Contains("/vendors/")
            || lower.Contains("vendor.")
            || lower.Contains(".vendor.")
            || lower.Contains("/chunk-vendors")
            || lower.Contains("vendors~")
            || lower.Contains("node_modules")
            || lower.Contains("/npm/")
            || lower.Contains("/cdn.jsdelivr.net/")
            || lower.Contains("/unpkg.com/")
            || lower.Contains("/cdnjs.cloudflare.com/")
            || lower.Contains("/ajax.googleapis.com/")
            || lower.Contains("-vendor.")
            || lower.Contains(".vendor-")
            || lower.Contains("/lib/")
            || Regex.IsMatch(lower, @"[/\-_]vendor[\.\-_]", RegexOptions.None, TimeSpan.FromSeconds(1));
    }

    /// <summary>Chromium / WebView origin-trial metadata often base64-decodes into faux secrets.</summary>
    public static bool IsChromiumOriginTrialMetadata(string text)
    {
        if (string.IsNullOrEmpty(text) || text.Length < 24)
            return false;

        return text.Contains("\"origin\"", StringComparison.Ordinal)
               && text.Contains("\"feature\"", StringComparison.Ordinal)
               && (text.Contains("\"expiry\"", StringComparison.Ordinal)
                   || text.Contains("WebViewXRequestedWithDeprecation", StringComparison.Ordinal)
                   || text.Contains("AIPromptAPIMultimodalInput", StringComparison.Ordinal));
    }

    public static bool IsCurrencyOrExchangeRateUrl(string? location)
    {
        if (string.IsNullOrEmpty(location)) return false;
        var lower = location.ToLowerInvariant();
        return lower.Contains("currency-file", StringComparison.Ordinal)
               || lower.Contains("currency/rates", StringComparison.Ordinal)
               || lower.Contains("/exchange-rate", StringComparison.Ordinal)
               || lower.Contains("prebid/currency", StringComparison.Ordinal)
               || lower.Contains("latest.json?date=", StringComparison.Ordinal);
    }

    /// <summary>Luhn-valid numbers in FX JSON (e.g. prebid currency-file) are not PANs.</summary>
    public static bool LooksLikeCurrencyRateContext(string text, int matchIndex)
    {
        var start = Math.Max(0, matchIndex - 100);
        var len = Math.Min(text.Length - start, 220);
        if (len <= 0) return false;
        var window = text.AsSpan(start, len);
        return window.Contains("\"USD\"", StringComparison.OrdinalIgnoreCase)
               || window.Contains("\"EUR\"", StringComparison.OrdinalIgnoreCase)
               || window.Contains("\"GBP\"", StringComparison.OrdinalIgnoreCase)
               || window.Contains("\"currency\"", StringComparison.OrdinalIgnoreCase)
               || window.Contains("\"conversions\"", StringComparison.OrdinalIgnoreCase)
               || window.Contains("\"factor\"", StringComparison.OrdinalIgnoreCase)
               || window.Contains("exchange", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Never emit — unambiguous non-secrets.</summary>
    public static bool ShouldHardSuppress(SecretsHarvestPipeline.SecretFinding f)
    {
        var cat = f.Category.ToLowerInvariant();
        var snippet = f.Snippet ?? "";
        var location = f.Location ?? "";

        if (cat == "email-address" && IsRetinaAssetEmailFalsePositive(snippet))
            return true;

        if (cat == "credit-card"
            && (IsCurrencyOrExchangeRateUrl(location)
                || IsCurrencyOrExchangeRateUrl(snippet)))
            return true;

        if (cat == "ssninstorage"
            && StorageAuditChecker.IsConsentOrPrivacyStorageKey(
                location.Contains('.') ? location[(location.LastIndexOf('.') + 1)..].ToLowerInvariant() : location.ToLowerInvariant()))
            return true;

        if (cat == "base64-decoded-url-or-secret")
        {
            if (IsChromiumOriginTrialMetadata(snippet)
                || IsBinaryGarbage(snippet)
                || AssetSecretsCommentMiner.LooksLikeSvgPathData(snippet)
                || AssetSecretsCommentMiner.LooksLikeMinifiedCodeSoup(snippet))
                return true;

            // Require a real URL scheme or secret keyword — bare path fragments are noise.
            if (!snippet.Contains("://", StringComparison.Ordinal)
                && !snippet.Contains("password", StringComparison.OrdinalIgnoreCase)
                && !snippet.Contains("secret", StringComparison.OrdinalIgnoreCase)
                && !snippet.Contains("apikey", StringComparison.OrdinalIgnoreCase)
                && !snippet.Contains("api_key", StringComparison.OrdinalIgnoreCase)
                && !snippet.Contains("token", StringComparison.OrdinalIgnoreCase)
                && !snippet.Contains("credential", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (SnippetContainsOnlyPlaceholderValues(snippet))
            return true;

        return false;
    }

    /// <summary>
    /// Adjusts severity and description in place. Call after all scanners, before dedup.
    /// Prefer info over suppress when uncertain (harvest over-reports by design).
    /// </summary>
    public static void CalibrateFinding(SecretsHarvestPipeline.SecretFinding f)
    {
        var cat = f.Category.ToLowerInvariant();
        var loc = f.Location ?? "";
        var snippet = f.Snippet ?? "";

        if (cat == "authtokeninstorage" || cat == "jwtinstorage")
        {
            var keyPart = loc.Contains('.') ? loc[(loc.LastIndexOf('.') + 1)..] : loc;
            if (StorageAuditChecker.IsBenignWebStorageSessionKey(keyPart.ToLowerInvariant(), snippet))
            {
                f.Severity = "info";
                f.Category = "session-id-in-storage";
                f.Description = "Anonymous session/analytics identifier in web storage (not a bearer credential). "
                                + f.Description;
                return;
            }
        }

        if (cat == "jwt-token" && f.Source == "cookies-storage")
        {
            if (loc.Contains("httpOnly", StringComparison.OrdinalIgnoreCase))
            {
                f.Severity = DowngradeSeverity(f.Severity, f.Severity.Equals("high", StringComparison.OrdinalIgnoreCase) ? 2 : 1);
                if (!f.Description.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase))
                    f.Description = "Session JWT in HttpOnly cookie — review alg/expiry hygiene; not the same as a hardcoded embed secret. "
                                    + f.Description;
            }
        }

        if (cat == "jwt-token"
            && (f.Source is "network-response" or "js-bundle")
            && (snippet.Contains("apiKey", StringComparison.OrdinalIgnoreCase)
                || snippet.Contains("api_key", StringComparison.OrdinalIgnoreCase)
                || snippet.Contains("embed", StringComparison.OrdinalIgnoreCase)))
        {
            f.Severity = DowngradeSeverity(f.Severity, 1);
            if (!f.Description.Contains("embed", StringComparison.OrdinalIgnoreCase))
                f.Description = "Client-side embed/API key (JWT-shaped) — scope and rotation matter; not a server-only secret. "
                                + f.Description;
        }

        if (cat == "source-map-exposed")
        {
            if (loc.Contains("data:application/json;base64", StringComparison.OrdinalIgnoreCase)
                || snippet.Contains("sourceMappingURL=data:", StringComparison.OrdinalIgnoreCase))
            {
                f.Severity = "info";
                f.Description = "Inline CSS source map (bundled data: URL, not a publicly downloadable .map file). "
                                + f.Description;
            }
            else if (snippet.Contains("style.css.map", StringComparison.OrdinalIgnoreCase)
                     && !snippet.Contains("HTTP 200", StringComparison.OrdinalIgnoreCase))
            {
                f.Severity = "info";
                f.Description = "CSS source map reference in markup — verify whether the .map file is actually served. "
                                + f.Description;
            }
        }

        if (cat == "comment-block" || cat == "comment-hygiene")
        {
            f.Severity = "info";
            f.Description = cat == "comment-hygiene"
                ? $"Comment hygiene (TODO/FIXME/localhost): {f.Description}"
                : $"Comment block (no strong secret signal): {f.Description}";
            return;
        }

        if (cat == "comment-secret-signal")
        {
            f.Severity = "info";
            f.Description = $"Legacy comment-secret category (suppressed): {f.Description}";
            return;
        }

        if (f.Source == "network-response"
            && (cat.Contains("token", StringComparison.OrdinalIgnoreCase)
                || cat.Contains("secret", StringComparison.OrdinalIgnoreCase)
                || (f.Snippet ?? "").Contains("access_token", StringComparison.OrdinalIgnoreCase))
            && IsAuthRelatedHarvestUrl(f.Location))
        {
            if (f.Severity is "low" or "info")
                f.Severity = "medium";
        }

        if (cat == "secret-assignment" && IsMisclassifiedIdentifierConstantAssignment(f))
        {
            f.Severity = "info";
            f.Description = $"Client-side identifier constant (not a credential): {f.Description}";
            return;
        }

        if (IsFrameworkBoilerplate(f))
        {
            f.Severity = "info";
            if (!f.Description.Contains("framework", StringComparison.OrdinalIgnoreCase))
                f.Description = $"{f.Description} (possible framework boilerplate)";
        }

        if (IsVendorBundleUrl(f.Location))
            f.Severity = DowngradeSeverity(f.Severity, 1);
    }

    /// <summary>
    /// Findings to omit from orchestrated VPX reports (pipeline may still emit at info).
    /// </summary>
    public static bool IsOrchestrationNoise(SecretsHarvestPipeline.SecretFinding f)
    {
        if (ShouldHardSuppress(f))
            return true;

        var cat = f.Category.ToLowerInvariant();
        if (cat is "comment-block" or "comment-hygiene")
            return true;

        if (cat is "session-id-in-storage")
            return true;

        if (f.Severity is "info" or "low")
        {
            if (IsFrameworkBoilerplate(f) || IsLicenseComment(f.Snippet ?? ""))
                return true;
            if (cat == "secret-assignment" && IsMisclassifiedIdentifierConstantAssignment(f))
                return true;
            if (cat is "api-key-in-request" or "plaintext-password-in-transit" or "jwt-token")
                return true;
            if (cat == "comment-secret-signal")
                return true;
        }

        return false;
    }

    public static string DowngradeSeverity(string severity, int steps = 1)
    {
        var order = new[] { "critical", "high", "medium", "low", "info" };
        var idx = Array.FindIndex(order, s => s.Equals(severity, StringComparison.OrdinalIgnoreCase));
        if (idx < 0) return "info";
        return order[Math.Min(idx + steps, order.Length - 1)];
    }

    public static bool SnippetContainsOnlyPlaceholderValues(string snippet)
    {
        if (string.IsNullOrEmpty(snippet)) return false;
        var matches = QuotedValue.Matches(snippet);
        if (matches.Count == 0) return false;
        return matches.Cast<Match>().All(m => IsPlaceholderSecretValue(m.Groups[1].Value));
    }

    /// <summary>
    /// Downgrades AUTOSTARTTOKEN-style compound identifier assignments that matched via embedded TOKEN= substring.
    /// </summary>
    public static bool IsMisclassifiedIdentifierConstantAssignment(SecretsHarvestPipeline.SecretFinding f)
    {
        var snippet = f.Snippet ?? "";
        if (string.IsNullOrEmpty(snippet))
            return false;

        foreach (Match m in CompoundIdentifierAssignment.Matches(snippet))
        {
            var name = m.Groups[1].Value;
            var value = m.Groups[2].Value;
            if (IsPlaceholderSecretValue(value))
                return true;
            if (IdentifierConstantValues.Any(v => value.Equals(v, StringComparison.OrdinalIgnoreCase)
                                                  || value.StartsWith(v, StringComparison.OrdinalIgnoreCase)))
                return true;
            if (value.Length <= 24 && !value.Any(char.IsLower))
                return true;
            if (name.Length >= 8 && name.All(c => char.IsUpper(c) || char.IsDigit(c) || c == '_'))
                return true;
        }

        return false;
    }

    /// <summary>Extract quoted assignment value from a regex match when a capture group exists.</summary>
    public static bool TryGetCapturedSecretValue(Match m, out string value)
    {
        value = "";
        if (m.Groups.Count > 1 && m.Groups[1].Success)
        {
            value = m.Groups[1].Value;
            return true;
        }
        return false;
    }

    internal static bool IsAuthRelatedHarvestUrl(string? location)
    {
        if (string.IsNullOrEmpty(location)) return false;
        var lower = location.ToLowerInvariant();
        return lower.Contains("login", StringComparison.Ordinal)
               || lower.Contains("auth", StringComparison.Ordinal)
               || lower.Contains("token", StringComparison.Ordinal)
               || lower.Contains("session", StringComparison.Ordinal)
               || lower.Contains("/api/", StringComparison.Ordinal);
    }
}
