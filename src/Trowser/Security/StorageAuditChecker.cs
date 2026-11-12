using System.Globalization;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Result of a web storage security audit.
/// </summary>
public class StorageAuditResult
{
    public string Url { get; init; } = "";
    public DateTime Timestamp { get; init; }
    public int LocalStorageCount { get; init; }
    public int SessionStorageCount { get; init; }
    public int IndexedDbRecordCount { get; init; }
    public List<StorageFinding> Findings { get; init; } = [];
    public bool IsClean => Findings.Count == 0;
    public int FindingCount => Findings.Count;

    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>
        {
            "=== Web Storage Security Audit ===",
            $"URL: {Url}",
            $"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}",
            $"localStorage keys: {LocalStorageCount}",
            $"sessionStorage keys: {SessionStorageCount}",
            $"IndexedDB records: {IndexedDbRecordCount}",
            ""
        };

        if (LocalStorageCount == 0 && SessionStorageCount == 0 && IndexedDbRecordCount == 0)
        {
            lines.Add("No web storage data found.");
            lines.Add("==================================");
            return string.Join(Environment.NewLine, lines);
        }

        if (Findings.Count == 0)
        {
            lines.Add("No storage security issues found.");
            lines.Add("==================================");
            return string.Join(Environment.NewLine, lines);
        }

        var high = Findings.Count(f => f.Severity >= Severity.High);
        var medium = Findings.Count(f => f.Severity == Severity.Medium);
        var low = Findings.Count(f => f.Severity == Severity.Low);

        lines.Add($"FINDINGS: {Findings.Count}");
        if (high > 0) lines.Add($"  HIGH/CRITICAL: {high}");
        if (medium > 0) lines.Add($"  MEDIUM:        {medium}");
        if (low > 0) lines.Add($"  LOW:           {low}");
        lines.Add("");

        if (includeDetails)
        {
            foreach (var f in Findings.OrderByDescending(f => f.Severity))
            {
                lines.Add($"--- [{f.Severity.ToString().ToUpper()}] {f.StorageType}.{f.Key} ({f.Category}) ---");
                lines.Add($"  {f.Description}");
                lines.Add($"  Fix: {f.Recommendation}");
                if (f.ValueSnippet != null)
                    lines.Add($"  Value: {f.ValueSnippet}");
                lines.Add("");
            }
        }

        if (high > 0)
            lines.Add($"ASSESSMENT: {high} high-severity issue(s) found — immediate attention recommended.");
        else if (medium > 0)
            lines.Add($"ASSESSMENT: {medium} medium-severity issue(s) found.");
        else
            lines.Add($"ASSESSMENT: Only low-severity findings.");

        lines.Add("==================================");
        return string.Join(Environment.NewLine, lines);
    }
}

public class StorageFinding
{
    public string StorageType { get; init; } = "";
    public string Key { get; init; } = "";
    public Severity Severity { get; init; }
    public string Category { get; init; } = "";
    public string Description { get; init; } = "";
    public string Recommendation { get; init; } = "";
    public string? ValueSnippet { get; init; }
}

/// <summary>
/// Audits localStorage, sessionStorage, and IndexedDB for security issues:
/// sensitive data exposure, auth tokens, PII, stored XSS risk, and secrets.
/// </summary>
public partial class StorageAuditChecker
{
    private static readonly string[] TokenKeyPatterns =
    [
        "token", "access_token", "id_token", "refresh_token", "auth_token",
        "jwt", "bearer", "api_key", "apikey", "api-key",
        "session", "sess", "sid",
        "secret", "password", "passwd", "pwd", "credential"
    ];

    private static readonly string[] PiiKeyPatterns =
    [
        "email", "e-mail", "mail",
        "phone", "tel", "mobile",
        "ssn", "social_security", "national_id",
        "credit_card", "card_number", "ccn",
        "address", "zip", "postal"
    ];

    /// <summary>CMP/consent vendor keys — large JSON blobs that often match SSN regex by accident.</summary>
    private static readonly string[] ConsentStorageKeyFragments =
    [
        "_sp_user_consent", "euconsent", "consent_string", "consentstring",
        "tcf", "gdpr", "cmp.", "_sp_", "sourcepoint", "userconsent"
    ];

    /// <summary>Analytics / feature-flag session ids — not bearer credentials.</summary>
    private static readonly string[] BenignSessionKeyFragments =
    [
        "portal_session_id", "repository:sessionid", "session_id",
        "analytics_session", "device_id", "visitor_id", "client_id"
    ];

    /// <summary>Keys that imply a time/expiry/metadata value, not a bearer token (matched as substrings).</summary>
    private static readonly string[] TimeOrExpiryMetadataKeyFragments =
    [
        "expire", "expiry", "expiration",
        "ttl", "timeout", // idle/session timeout durations
        "validuntil", "valid_until",
        "notbefore", "not_before",
        "timestamp", "time_ms", "timems",
        "issuedat", "createdat", "updatedat", // common *At epoch fields
        "lastlogin", "last_active", "lastactive",
        "_iat", ".iat"
    ];

    [GeneratedRegex(@"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", RegexOptions.None)]
    private static partial Regex JwtPattern();

    [GeneratedRegex(@"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", RegexOptions.None)]
    private static partial Regex EmailPattern();

    [GeneratedRegex(@"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", RegexOptions.None)]
    private static partial Regex SsnPattern();

    [GeneratedRegex(@"(innerHTML|outerHTML|document\.write|\.html\(|dangerouslySetInnerHTML)", RegexOptions.IgnoreCase)]
    private static partial Regex XssRenderPattern();

    [GeneratedRegex(@"<\s*(script|img|svg|iframe|object|embed|link|style|on\w+)\b", RegexOptions.IgnoreCase)]
    private static partial Regex HtmlTagPattern();

    public StorageAuditResult Run(
        string url,
        Dictionary<string, string> localStorage,
        Dictionary<string, string> sessionStorage,
        Dictionary<string, string>? indexedDb = null)
    {
        var findings = new List<StorageFinding>();

        AuditStorage("localStorage", localStorage, findings);
        AuditStorage("sessionStorage", sessionStorage, findings);
        if (indexedDb is { Count: > 0 })
            AuditStorage("indexedDB", indexedDb, findings);

        return new StorageAuditResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            LocalStorageCount = localStorage.Count,
            SessionStorageCount = sessionStorage.Count,
            IndexedDbRecordCount = indexedDb?.Count ?? 0,
            Findings = findings
        };
    }

    private static void AuditStorage(string storageType, Dictionary<string, string> entries, List<StorageFinding> findings)
    {
        foreach (var (key, value) in entries)
        {
            var keyLower = key.ToLowerInvariant();

            if (TokenKeyPatterns.Any(p => keyLower.Contains(p))
                && !string.IsNullOrWhiteSpace(value)
                && value.Length > 5
                && !LooksLikeExpiryOrDurationMetadata(keyLower, value)
                && !IsBenignWebStorageSessionKey(keyLower, value))
            {
                var severity = storageType is "localStorage" or "indexedDB" ? Severity.High : Severity.Medium;
                findings.Add(new StorageFinding
                {
                    StorageType = storageType,
                    Key = key,
                    Severity = severity,
                    Category = "AuthTokenInStorage",
                    Description = $"Authentication/session token found in {storageType}. " +
                        (storageType == "localStorage"
                            ? "localStorage persists across browser sessions and is accessible to any JavaScript on the page, making it vulnerable to XSS-based token theft."
                            : storageType == "indexedDB"
                                ? "IndexedDB persists across sessions and is readable by same-origin scripts (and XSS)."
                                : "sessionStorage is tab-scoped but still accessible to any JavaScript on the page."),
                    Recommendation = "Store authentication tokens in HttpOnly cookies instead of web storage. If web storage is required, use sessionStorage (not localStorage/IndexedDB) and implement strict CSP to mitigate XSS.",
                    ValueSnippet = Truncate(value, 40)
                });
            }

            if (PiiKeyPatterns.Any(p => keyLower.Contains(p)) && !string.IsNullOrWhiteSpace(value))
            {
                findings.Add(new StorageFinding
                {
                    StorageType = storageType,
                    Key = key,
                    Severity = Severity.Medium,
                    Category = "PiiInStorage",
                    Description = $"Key name suggests PII (personally identifiable information) stored in {storageType}. Client-side storage of PII increases exposure in case of XSS.",
                    Recommendation = "Avoid storing PII in web storage. Fetch it from the server on demand and keep it in memory only while needed.",
                    ValueSnippet = RedactValue(value)
                });
            }

            if (JwtPattern().IsMatch(value))
            {
                if (!TokenKeyPatterns.Any(p => keyLower.Contains(p)))
                {
                    findings.Add(new StorageFinding
                    {
                        StorageType = storageType,
                        Key = key,
                        Severity = storageType is "localStorage" or "indexedDB" ? Severity.High : Severity.Medium,
                        Category = "JwtInStorage",
                        Description = $"JWT token detected in {storageType} value. JWTs in web storage are accessible to JavaScript and vulnerable to XSS-based theft.",
                        Recommendation = "Store JWTs in HttpOnly cookies. If using web storage, implement a short expiry and strict CSP.",
                        ValueSnippet = Truncate(value, 40)
                    });
                }
            }

            if (EmailPattern().IsMatch(value))
            {
                if (!PiiKeyPatterns.Any(p => keyLower.Contains(p)))
                {
                    findings.Add(new StorageFinding
                    {
                        StorageType = storageType,
                        Key = key,
                        Severity = Severity.Low,
                        Category = "EmailInStorage",
                        Description = $"Email address detected in {storageType} value.",
                        Recommendation = "Avoid storing email addresses in web storage if not strictly necessary.",
                        ValueSnippet = RedactValue(value)
                    });
                }
            }

            if (!IsConsentOrPrivacyStorageKey(keyLower)
                && SsnPattern().IsMatch(value)
                && TryGetPlausibleSsnMatch(value, out _))
            {
                findings.Add(new StorageFinding
                {
                    StorageType = storageType,
                    Key = key,
                    Severity = Severity.Critical,
                    Category = "SsnInStorage",
                    Description = $"Value matches SSN/national ID pattern in {storageType}. Highly sensitive data must never be stored client-side.",
                    Recommendation = "Remove this data from web storage immediately. Handle sensitive identifiers server-side only.",
                    ValueSnippet = "***-**-****"
                });
            }

            if (HtmlTagPattern().IsMatch(value))
            {
                findings.Add(new StorageFinding
                {
                    StorageType = storageType,
                    Key = key,
                    Severity = Severity.Medium,
                    Category = "HtmlInStorage",
                    Description = $"HTML markup with potentially dangerous tags detected in {storageType}. If rendered via innerHTML or similar, this is a stored XSS vector.",
                    Recommendation = "Sanitize HTML before storing. When rendering, use textContent or a sanitizer library instead of innerHTML.",
                    ValueSnippet = Truncate(value, 80)
                });
            }

            if (value.Length > 10_000)
            {
                findings.Add(new StorageFinding
                {
                    StorageType = storageType,
                    Key = key,
                    Severity = Severity.Low,
                    Category = "LargeValue",
                    Description = $"Unusually large value ({value.Length:N0} chars) in {storageType}. Large storage values may indicate data that should be stored server-side.",
                    Recommendation = "Review whether this data needs to be client-side. Consider using server-side storage or IndexedDB with proper access controls.",
                    ValueSnippet = null
                });
            }
        }
    }

    private static string Truncate(string s, int max)
    {
        if (s.Length <= max) return s;
        return s[..(max - 3)] + "...";
    }

    private static string RedactValue(string s)
    {
        if (s.Length <= 4) return "****";
        return s[..2] + new string('*', Math.Min(s.Length - 4, 10)) + s[^2..];
    }

    /// <summary>
    /// Broad token key heuristics match <c>session</c>/<c>sess</c>, which flags benign keys like
    /// <c>sessionExpiresAt</c>. Skip auth-token severity when name and value look like expiry or duration metadata.
    /// </summary>
    private static bool LooksLikeExpiryOrDurationMetadata(string keyLower, string value)
    {
        var suggestsTime = TimeOrExpiryMetadataKeyFragments.Any(f => keyLower.Contains(f))
            || (keyLower.EndsWith("at", StringComparison.Ordinal)
                && (keyLower.Contains("expir")
                    || keyLower.Contains("creat")
                    || keyLower.Contains("updat")
                    || keyLower.Contains("start")
                    || keyLower.Contains("end")));

        if (!suggestsTime)
            return false;

        var v = value.Trim();
        if (v.Length == 0)
            return false;

        if (LooksLikeNumericEpochOrSmallDuration(v))
            return true;

        // ISO timestamps often used for "expiresAt" string values
        if (DateTime.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _))
            return true;

        return false;
    }

    /// <summary>Decimal epoch (seconds/ms) or a short integer duration.</summary>
    private static bool LooksLikeNumericEpochOrSmallDuration(string v)
    {
        var trimmed = v.Trim();
        if (trimmed.Length == 0 || trimmed.Length > 20)
            return false;

        for (var i = 0; i < trimmed.Length; i++)
        {
            var c = trimmed[i];
            if (i == 0 && c == '-' && trimmed.Length > 1)
                continue;
            if (!char.IsAsciiDigit(c))
                return false;
        }

        if (!long.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n))
            return false;

        var mag = trimmed.TrimStart('-');
        var len = mag.Length;

        // Idle timeouts, max-age seconds, etc.
        if (len <= 6 && Math.Abs(n) <= 86400_000L)
            return true;

        // Unix seconds (~2001–2286)
        if (len is >= 9 and <= 10 && n is >= 1_000_000_000 and < 10_000_000_000)
            return true;

        // Unix milliseconds (roughly 2001–2627 when 13 digits)
        if (len is >= 11 and <= 13 && Math.Abs(n) >= 100_000_000_000L)
            return true;

        return false;
    }

    internal static bool IsConsentOrPrivacyStorageKey(string keyLower) =>
        ConsentStorageKeyFragments.Any(f => keyLower.Contains(f, StringComparison.Ordinal));

    /// <summary>
    /// Skip auth-token severity for numeric/hex session ids and JSON session blobs without token material.
    /// </summary>
    internal static bool IsBenignWebStorageSessionKey(string keyLower, string value)
    {
        if (BenignSessionKeyFragments.Any(f => keyLower.Contains(f, StringComparison.Ordinal)))
            return true;

        var hasStrongAuthKeyName = keyLower.Contains("access_token")
            || keyLower.Contains("refresh_token")
            || keyLower.Contains("id_token")
            || keyLower.Contains("auth_token")
            || keyLower.Contains("bearer")
            || keyLower.Contains("jwt")
            || keyLower.Contains("api_key")
            || keyLower.Contains("apikey");

        if (hasStrongAuthKeyName)
            return false;

        var v = value.Trim();
        if (v.Length == 0)
            return true;

        if (JwtPattern().IsMatch(v))
            return false;

        if (v.All(c => char.IsAsciiDigit(c)) && v.Length <= 20)
            return keyLower.Contains("session", StringComparison.Ordinal)
                   || keyLower.Contains("sess", StringComparison.Ordinal)
                   || keyLower.Contains("sid", StringComparison.Ordinal);

        if (v.Length is >= 8 and <= 64 && v.All(c => char.IsAsciiHexDigit(c))
            && keyLower.Contains("session", StringComparison.Ordinal))
            return true;

        if ((v.StartsWith('{') || v.StartsWith('['))
            && keyLower.Contains("session", StringComparison.Ordinal)
            && !keyLower.Contains("token", StringComparison.Ordinal))
            return true;

        return false;
    }

    internal static bool TryGetPlausibleSsnMatch(string value, out string digits)
    {
        digits = "";
        var m = SsnPattern().Match(value);
        if (!m.Success)
            return false;

        digits = new string(m.Value.Where(char.IsDigit).ToArray());
        if (digits.Length != 9)
            return false;

        return IsPlausibleUsSsnDigits(digits);
    }

    /// <summary>US SSN area/group/serial rules — rejects most random digit runs in JSON.</summary>
    internal static bool IsPlausibleUsSsnDigits(string digits)
    {
        if (digits.Length != 9 || !digits.All(char.IsDigit))
            return false;

        var area = int.Parse(digits[..3], CultureInfo.InvariantCulture);
        var group = int.Parse(digits[3..5], CultureInfo.InvariantCulture);
        var serial = int.Parse(digits[5..], CultureInfo.InvariantCulture);

        if (area is 0 or 666 or >= 900)
            return false;
        if (group == 0)
            return false;
        if (serial == 0)
            return false;

        return true;
    }
}
