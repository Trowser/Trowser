using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Lightweight passive checks on HTTP response bodies (regex / substring, bounded input).
/// </summary>
public static class ResponseBodySecurityHeuristics
{
    public const int DefaultMaxScanChars = 262_144;

    /// <summary>SQL error / leakage signatures (conservative substrings — tuned to reduce false positives).
    /// More-specific engines are listed before ambiguous phrases (e.g. Postgres "at or near" before sqlite "near").</summary>
    private static readonly (string Engine, string Pattern)[] SqlPatterns =
    [
        ("postgresql", "PostgreSQL"),
        ("postgresql", "ERROR:  syntax error at"),
        ("postgresql", "syntax error at or near"),
        ("postgresql", "unterminated quoted string"),
        ("postgresql", "pg_query"),
        ("postgresql", "psql:"),
        ("postgresql", "PL/pgSQL"),
        // Postgres rejects MySQL SLEEP() with this exact phrase — still a SQL error oracle.
        ("postgresql", "function sleep(integer) does not exist"),
        ("postgresql", "function pg_sleep"),
        ("mysql", "You have an error in your SQL syntax"),
        ("mysql", "SQL syntax"),
        ("mysql", "mysql_fetch"),
        ("mysql", "mysqli_"),
        ("mysql", "MariaDB"),
        ("mssql", "Microsoft SQL Server"),
        ("mssql", "ODBC SQL Server"),
        ("mssql", "Unclosed quotation mark"),
        ("mssql", "SqlException"),
        ("oracle", "ORA-01756"),
        ("oracle", "oracle.jdbc"),
        ("sqlite", "SQLITE_ERROR"),
        ("sqlite", "sqlite3.OperationalError"),
        ("sqlite", "sqlite3.ProgrammingError"),
        // Ambiguous phrase — classified as generic unless a strong sqlite signal is also present.
        // Postgres "syntax error at or near \"…\"" must never become sqlite.
        ("generic", "near \""),
        // H2 / Spring JDBC (common in Java lab and enterprise apps)
        ("h2", "bad SQL grammar"),
        ("h2", "Syntax error in SQL statement"),
        ("h2", "org.h2.jdbc"),
        ("h2", "JdbcSQLException"),
        ("h2", "JdbcSQLSyntaxErrorException"),
        ("spring", "StatementCallback"),
        ("spring", "BadSqlGrammarException"),
        ("spring", "UncategorizedSQLException"),
        ("java", "SQLSyntaxErrorException"),
        ("java", "SQLException:"),
        ("generic", "syntax error near"),
        ("generic", "quoted string not properly terminated"),
        ("generic", "unterminated quoted string"),
        ("generic", "Invalid column name"),
        ("generic", "Invalid object name"),
    ];

    private static readonly string[] StrongEngineHints =
    [
        "postgresql", "postgres", "psql:", "pl/pgsql", "pg_query",
        "syntax error at or near", "error:  syntax error at",
        "unterminated quoted string", "function sleep(integer) does not exist",
        "mysql", "mysqli_", "mariadb",
        "microsoft sql server", "sqlexception", "odbc sql server",
        "oracle.jdbc", "ora-",
        "sqlite_error", "sqlite3.",
        "org.h2.jdbc", "jdbcsqlexception"
    ];

    public sealed record SqlSignatureHit(string Engine, string Pattern, string? Snippet);

    public sealed record StoredXssHit(string Pattern, string Context, string? Snippet);

    public sealed record CredentialHit(string Kind, string? Snippet);

    private static readonly Regex ScriptInTableCellRegex = new(
        @"<td[^>]*>[\s\S]{0,800}?<script\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex EventHandlerInTableCellRegex = new(
        @"<td[^>]*>[\s\S]{0,400}?\bon(?:error|load|mouseover|focus)\s*=",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IframeJsUrlInTableCellRegex = new(
        @"<td[^>]*>[\s\S]{0,400}?<iframe[^>]+src\s*=\s*[""']?\s*javascript:",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static string ClampBody(string? body, int maxChars = DefaultMaxScanChars)
    {
        if (string.IsNullOrEmpty(body)) return "";
        if (body.Length <= maxChars) return body;
        return body[..maxChars];
    }

    public static List<SqlSignatureHit> DetectSqlErrorSignatures(string? body, int maxChars = DefaultMaxScanChars)
    {
        var hits = new List<SqlSignatureHit>();
        if (string.IsNullOrEmpty(body)) return hits;

        var scan = ClampBody(body, maxChars);
        foreach (var (engine, pattern) in SqlPatterns)
        {
            var idx = scan.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;

            // Postgres emits "syntax error at or near \"…\"" — do not treat as sqlite/generic near-phrase.
            if (pattern.Equals("near \"", StringComparison.Ordinal)
                && LooksLikePostgresNearPhrase(scan, idx))
                continue;

            if (pattern.Equals("near \"", StringComparison.Ordinal)
                && HasStrongNonSqliteEngineHint(scan))
                continue;

            // Promote ambiguous "near \"" to sqlite only when a strong sqlite marker is also present.
            var resolvedEngine = engine;
            if (pattern.Equals("near \"", StringComparison.Ordinal)
                && engine.Equals("generic", StringComparison.OrdinalIgnoreCase)
                && HasStrongSqliteEngineHint(scan))
                resolvedEngine = "sqlite";

            var start = Math.Max(0, idx - 40);
            var end = Math.Min(scan.Length, idx + pattern.Length + 40);
            var snippet = scan[start..end].Replace('\r', ' ').Replace('\n', ' ');
            hits.Add(new SqlSignatureHit(resolvedEngine, pattern, snippet));
        }

        return PreferStrongestEngine(hits);
    }

    private static bool LooksLikePostgresNearPhrase(string scan, int nearIdx)
    {
        var lookbehind = Math.Max(0, nearIdx - 40);
        var prefix = scan.AsSpan(lookbehind, nearIdx - lookbehind);
        return prefix.Contains("at or near", StringComparison.OrdinalIgnoreCase)
               || prefix.Contains("syntax error at", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasStrongSqliteEngineHint(string scan) =>
        scan.Contains("SQLITE_ERROR", StringComparison.OrdinalIgnoreCase)
        || scan.Contains("sqlite3.", StringComparison.OrdinalIgnoreCase);

    private static bool HasStrongNonSqliteEngineHint(string scan)
    {
        foreach (var hint in StrongEngineHints)
        {
            if (hint.StartsWith("sqlite", StringComparison.OrdinalIgnoreCase)) continue;
            if (scan.Contains(hint, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>When multiple engines match the same body, keep the most specific engine hits.</summary>
    private static List<SqlSignatureHit> PreferStrongestEngine(List<SqlSignatureHit> hits)
    {
        if (hits.Count <= 1) return hits;

        static int Rank(string engine) => engine.ToLowerInvariant() switch
        {
            "postgresql" => 6,
            "mysql" => 5,
            "mssql" => 5,
            "oracle" => 5,
            "sqlite" => 4,
            "h2" => 3,
            "spring" or "java" => 2,
            "generic" => 1,
            _ => 0
        };

        var best = hits.Max(h => Rank(h.Engine));
        if (best <= 1) return hits;

        // Keep only the strongest DB engine family; drop weaker competing engines and generic noise.
        return hits.Where(h => Rank(h.Engine) == best).ToList();
    }

    /// <summary>Detect unencoded user content persisted in HTML tables (stored XSS indicator).</summary>
    public static List<StoredXssHit> DetectStoredXssInHtml(string? body, int maxChars = DefaultMaxScanChars)
    {
        var hits = new List<StoredXssHit>();
        if (string.IsNullOrEmpty(body)) return hits;

        var scan = ClampBody(body, maxChars);
        if (!scan.Contains('<')) return hits;

        foreach (var (pattern, regex, context) in new (string, Regex, string)[]
                 {
                     ("script-in-table-cell", ScriptInTableCellRegex, "table-cell"),
                     ("event-handler-in-table-cell", EventHandlerInTableCellRegex, "table-cell"),
                     ("iframe-javascript-url", IframeJsUrlInTableCellRegex, "table-cell"),
                 })
        {
            var m = regex.Match(scan);
            if (!m.Success) continue;
            var start = Math.Max(0, m.Index - 20);
            var end = Math.Min(scan.Length, m.Index + Math.Min(m.Length, 120) + 20);
            hits.Add(new StoredXssHit(pattern, context, scan[start..end].Replace('\r', ' ').Replace('\n', ' ')));
            break;
        }

        return hits;
    }

    private static readonly Regex Md5Hex = new(@"\b[0-9a-f]{32}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Sha1Hex = new(@"\b[0-9a-f]{40}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Sha256Hex = new(@"\b[0-9a-f]{64}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Bcrypt = new(@"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", RegexOptions.Compiled);
    private static readonly Regex Argon2 = new(@"\$argon2(id|i|d)\$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ApiKeyish = new(@"\b(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['""]?([A-Za-z0-9_\-]{16,})['""]?", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex BearerInJson = new(@"""authorization""\s*:\s*""Bearer\s+([A-Za-z0-9_\-.]+)""", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Email = new(@"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex JsonPlaintextPassword = new(
        @"""(?:password|passwd|pwd|pass)""\s*:\s*""([^""]{1,200})""",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex JsonEmailPasswordCombo = new(
        @"""(?:email|username|user)""\s*:\s*""([^""]{1,200})""[\s\S]{0,240}?""(?:password|passwd|pwd|pass)""\s*:\s*""([^""]{1,200})""",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <param name="suppressStandaloneHexFingerprints">
    /// When true, skips md5/sha1/sha256 “hex digest” buckets. Bundled/minified JS routinely contains standalone
    /// 32/40/64-char hex sequences (chunk hashes, build IDs, SRI fingerprints, inlined source-map references).
    /// </param>
    public static List<CredentialHit> DetectCredentialExposure(
        string? body,
        int maxChars = DefaultMaxScanChars,
        bool suppressStandaloneHexFingerprints = false)
    {
        var hits = new List<CredentialHit>();
        if (string.IsNullOrEmpty(body)) return hits;

        var scan = ClampBody(body, maxChars);
        if (Bcrypt.IsMatch(scan))
            hits.Add(new CredentialHit("password-hash-bcrypt", TruncateMatch(scan, Bcrypt.Match(scan))));
        if (Argon2.IsMatch(scan))
            hits.Add(new CredentialHit("password-hash-argon2", null));

        if (!suppressStandaloneHexFingerprints)
        {
            foreach (Match m in Md5Hex.Matches(scan))
            {
                if (IsLikelyObjectId(m.Value)) continue;
                if (!HasCredentialContext(scan, m.Index)) continue;
                hits.Add(new CredentialHit("md5-hex-like", m.Value));
                break;
            }
            foreach (Match m in Sha1Hex.Matches(scan))
            {
                if (!HasCredentialContext(scan, m.Index)) continue;
                hits.Add(new CredentialHit("sha1-hex-like", m.Value));
                break;
            }
            foreach (Match m in Sha256Hex.Matches(scan))
            {
                if (!HasCredentialContext(scan, m.Index)) continue;
                hits.Add(new CredentialHit("sha256-hex-like", m.Value));
                break;
            }
        }

        var ak = ApiKeyish.Match(scan);
        if (ak.Success)
            hits.Add(new CredentialHit("credential-like-key", ak.Groups[1].Value.Length > 8 ? ak.Groups[1].Value[..8] + "…" : ak.Groups[1].Value));
        var br = BearerInJson.Match(scan);
        if (br.Success)
            hits.Add(new CredentialHit("bearer-token-in-json", "Bearer …"));

        foreach (Match m in JsonEmailPasswordCombo.Matches(scan))
        {
            var pass = m.Groups[2].Value;
            if (SecretsHarvestHeuristics.IsPlaceholderSecretValue(pass)
                || SecretsHarvestHeuristics.IsUiLabelSecretValue(pass))
                continue;
            hits.Add(new CredentialHit("email-password-combo", m.Groups[1].Value));
            if (hits.Count >= 8) break;
        }

        foreach (Match m in JsonPlaintextPassword.Matches(scan))
        {
            var pass = m.Groups[1].Value;
            if (SecretsHarvestHeuristics.IsPlaceholderSecretValue(pass)
                || SecretsHarvestHeuristics.IsUiLabelSecretValue(pass))
                continue;
            // Skip if already covered by email+password combo above.
            if (hits.Any(h => h.Kind.Equals("email-password-combo", StringComparison.OrdinalIgnoreCase)))
                break;
            hits.Add(new CredentialHit("plaintext-password-in-json",
                pass.Length > 4 ? pass[..2] + "…" + pass[^2..] : "****"));
            break;
        }

        foreach (Match m in Email.Matches(scan))
        {
            hits.Add(new CredentialHit("email-address", m.Value));
            if (hits.Count >= 10) break;
        }

        return hits;
    }

    private static bool IsLikelyObjectId(string hex32) =>
        hex32.AsSpan().Trim('0').Length <= 8;

    private static readonly string[] HexCredentialContextNeedles =
    [
        "password", "passwd", "pwd", "secret", "credential", "hash", "digest",
        "bcrypt", "scrypt", "argon", "salt", "apikey", "api_key", "passwd_hash"
    ];

    private static bool HasCredentialContext(string scan, int matchIndex)
    {
        var start = Math.Max(0, matchIndex - 96);
        var end = Math.Min(scan.Length, matchIndex + 96);
        if (end <= start) return false;
        var window = scan[start..end];
        return HexCredentialContextNeedles.Any(n => window.Contains(n, StringComparison.OrdinalIgnoreCase));
    }

    private static string? TruncateMatch(string scan, Match m)
    {
        if (!m.Success) return null;
        var s = m.Value;
        return s.Length > 40 ? s[..40] + "…" : s;
    }

    /// <summary>
    /// Heuristic: same response mentions a CAPTCHA/challenge and an answer/solution field together (possible answer leakage).
    /// Requires JSON-ish field pairing — not mere co-occurrence of the words "captcha" and "solution" in prose/CSP docs.
    /// </summary>
    public static bool DetectCaptchaAnswerLeakage(string? body, int maxChars = DefaultMaxScanChars)
    {
        if (string.IsNullOrEmpty(body)) return false;
        var scan = ClampBody(body, maxChars);

        // Strong signals: explicit answer field keys next to captcha context.
        var hasStrongAnswerField =
            Regex.IsMatch(scan, @"""(?:captcha[_-]?answer|captchaAnswer|answer)""\s*:", RegexOptions.IgnoreCase)
            || Regex.IsMatch(scan, @"'(?:captcha[_-]?answer|captchaAnswer|answer)'\s*:", RegexOptions.IgnoreCase);

        if (!hasStrongAnswerField) return false;

        var hasChallenge = scan.Contains("captcha", StringComparison.OrdinalIgnoreCase)
            || scan.Contains("recaptcha", StringComparison.OrdinalIgnoreCase)
            || scan.Contains("hcaptcha", StringComparison.OrdinalIgnoreCase)
            || scan.Contains("turnstile", StringComparison.OrdinalIgnoreCase);

        return hasChallenge;
    }

    /// <summary>
    /// True when both a challenge object and an answer/solution value appear as JSON fields
    /// (used to decide whether captcha-leak can rise above info/low).
    /// </summary>
    public static bool DetectCaptchaAnswerLeakageConfirmed(string? body, int maxChars = DefaultMaxScanChars)
    {
        if (!DetectCaptchaAnswerLeakage(body, maxChars)) return false;
        var scan = ClampBody(body, maxChars);
        // Confirmed: answer field has a non-empty scalar value (not null/empty/placeholder schema).
        return Regex.IsMatch(
            scan,
            @"""(?:captcha[_-]?answer|captchaAnswer|answer)""\s*:\s*""[^""]{1,64}""",
            RegexOptions.IgnoreCase);
    }

    public static string ResponseFingerprint(int statusCode, string body, int sampleLen = 400)
    {
        var sample = body.Length <= sampleLen ? body : body[..sampleLen];
        sample = Regex.Replace(sample, @"\s+", " ");
        var bytes = Encoding.UTF8.GetBytes(sample);
        var hash = SHA256.HashData(bytes);
        return $"{statusCode}:{body.Length}:{Convert.ToHexString(hash)[..16]}";
    }

    /// <summary>
    /// Reduces noisy framework serialization (especially Next.js App Router Flight / <c>__next_f</c> chunks)
    /// so fingerprints and LLM-visible diffs emphasize application meaning instead of flight plumbing.
    /// </summary>
    public static string StripFrameworkNoiseForSecurityEvidence(string? body, int maxChars = DefaultMaxScanChars)
    {
        if (string.IsNullOrEmpty(body)) return "";
        var scan = ClampBody(body, maxChars);
        var sb = new StringBuilder(Math.Min(scan.Length, 65536));
        foreach (var line in scan.Split('\n'))
        {
            if (line.IndexOf("__next_f", StringComparison.OrdinalIgnoreCase) >= 0) continue;
            sb.Append(line);
            sb.Append('\n');
        }

        return Regex.Replace(sb.ToString(), @"\s+", " ").Trim();
    }

    /// <summary>Heuristic for Next.js RSC / Flight HTML shells that embed request-derived strings in serialized chunks.</summary>
    public static bool BodySuggestsNextJsRscFlight(string? body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        return body.Contains("__next_f", StringComparison.OrdinalIgnoreCase)
               || body.Contains("next-flight", StringComparison.OrdinalIgnoreCase)
               || body.Contains("Next-Router-State-Tree", StringComparison.OrdinalIgnoreCase)
               || body.Contains("\"$@\"", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Short SHA-256 prefix of <see cref="StripFrameworkNoiseForSecurityEvidence"/> output (stable across flight noise).</summary>
    public static string CanonicalSecurityEvidenceHash(string? body, int maxChars = DefaultMaxScanChars)
    {
        var stripped = StripFrameworkNoiseForSecurityEvidence(body, maxChars);
        var bytes = Encoding.UTF8.GetBytes(stripped);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash)[..16];
    }

    /// <summary>
    /// Short excerpt around the first character index where normalized bodies differ (for auto-scan / LLM triage).
    /// </summary>
    public static string BuildShortSecurityBodyDiffExcerpt(string? a, string? b, int context = 72, int maxChars = DefaultMaxScanChars)
    {
        var na = StripFrameworkNoiseForSecurityEvidence(a, maxChars);
        var nb = StripFrameworkNoiseForSecurityEvidence(b, maxChars);
        if (na == nb) return "(identical after framework-noise strip)";

        var min = Math.Min(na.Length, nb.Length);
        var i = 0;
        for (; i < min; i++)
        {
            if (na[i] != nb[i]) break;
        }

        if (i == min && na.Length != nb.Length)
            i = min;

        static string Snip(string s, int at, int ctx)
        {
            var start = Math.Max(0, at - ctx);
            var take = Math.Min(s.Length - start, ctx * 2 + 24);
            var chunk = s.Length <= start + take ? s[start..] : s.Substring(start, take);
            return chunk.Replace('\r', ' ').Replace('\n', ' ');
        }

        return $"at≈{i}: A «{Snip(na, i, context)}» | B «{Snip(nb, i, context)}»";
    }
}
