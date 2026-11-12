using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

// ReSharper disable MemberCanBePrivate.Global

namespace Trowser.Security;

/// <summary>
/// Unified secret/credential harvesting across all browser sources:
/// JS bundles, cookies, storage, network responses, page text, and source maps.
/// </summary>
public static class SecretsHarvestPipeline
{
    public sealed class HarvestOptions
    {
        public bool IncludeJsBundles { get; set; } = true;
        public bool IncludeCookiesAndStorage { get; set; } = true;
        public bool IncludeNetworkResponses { get; set; } = true;
        public bool IncludePageText { get; set; } = true;
        public bool IncludeSourceMaps { get; set; } = true;
        public int MaxJsScripts { get; set; } = 20;
        public int MaxNetworkResponses { get; set; } = 100;
        /// <summary>Max bytes read per JS bundle (default 1MB; js-audit alone defaults to 512KB).</summary>
        public int MaxBytesPerFile { get; set; } = 1_048_576;
        public int TimeoutMs { get; set; } = 30000;
        public bool IncludeHtmlComments { get; set; } = true;

        /// <summary>When set, network scans only include entries for this host (see <see cref="SecurityHostScope.MatchesHostFilter"/>).</summary>
        public string? ScopeHost { get; set; }

        /// <summary>When true (default), network response/header scans skip hosts outside <see cref="ScopeHost"/>.</summary>
        public bool LimitNetworkToScopeHost { get; set; } = true;
    }

    public sealed class SecretFinding
    {
        public string Source { get; set; } = "";
        public string Category { get; set; } = "";
        public string Severity { get; set; } = "info";
        public string Location { get; set; } = "";
        public string Description { get; set; } = "";
        public string? Snippet { get; set; }
    }

    public sealed class HarvestResult
    {
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string Url { get; set; } = "";
        public int TotalFindings { get; set; }
        public List<SecretFinding> Findings { get; set; } = [];
        public HarvestSummary Summary { get; set; } = new();
        public List<string> SourcesScanned { get; set; } = [];
        public List<string> Errors { get; set; } = [];
        public List<string> Warnings { get; set; } = [];
        public int ElapsedMs { get; set; }

        /// <summary>Findings removed by hard suppress, per-URL comment caps, and similar noise filters.</summary>
        public int FilteredNoise { get; set; }

        public bool IsClean => TotalFindings == 0;

        public List<SecretFinding> GetByMinSeverity(string minSeverity)
        {
            var minRank = SeverityRankStatic(minSeverity);
            return Findings.Where(f => SeverityRankStatic(f.Severity) >= minRank).ToList();
        }

        private static int SeverityRankStatic(string s) => s switch
        {
            "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0
        };

        public string Format(bool includeDetails = true)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== Secrets Harvest Results ===");
            sb.AppendLine($"URL: {Url}");
            sb.AppendLine($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"Sources scanned: {string.Join(", ", SourcesScanned)}");
            sb.AppendLine($"Total findings: {TotalFindings}");

            if (TotalFindings > 0)
            {
                sb.Append($"  Critical: {Summary.Critical}, High: {Summary.High}, ");
                sb.AppendLine($"Medium: {Summary.Medium}, Low: {Summary.Low}, Info: {Summary.Info}");

                if (Summary.BySource.Count > 0)
                    sb.AppendLine($"  By source: {string.Join(", ", Summary.BySource.Select(kv => $"{kv.Key}: {kv.Value}"))}");
                if (Summary.ByCategory.Count > 0)
                    sb.AppendLine($"  By category: {string.Join(", ", Summary.ByCategory.Select(kv => $"{kv.Key}: {kv.Value}"))}");
            }

            sb.AppendLine($"Elapsed: {ElapsedMs}ms");

            if (Errors.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("--- Errors ---");
                foreach (var err in Errors)
                    sb.AppendLine($"  ! {err}");
            }

            if (includeDetails && Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine(new string('─', 80));

                foreach (var f in Findings)
                {
                    sb.AppendLine();
                    sb.AppendLine($"[{f.Severity.ToUpper()}] [{f.Source}] {f.Description}");
                    sb.AppendLine($"  Category: {f.Category}");
                    sb.AppendLine($"  Location: {f.Location}");
                    if (!string.IsNullOrEmpty(f.Snippet))
                        sb.AppendLine($"  Snippet: {f.Snippet}");
                }
            }
            else if (Findings.Count == 0)
            {
                sb.AppendLine();
                sb.AppendLine("No secrets or credentials found — all sources clean.");
            }

            return sb.ToString().TrimEnd();
        }
    }

    public sealed class HarvestSummary
    {
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int Info { get; set; }
        public Dictionary<string, int> BySource { get; set; } = new();
        public Dictionary<string, int> ByCategory { get; set; } = new();
    }

    private static readonly Regex JwtPattern = new(
        @"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex ApiKeyPattern = new(
        @"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|private[_-]?key)\s*[=:""']\s*[""']?([A-Za-z0-9_\-/.+=]{16,})[""']?",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex JsonApiKeyPattern = new(
        @"(?i)[""'](?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key)[""']\s*:\s*[""']([A-Za-z0-9_\-/.+=]{8,})[""']",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex BearerPattern = new(
        @"(?i)bearer\s+([A-Za-z0-9_\-.+/=]{20,})",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex PasswordPattern = new(
        @"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*[""']([^""'\s]{3,100})[""']",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex AwsKeyPattern = new(
        @"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    private static readonly Regex PrivateKeyPattern = new(
        @"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    private static readonly Regex ConnectionStringPattern = new(
        @"(?i)(?:mongodb|mysql|postgres|redis|amqp|mssql)://[^\s""'<>]{10,}",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex GenericSecretAssignment = new(
        @"(?i)\b(?:secret|token|credential|auth_key|signing_key|client_secret)\s*[=:]\s*[""']([^""'\n]{8,200})[""']",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex EmailPasswordCombo = new(
        @"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}[""',\s:]+[""']?(?:password|passwd|pwd|pass)[""']?\s*[=:]\s*[""']([^""']{2,100})[""']",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex EmailAddress = new(
        @"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex CreditCardCandidate = new(
        @"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex HtmlComment = new(
        @"<!--([\s\S]*?)-->",
        RegexOptions.Compiled, TimeSpan.FromSeconds(3));

    /// <summary>Retina filenames like <c>hero@2x.png</c> match the email regex (@2x as faux domain).</summary>
    internal static bool IsRetinaAssetEmailFalsePositive(string match) =>
        SecretsHarvestHeuristics.IsRetinaAssetEmailFalsePositive(match);

    public static async Task<HarvestResult> RunAsync(
        AutomationContext ctx,
        HarvestOptions options,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var result = new HarvestResult();

        try { result.Url = await ctx.GetCurrentUrl(); } catch { }

        if (options.IncludeJsBundles)
        {
            ct.ThrowIfCancellationRequested();
            await ScanJsBundles(ctx, options, result, ct);
        }

        if (options.IncludeCookiesAndStorage)
        {
            ct.ThrowIfCancellationRequested();
            await ScanCookiesAndStorage(ctx, result, ct);
        }

        if (options.IncludeNetworkResponses)
        {
            ct.ThrowIfCancellationRequested();
            ScanNetworkResponses(ctx, options, result);
        }

        if (options.IncludePageText)
        {
            ct.ThrowIfCancellationRequested();
            await ScanPageText(ctx, result, ct);
        }

        if (options.IncludeHtmlComments)
        {
            ct.ThrowIfCancellationRequested();
            await ScanHtmlComments(ctx, result, ct);
        }

        if (options.IncludeSourceMaps)
        {
            ct.ThrowIfCancellationRequested();
            await ScanSourceMaps(ctx, result, ct);
        }

        CalibrateFindings(result);
        CapCommentBlockFindings(result, maxPerLocation: 3);
        DeduplicateFindings(result);

        result.Findings = result.Findings
            .OrderByDescending(f => SeverityRank(f.Severity))
            .ThenBy(f => f.Source)
            .ToList();

        result.TotalFindings = result.Findings.Count;
        result.Summary = BuildSummary(result.Findings);
        result.ElapsedMs = (int)sw.ElapsedMilliseconds;

        return result;
    }

    private static async Task ScanJsBundles(
        AutomationContext ctx, HarvestOptions options, HarvestResult result, CancellationToken ct)
    {
        try
        {
            var maxBytes = Math.Clamp(options.MaxBytesPerFile, 8_192, 2_000_000);
            var jsResult = await JavaScriptStaticAudit.RunAsync(
                ctx, options.MaxJsScripts, maxBytes, false, options.TimeoutMs, ct);

            result.SourcesScanned.Add($"js-bundles ({jsResult.ScriptsFetched} scripts)");

            foreach (var asset in jsResult.Assets)
            {
                if (!string.IsNullOrEmpty(asset.ScannedText))
                    ScanTextForSecrets(asset.ScannedText, asset.Url, "js-bundle", result);

                foreach (var hit in asset.Hits)
                {
                    if (hit.Category == "truncation")
                    {
                        result.Warnings.Add($"{asset.Url}: {hit.Snippet}");
                        continue;
                    }

                    var (severity, category) = ClassifyJsHit(hit);
                    result.Findings.Add(new SecretFinding
                    {
                        Source = "js-bundle",
                        Category = category,
                        Severity = severity,
                        Location = asset.Url,
                        Description = $"{hit.Category}: {hit.Pattern}",
                        Snippet = Truncate(hit.Snippet, 200)
                    });
                }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"js-bundles: {ex.Message}");
        }
    }

    private static async Task ScanCookiesAndStorage(
        AutomationContext ctx, HarvestResult result, CancellationToken ct)
    {
        try
        {
            var jwtResult = await HttpSecurityProbes.RunJwtAnalyzeAsync(ctx, null, ct);
            result.SourcesScanned.Add($"jwt-analyze ({jwtResult.Tokens.Count} tokens)");

            foreach (var token in jwtResult.Tokens)
            {
                var severity = token.Issues.Count > 0 ? "medium" : "low";
                var jwtDesc = token.Issues.Count > 0
                    ? $"JWT ({token.HeaderAlg}): {string.Join("; ", token.Issues.Take(3))}"
                    : $"JWT in client storage ({token.HeaderAlg}) — review HttpOnly/SameSite if session token";
                result.Findings.Add(new SecretFinding
                {
                    Source = "cookies-storage",
                    Category = "jwt-token",
                    Severity = severity,
                    Location = token.Source,
                    Description = jwtDesc,
                    Snippet = Truncate(token.Raw ?? "", 60)
                });

                foreach (var claim in token.SensitiveClaims)
                {
                    var claimSeverity = claim.Contains("md5-password-hash", StringComparison.OrdinalIgnoreCase)
                        ? "critical"
                        : claim.Contains("sha1-password-hash", StringComparison.OrdinalIgnoreCase)
                            ? "high"
                            : "medium";
                    result.Findings.Add(new SecretFinding
                    {
                        Source = "cookies-storage",
                        Category = claim.Contains("md5-password-hash", StringComparison.OrdinalIgnoreCase)
                            ? "md5-password-hash-in-jwt"
                            : "jwt-sensitive-claim",
                        Severity = claimSeverity,
                        Location = token.Source,
                        Description = claim.Contains("md5-password-hash", StringComparison.OrdinalIgnoreCase)
                            ? $"MD5 password hash in JWT claim: {claim}"
                            : $"Sensitive claim in JWT: {claim}",
                        Snippet = null
                    });
                }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"jwt-analyze: {ex.Message}");
        }

        try
        {
            var storageResult = await ctx.CheckStorageSecurity();
            result.SourcesScanned.Add($"storage ({storageResult.LocalStorageCount + storageResult.SessionStorageCount} keys)");

            foreach (var finding in storageResult.Findings)
            {
                result.Findings.Add(new SecretFinding
                {
                    Source = "web-storage",
                    Category = finding.Category.ToLowerInvariant(),
                    Severity = finding.Severity.ToString().ToLowerInvariant(),
                    Location = $"{finding.StorageType}.{finding.Key}",
                    Description = finding.Description,
                    Snippet = finding.ValueSnippet
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"storage-audit: {ex.Message}");
        }
    }

    private static List<NetworkEntry> FilterNetworkEntriesForScope(
        IReadOnlyList<NetworkEntry> entries, HarvestOptions options, string? pageUrl)
    {
        if (!options.LimitNetworkToScopeHost)
            return entries.Count == 0 ? [] : entries.ToList();

        var scopeHost = options.ScopeHost;
        if (string.IsNullOrWhiteSpace(scopeHost))
            scopeHost = SecurityHostScope.ResolveScopeHost(null, pageUrl);

        if (string.IsNullOrWhiteSpace(scopeHost))
            return entries.Count == 0 ? [] : entries.ToList();

        return entries.Where(e => SecurityHostScope.MatchesHostFilter(e.Host, scopeHost)).ToList();
    }

    private static void ScanNetworkResponses(
        AutomationContext ctx, HarvestOptions options, HarvestResult result)
    {
        try
        {
            var allEntries = FilterNetworkEntriesForScope(ctx.Network.Entries, options, result.Url);

            // Scan request headers for Bearer tokens / API keys
            ScanRequestHeaders(allEntries, options, result);
            ScanRequestBodies(allEntries, options, result);

            var entries = allEntries
                .Where(e => !string.IsNullOrEmpty(e.ResponseBody))
                .Where(e => e.StatusCode is >= 200 and < 400)
                .Where(e => !IsStaticContentType(e.ContentType))
                .OrderByDescending(e => IsAuthRelatedUrl(e.Url) ? 1 : 0)
                .ThenByDescending(e => e.StatusCode == 200 ? 1 : 0)
                .Take(options.MaxNetworkResponses)
                .ToList();

            result.SourcesScanned.Add($"network-responses ({entries.Count} bodies)");

            foreach (var entry in entries)
            {
                var body = ResponseBodySecurityHeuristics.ClampBody(entry.ResponseBody, 131072);
                var scanBody = ResponseBodySecurityHeuristics.StripFrameworkNoiseForSecurityEvidence(body, 131072);
                var isApiDocs = LooksLikeOpenApiOrSwagger(entry.Url, scanBody);
                ScanTextForSecrets(scanBody, $"response:{entry.Url}", "network-response", result,
                    suppressCreditCards: isApiDocs);

                var credHits = ResponseBodySecurityHeuristics.DetectCredentialExposure(scanBody,
                    ResponseBodySecurityHeuristics.DefaultMaxScanChars,
                    suppressStandaloneHexFingerprints: true);
                foreach (var hit in credHits)
                {
                    var severity = CredentialExposureSeverity(hit.Kind);
                    result.Findings.Add(new SecretFinding
                    {
                        Source = "network-response",
                        Category = hit.Kind,
                        Severity = severity,
                        Location = Truncate(entry.Url, 120),
                        Description = DescribeCredentialHit(hit.Kind),
                        Snippet = hit.Snippet
                    });
                }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"network-responses: {ex.Message}");
        }
    }

    private static void ScanRequestHeaders(
        List<NetworkEntry> entries, HarvestOptions options, HarvestResult result)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hits = 0;

        foreach (var entry in entries)
        {
            if (hits >= options.MaxNetworkResponses) break;

            foreach (var (header, value) in entry.RequestHeaders)
            {
                if (!header.Equals("Authorization", StringComparison.OrdinalIgnoreCase)
                    && !header.Equals("X-Api-Key", StringComparison.OrdinalIgnoreCase)
                    && !header.Equals("X-Auth-Token", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (string.IsNullOrEmpty(value) || value.Length < 12)
                    continue;

                var dedupKey = $"{header}|{value[..Math.Min(value.Length, 20)]}";
                if (!seen.Add(dedupKey))
                    continue;

                hits++;
                var isBearer = value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
                var tokenValue = isBearer ? value[7..] : value;
                var isJwt = tokenValue.StartsWith("eyJ", StringComparison.Ordinal)
                            && tokenValue.Count(c => c == '.') == 2;

                result.Findings.Add(new SecretFinding
                {
                    Source = "network-request",
                    Category = "api-key-in-request",
                    Severity = "info",
                    Location = Truncate(entry.Url, 120),
                    Description = $"Client-side {header} header in network request ({(isJwt ? "JWT" : isBearer ? "Bearer token" : "API key")} — expected for authenticated API calls; review if also hardcoded in JS)",
                    Snippet = RedactSecret($"{header}: {Truncate(value, 80)}")
                });
            }
        }

        if (hits > 0)
            result.SourcesScanned.Add($"network-request-headers ({hits} tokens)");
    }

    private static void ScanRequestBodies(
        List<NetworkEntry> entries, HarvestOptions options, HarvestResult result)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hits = 0;

        foreach (var entry in entries)
        {
            if (hits >= options.MaxNetworkResponses) break;
            if (string.IsNullOrWhiteSpace(entry.RequestBody)) continue;

            var credHits = NetworkRequestCredentialHeuristics.DetectPlaintextCredentials(
                entry.Url, entry.Method, entry.RequestBody, entry.ContentType);
            foreach (var hit in credHits.Where(h => !h.IsHashed))
            {
                var dedupKey = $"{entry.Url}|{hit.FieldName}|{hit.Kind}";
                if (!seen.Add(dedupKey)) continue;
                hits++;
                var bodySeverity = hit.IsAuthEndpoint ? "info" : "medium";
                result.Findings.Add(new SecretFinding
                {
                    Source = "network-request-body",
                    Category = "plaintext-password-in-transit",
                    Severity = bodySeverity,
                    Location = Truncate(entry.Url, 120),
                    Description = hit.IsAuthEndpoint
                        ? $"Password field '{hit.FieldName}' in {entry.Method} auth request (expected over TLS; not client-side hashed)."
                        : $"Sensitive password field '{hit.FieldName}' sent in {entry.Method} request body.",
                    Snippet = hit.Snippet
                });
            }
        }

        if (hits > 0)
            result.SourcesScanned.Add($"network-request-bodies ({hits} plaintext password field(s))");
    }

    private static async Task ScanPageText(
        AutomationContext ctx, HarvestResult result, CancellationToken ct)
    {
        try
        {
            var pageText = await ctx.GetPageText();
            result.SourcesScanned.Add("page-text");

            if (!string.IsNullOrEmpty(pageText) && pageText.Length > 10)
            {
                ScanTextForSecrets(pageText, "visible-page-text", "page-text", result);
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"page-text: {ex.Message}");
        }
    }

    private static async Task ScanSourceMaps(
        AutomationContext ctx, HarvestResult result, CancellationToken ct)
    {
        try
        {
            var smResult = await ctx.CheckSourceMaps();
            result.SourcesScanned.Add("source-maps");

            foreach (var finding in smResult.Findings)
            {
                var category = finding.Category.Contains("map", StringComparison.OrdinalIgnoreCase)
                    ? "source-map-exposed"
                    : finding.Category.Contains("debug", StringComparison.OrdinalIgnoreCase)
                        ? "debug-mode-active"
                        : finding.Category;

                result.Findings.Add(new SecretFinding
                {
                    Source = "source-maps",
                    Category = category,
                    Severity = finding.Severity.ToString().ToLowerInvariant(),
                    Location = finding.Url ?? "page",
                    Description = finding.Description,
                    Snippet = finding.Detail
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"source-maps: {ex.Message}");
        }
    }

    private static async Task ScanHtmlComments(
        AutomationContext ctx, HarvestResult result, CancellationToken ct)
    {
        try
        {
            var html = await ctx.GetPageSource();
            result.SourcesScanned.Add("html-comments");
            if (string.IsNullOrEmpty(html)) return;

            var capped = html.Length > 500_000 ? html[..500_000] : html;
            var hits = 0;
            foreach (Match m in HtmlComment.Matches(capped))
            {
                if (++hits > 20) break;
                var inner = m.Groups[1].Value.Trim();
                if (inner.Length < 4) continue;
                ScanTextForSecrets(inner, "html-comment", "html-comment", result);
            }

            foreach (var hit in AssetSecretsCommentMiner.ScanText(capped, "page-html"))
            {
                if (hit.Category is "comment-block" or "comment-hygiene")
                {
                    if (hit.Category == "comment-hygiene")
                    {
                        result.Findings.Add(new SecretFinding
                        {
                            Source = "html-comments",
                            Category = hit.Category,
                            Severity = "info",
                            Location = hit.Source,
                            Description = $"Comment hygiene: {hit.Category}",
                            Snippet = hit.Snippet
                        });
                    }
                    continue;
                }

                result.Findings.Add(new SecretFinding
                {
                    Source = "html-comments",
                    Category = hit.Category,
                    Severity = hit.Category.Contains("secret", StringComparison.OrdinalIgnoreCase) ? "low" : "info",
                    Location = hit.Source,
                    Description = $"Comment/base64 mining: {hit.Category}",
                    Snippet = hit.Snippet
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"html-comments: {ex.Message}");
        }
    }

    private static void ScanTextForSecrets(
        string text, string location, string source, HarvestResult result,
        bool suppressCreditCards = false)
    {
        if (string.IsNullOrEmpty(text)) return;
        var capped = text.Length > 500_000 ? text[..500_000] : text;

        CheckPattern(capped, EmailAddress, "email-address", "info", "Email address", location, source, result, maxHits: 8);
        if (!suppressCreditCards)
            CheckCreditCards(capped, location, source, result);

        CheckPattern(capped, JwtPattern, "jwt-token", "high", "JWT token found", location, source, result);
        CheckPattern(capped, ApiKeyPattern, "api-key", "high", "API key pattern", location, source, result, maxHits: 5);
        CheckPattern(capped, JsonApiKeyPattern, "api-key", "medium", "JSON API key property", location, source, result, maxHits: 5);
        CheckPattern(capped, BearerPattern, "bearer-token", "high", "Bearer token", location, source, result, maxHits: 3);
        CheckPattern(capped, PasswordPattern, "password", "critical", "Hardcoded password", location, source, result, maxHits: 5);
        CheckPattern(capped, AwsKeyPattern, "aws-access-key", "critical", "AWS access key ID", location, source, result, maxHits: 3);
        CheckPattern(capped, PrivateKeyPattern, "private-key", "critical", "Private key header", location, source, result, maxHits: 2);
        CheckPattern(capped, ConnectionStringPattern, "connection-string", "critical", "Database/service connection string", location, source, result, maxHits: 3);
        CheckPattern(capped, GenericSecretAssignment, "secret-assignment", "high", "Secret/token assignment", location, source, result, maxHits: 5);
        CheckPattern(capped, EmailPasswordCombo, "email-password-combo", "critical", "Email + password combination", location, source, result, maxHits: 3);
    }

    private static void CheckCreditCards(string text, string location, string source, HarvestResult result)
    {
        var hits = 0;
        foreach (Match m in CreditCardCandidate.Matches(text))
        {
            if (++hits > 5) break;
            var digits = new string(m.Value.Where(char.IsDigit).ToArray());
            if (digits.Length < 13 || !PassesLuhn(digits)) continue;
            if (SecretsHarvestHeuristics.IsCurrencyOrExchangeRateUrl(location)
                || SecretsHarvestHeuristics.LooksLikeCurrencyRateContext(text, m.Index))
                continue;
            // OpenAPI/Swagger example schemas commonly use Luhn-valid PANs (4111…).
            if (LooksLikeOpenApiExampleContext(text, m.Index))
                continue;
            var masked = digits.Length > 4 ? new string('*', digits.Length - 4) + digits[^4..] : "****";
            result.Findings.Add(new SecretFinding
            {
                Source = source,
                Category = "credit-card",
                Severity = "high",
                Location = location,
                Description = "Credit card number pattern (Luhn-valid)",
                Snippet = masked
            });
        }
    }

    /// <summary>True for swagger/openapi URLs or bodies that look like OpenAPI documents.</summary>
    internal static bool LooksLikeOpenApiOrSwagger(string? url, string? body)
    {
        if (!string.IsNullOrEmpty(url))
        {
            var u = url;
            if (u.Contains("swagger", StringComparison.OrdinalIgnoreCase)
                || u.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                || u.Contains("/api-docs", StringComparison.OrdinalIgnoreCase)
                || u.Contains("swagger-resources", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (string.IsNullOrEmpty(body)) return false;
        var trim = body.TrimStart();
        if (trim.Length > 0 && trim[0] == '{')
        {
            return trim.Contains("\"openapi\"", StringComparison.OrdinalIgnoreCase)
                   || trim.Contains("\"swagger\":", StringComparison.OrdinalIgnoreCase);
        }

        return trim.StartsWith("openapi:", StringComparison.OrdinalIgnoreCase)
               || trim.StartsWith("swagger:", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Heuristic: PAN sits near OpenAPI example / schema keywords.</summary>
    private static bool LooksLikeOpenApiExampleContext(string text, int matchIndex)
    {
        var start = Math.Max(0, matchIndex - 120);
        var len = Math.Min(text.Length - start, 240);
        if (len <= 0) return false;
        var window = text.AsSpan(start, len);
        return window.Contains("\"example\"", StringComparison.OrdinalIgnoreCase)
               || window.Contains("\"examples\"", StringComparison.OrdinalIgnoreCase)
               || window.Contains("\"exampleSetFlag\"", StringComparison.OrdinalIgnoreCase)
               || window.Contains("format\": \"credit", StringComparison.OrdinalIgnoreCase)
               || window.Contains("format\": \"credit-card", StringComparison.OrdinalIgnoreCase)
               || window.Contains("\"schema\"", StringComparison.OrdinalIgnoreCase)
                  && window.Contains("\"type\"", StringComparison.OrdinalIgnoreCase);
    }

    private static bool PassesLuhn(string digits)
    {
        var sum = 0;
        var alt = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            if (!char.IsDigit(digits[i])) return false;
            var n = digits[i] - '0';
            if (alt)
            {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alt = !alt;
        }
        return sum % 10 == 0;
    }

    private static void CheckPattern(
        string text, Regex pattern, string category, string severity,
        string description, string location, string source,
        HarvestResult result, int maxHits = 5)
    {
        var hits = 0;
        foreach (Match m in pattern.Matches(text))
        {
            if (++hits > maxHits) break;

            // Prefer evidence that includes the proving value (password combo / secret),
            // not just a leading username token like "admin".
            var snippet = category is "password" or "email-password-combo" or "secret-assignment" or "api-key"
                ? EvidenceSnippet(text, m, 160)
                : Snippet(text, m.Index, 120);
            if (category is "password" or "secret-assignment" or "api-key" or "email-password-combo"
                && SecretsHarvestHeuristics.IsFalsePositiveSnippet(snippet))
                continue;
            if (category == "secret-assignment")
            {
                var probe = new SecretFinding { Snippet = snippet, Category = category };
                if (SecretsHarvestHeuristics.IsMisclassifiedIdentifierConstantAssignment(probe))
                    continue;
            }
            if (category == "email-address" && IsRetinaAssetEmailFalsePositive(m.Value))
                continue;
            if (SecretsHarvestHeuristics.TryGetCapturedSecretValue(m, out var captured)
                && SecretsHarvestHeuristics.IsPlaceholderSecretValue(captured))
                continue;

            var effectiveSeverity = severity;
            var effectiveDescription = description;
            if (category is "password" or "secret-assignment"
                && SecretsHarvestHeuristics.TryGetCapturedSecretValue(m, out var weakVal)
                && SecretsHarvestHeuristics.IsWeakCredentialAssignment(category, weakVal))
            {
                // Form labels / i18n in JS bundles — do not emit as critical/high.
                effectiveSeverity = "info";
                effectiveDescription = $"Possible {category} label/assignment (weak proof — review manually)";
            }

            if (category == "api-key" && source == "js-bundle"
                && !effectiveDescription.Contains("network log", StringComparison.OrdinalIgnoreCase))
            {
                effectiveDescription +=
                    " Verify whether the value is sent on requests (check network log / fetch replay).";
            }

            result.Findings.Add(new SecretFinding
            {
                Source = source,
                Category = category,
                Severity = effectiveSeverity,
                Location = location,
                Description = effectiveDescription,
                Snippet = RedactSecret(snippet)
            });
        }
    }

    private static void DeduplicateFindings(HarvestResult result)
    {
        var grouped = result.Findings
            .GroupBy(f => $"{f.Source}|{f.Category}|{NormalizeForDedup(f.Snippet)}")
            .Select(g => g.First())
            .ToList();

        var emailByHost = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var jwtStorageKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in grouped)
        {
            if (f.Category.Equals("jwt-token", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(f.Location))
                jwtStorageKeys.Add(NormalizeStorageKey(f.Location));
        }

        var deduped = new List<SecretFinding>();
        foreach (var f in grouped)
        {
            if (f.Category.Equals("email-address", StringComparison.OrdinalIgnoreCase))
            {
                var host = TryGetUrlHost(f.Location) ?? f.Location;
                if (!emailByHost.Add(host))
                    continue;
                f.Severity = "info";
            }

            if (f.Source.Equals("web-storage", StringComparison.OrdinalIgnoreCase)
                && (f.Category.Contains("jwt", StringComparison.OrdinalIgnoreCase)
                    || f.Category.Contains("authtoken", StringComparison.OrdinalIgnoreCase))
                && jwtStorageKeys.Contains(NormalizeStorageKey(f.Location)))
                continue;

            if (f.Source.Equals("source-maps", StringComparison.OrdinalIgnoreCase)
                && f.Category.Equals("debug-mode-active", StringComparison.OrdinalIgnoreCase)
                && deduped.Any(d => d.Source.Equals("source-maps", StringComparison.OrdinalIgnoreCase)
                                    && d.Category.Equals("debug-mode-active", StringComparison.OrdinalIgnoreCase)
                                    && string.Equals(d.Description, f.Description, StringComparison.Ordinal)))
                continue;

            deduped.Add(f);
        }

        result.Findings = deduped;
    }

    private static string NormalizeStorageKey(string location)
    {
        var t = location.Trim();
        var dot = t.LastIndexOf('.');
        return dot >= 0 ? t[(dot + 1)..] : t;
    }

    private static string? TryGetUrlHost(string location)
    {
        if (Uri.TryCreate(location, UriKind.Absolute, out var uri))
            return uri.Host;
        var idx = location.IndexOf("://", StringComparison.Ordinal);
        if (idx < 0) return null;
        var rest = location[(idx + 3)..];
        var slash = rest.IndexOf('/');
        return slash > 0 ? rest[..slash] : rest;
    }

    private static bool IsAuthRelatedUrl(string url)
    {
        return SecretsHarvestHeuristics.IsAuthRelatedHarvestUrl(url);
    }

    private static string NormalizeForDedup(string? snippet)
    {
        if (string.IsNullOrEmpty(snippet)) return "";
        if (snippet.Length < 16) return snippet;
        return snippet[..16];
    }

    private static HarvestSummary BuildSummary(List<SecretFinding> findings)
    {
        var summary = new HarvestSummary
        {
            Critical = findings.Count(f => f.Severity == "critical"),
            High = findings.Count(f => f.Severity == "high"),
            Medium = findings.Count(f => f.Severity == "medium"),
            Low = findings.Count(f => f.Severity == "low"),
            Info = findings.Count(f => f.Severity == "info"),
        };

        foreach (var g in findings.GroupBy(f => f.Source))
            summary.BySource[g.Key] = g.Count();

        foreach (var g in findings.GroupBy(f => f.Category))
            summary.ByCategory[g.Key] = g.Count();

        return summary;
    }

    private static (string severity, string category) ClassifyJsHit(JavaScriptStaticAudit.JsContentHit hit) =>
        hit.Category switch
        {
            // Only elevate when the assignment survived UI-label / weak-value filters.
            "credential-like-assignment" => ("medium", "hardcoded-credential"),
            "email-credential-proximity" => ("medium", "email-password-combo"),
            "internal-or-private-url" => ("low", "internal-url"),
            "debug-or-test-tuning" => ("info", "debug-flag"),
            _ => ("low", hit.Category)
        };

    private static string CredentialExposureSeverity(string kind)
    {
        // Docs: plaintext password / email+password combos in API responses → CRITICAL.
        if (kind.Contains("email-password-combo", StringComparison.OrdinalIgnoreCase)
            || kind.Contains("plaintext-password", StringComparison.OrdinalIgnoreCase))
            return "critical";
        if (kind.Contains("password-hash", StringComparison.OrdinalIgnoreCase))
            return "medium";
        if (kind.Contains("bearer", StringComparison.OrdinalIgnoreCase))
            return "medium";
        if (kind.Contains("email", StringComparison.OrdinalIgnoreCase))
            return "info";
        if (kind.Contains("md5", StringComparison.OrdinalIgnoreCase)
            || kind.Contains("sha1", StringComparison.OrdinalIgnoreCase)
            || kind.Contains("sha256", StringComparison.OrdinalIgnoreCase))
            return "low";
        return "medium";
    }

    private static string DescribeCredentialHit(string kind) =>
        kind.Contains("email-password-combo", StringComparison.OrdinalIgnoreCase)
            ? "Email + password combination in API response"
            : kind.Contains("plaintext-password", StringComparison.OrdinalIgnoreCase)
                ? "Plaintext password field in API response"
                : kind.Contains("email", StringComparison.OrdinalIgnoreCase)
                    ? "Email address in response"
                    : $"Possible credential material in response: {kind}";

    private static void CalibrateFindings(HarvestResult result)
    {
        var kept = new List<SecretFinding>(result.Findings.Count);
        var filtered = 0;
        foreach (var f in result.Findings)
        {
            if (SecretsHarvestHeuristics.ShouldHardSuppress(f))
            {
                filtered++;
                continue;
            }
            SecretsHarvestHeuristics.CalibrateFinding(f);
            kept.Add(f);
        }
        result.FilteredNoise = filtered;
        result.Findings = kept;
    }

    /// <summary>Ad/GTM bundles can produce dozens of identical comment-block hits per script URL.</summary>
    private static void CapCommentBlockFindings(HarvestResult result, int maxPerLocation)
    {
        if (maxPerLocation <= 0) return;

        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var kept = new List<SecretFinding>(result.Findings.Count);
        var filtered = 0;

        foreach (var f in result.Findings)
        {
            if (f.Category is not ("comment-block" or "comment-hygiene"))
            {
                kept.Add(f);
                continue;
            }

            var loc = f.Location ?? "";
            counts.TryGetValue(loc, out var c);
            if (c >= maxPerLocation)
            {
                filtered++;
                continue;
            }

            counts[loc] = c + 1;
            kept.Add(f);
        }

        result.FilteredNoise += filtered;
        result.Findings = kept;
    }

    /// <summary>
    /// Plain md5/sha1/sha256 hex digests in JS are usually chunk hashes / build IDs — not leaked credentials.
    /// </summary>
    private static bool OmitStandaloneHexFingerprintsForLikelyJavascript(NetworkEntry entry)
    {
        var ct = entry.ContentType ?? "";
        if (ct.Contains("javascript", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("ecmascript", StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.IsNullOrEmpty(entry.Url) && Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
        {
            var ext = Path.GetExtension(uri.AbsolutePath);
            return ext.Equals(".js", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".mjs", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".cjs", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static bool IsStaticContentType(string ct) =>
        string.IsNullOrEmpty(ct) ||
        ct.Contains("image/", StringComparison.OrdinalIgnoreCase) ||
        ct.Contains("font/", StringComparison.OrdinalIgnoreCase) ||
        ct.Contains("audio/", StringComparison.OrdinalIgnoreCase) ||
        ct.Contains("video/", StringComparison.OrdinalIgnoreCase) ||
        ct.Contains("/css", StringComparison.OrdinalIgnoreCase) ||
        ct.Contains("/woff", StringComparison.OrdinalIgnoreCase);

    private static int SeverityRank(string s) => s switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0
    };

    private static string Truncate(string s, int max)
    {
        if (s.Length <= max) return s;
        return s[..(max - 3)] + "...";
    }

    private static string Snippet(string text, int index, int maxLen)
    {
        var start = Math.Max(0, index - 30);
        var end = Math.Min(text.Length, start + maxLen);
        start = Math.Max(0, end - maxLen);
        var slice = text[start..end].Replace('\r', ' ').Replace('\n', ' ');
        if (start > 0) slice = "…" + slice;
        if (end < text.Length) slice += "…";
        return slice;
    }

    /// <summary>
    /// Build a snippet centered on the full match (and captured secret when present) so CRITICAL
    /// credential findings show username+password evidence, not just a leading identifier.
    /// </summary>
    private static string EvidenceSnippet(string text, Match m, int maxLen)
    {
        var focusIndex = m.Index;
        var focusLen = m.Length;
        if (SecretsHarvestHeuristics.TryGetCapturedSecretValue(m, out var captured)
            && !string.IsNullOrEmpty(captured))
        {
            var capturedAt = text.IndexOf(captured, m.Index, StringComparison.Ordinal);
            if (capturedAt >= m.Index && capturedAt < m.Index + m.Length)
            {
                focusIndex = Math.Max(m.Index, capturedAt - 40);
                focusLen = Math.Min(text.Length - focusIndex, Math.Max(captured.Length + 80, m.Length));
            }
        }

        var start = Math.Max(0, focusIndex - 20);
        var end = Math.Min(text.Length, start + Math.Max(maxLen, focusLen + 40));
        start = Math.Max(0, end - Math.Max(maxLen, focusLen + 40));
        var slice = text[start..end].Replace('\r', ' ').Replace('\n', ' ');
        if (start > 0) slice = "…" + slice;
        if (end < text.Length) slice += "…";
        return slice;
    }

    private static string RedactSecret(string s)
    {
        // Keep short tokens (usernames / short passwords) visible — they are often the proof.
        // Only redact long high-entropy secrets.
        return Regex.Replace(s, @"[""']([A-Za-z0-9+/=_\-.]{16,200})[""']", m =>
        {
            var v = m.Groups[1].Value;
            if (v.Length < 16) return m.Value;
            return m.Value[0] + v[..4] + "…" + v.Length + "chars…" + m.Value[^1];
        });
    }
}
