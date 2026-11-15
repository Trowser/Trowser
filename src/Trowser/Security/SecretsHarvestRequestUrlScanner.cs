using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Passive scan of captured request URLs for JWTs and high-risk query/fragment parameters.
/// </summary>
internal static class SecretsHarvestRequestUrlScanner
{
    internal readonly struct UrlParamMatch
    {
        public string Parameter { get; init; }
        public string Value { get; init; }
        public string Placement { get; init; }
    }

    private static readonly Regex JwtPattern = new(
        @"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly HashSet<string> RoutineOAuthParams = new(StringComparer.OrdinalIgnoreCase)
    {
        "state", "nonce", "code", "session_state", "redirect_uri", "post_logout_redirect_uri",
        "client_id", "response_type", "scope", "grant_type", "prompt", "login_hint",
        "code_challenge", "code_verifier", "code_challenge_method", "acr_values", "claims",
        "request", "request_uri", "registration", "max_age", "ui_locales", "resource",
        "id_token_hint", "access_token", "refresh_token", "id_token", "token_type",
    };

    public static void CollectJwtInUrlFindings(
        IReadOnlyList<NetworkEntry> entries,
        string? pageUrl,
        SecretsHarvestPipeline.HarvestResult result,
        int maxHits = 20)
    {
        if (maxHits <= 0) return;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var hits = 0;

        foreach (var entry in entries)
        {
            if (hits >= maxHits) break;
            if (entry.IsTrowserGenerated) continue;
            if (SecurityHostScope.IsWellKnownThirdPartyHost(entry.Host)) continue;
            hits += AppendJwtUrlFindings(entry.Url, "network-request-url", seen, result, maxHits - hits);
        }

        if (hits < maxHits && !string.IsNullOrEmpty(pageUrl))
            hits += AppendJwtUrlFindings(pageUrl, "page-url", seen, result, maxHits - hits);

        if (hits > 0)
            result.SourcesScanned.Add($"network-request-urls ({hits} jwt)");
    }

    public static void CollectSensitiveQueryParamFindings(
        IReadOnlyList<NetworkEntry> entries,
        string? pageUrl,
        SecretsHarvestPipeline.HarvestResult result,
        int maxHits = 20)
    {
        if (maxHits <= 0) return;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var hits = 0;

        foreach (var entry in entries)
        {
            if (hits >= maxHits) break;
            if (entry.IsTrowserGenerated) continue;
            if (SecurityHostScope.IsWellKnownThirdPartyHost(entry.Host)) continue;
            hits += AppendSensitiveUrlFindings(entry.Url, "network-request-url", seen, result, maxHits - hits);
        }

        if (hits < maxHits && !string.IsNullOrEmpty(pageUrl))
            hits += AppendSensitiveUrlFindings(pageUrl, "page-url", seen, result, maxHits - hits);

        if (hits > 0)
            result.SourcesScanned.Add($"network-request-urls ({hits} named secret param)");
    }

    private static int AppendJwtUrlFindings(
        string url, string source, HashSet<string> seen, SecretsHarvestPipeline.HarvestResult result, int remaining)
    {
        var added = 0;
        foreach (var hit in EnumerateUrlParams(url))
        {
            if (added >= remaining) break;
            var jwt = JwtPattern.Match(hit.Value);
            if (!jwt.Success && hit.Placement == "path")
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                    continue;
                jwt = JwtPattern.Match(uri.AbsolutePath);
            }

            if (!jwt.Success) continue;

            var token = jwt.Value;
            var dedup = hit.Parameter + "|" + hit.Placement + "|" + TokenFingerprint(token);
            if (!seen.Add(dedup)) continue;

            var where = PlacementLabel(hit.Placement);
            result.Findings.Add(new SecretsHarvestPipeline.SecretFinding
            {
                Source = source,
                Category = "jwt-in-url",
                Severity = JwtUrlSeverity(hit.Parameter),
                Location = FormatUrlParamLocation(url, hit.Parameter, hit.Placement),
                Description = DescribeJwtInUrl(hit.Parameter, where),
                Snippet = token
            });
            added++;
        }

        return added;
    }

    private static int AppendSensitiveUrlFindings(
        string url, string source, HashSet<string> seen, SecretsHarvestPipeline.HarvestResult result, int remaining)
    {
        var added = 0;
        foreach (var hit in EnumerateUrlParams(url))
        {
            if (added >= remaining) break;
            if (string.IsNullOrEmpty(hit.Parameter)) continue;
            if (JwtPattern.IsMatch(hit.Value)) continue;
            if (ShouldSkipRoutineUrlParam(hit.Parameter, hit.Value)) continue;
            if (!TryClassifySensitiveParam(hit.Parameter, out var tier)) continue;
            if (!LooksLikeSensitiveUrlValue(hit.Parameter, hit.Value, tier)) continue;

            var dedup = $"{hit.Parameter}|{hit.Placement}|{ValueDedupKey(hit.Value)}";
            if (!seen.Add(dedup)) continue;

            var where = PlacementLabel(hit.Placement);
            result.Findings.Add(new SecretsHarvestPipeline.SecretFinding
            {
                Source = source,
                Category = "sensitive-query-param",
                Severity = SensitiveParamSeverity(tier),
                Location = FormatUrlParamLocation(url, hit.Parameter, hit.Placement),
                Description = $"Sensitive value in URL {where} parameter '{hit.Parameter}'. "
                              + "Query strings are stored in history, proxy logs, and Referer.",
                Snippet = hit.Value
            });
            added++;
        }

        return added;
    }

    private static IEnumerable<UrlParamMatch> EnumerateUrlParams(string url)
    {
        if (string.IsNullOrEmpty(url)) yield break;

        var hash = url.IndexOf('#');
        var queryStart = url.IndexOf('?');
        if (queryStart >= 0 && (hash < 0 || queryStart < hash))
        {
            var end = hash > queryStart ? hash : url.Length;
            foreach (var hit in ParamsIn(url[(queryStart + 1)..end], "query"))
                yield return hit;
        }

        if (hash >= 0 && hash + 1 < url.Length)
        {
            foreach (var hit in ParamsIn(url[(hash + 1)..], "fragment"))
                yield return hit;
        }

        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.AbsolutePath.Contains("eyJ", StringComparison.Ordinal))
        {
            yield return new UrlParamMatch
            {
                Parameter = "",
                Value = uri.AbsolutePath,
                Placement = "path"
            };
        }
    }

    private static IEnumerable<UrlParamMatch> ParamsIn(string raw, string placement)
    {
        foreach (var part in raw.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            string name;
            string value;
            if (eq <= 0)
            {
                name = "";
                value = UnescapeUrlPart(part);
            }
            else
            {
                name = UnescapeUrlPart(part[..eq]);
                value = UnescapeUrlPart(part[(eq + 1)..]);
            }

            yield return new UrlParamMatch
            {
                Parameter = name,
                Value = value,
                Placement = placement
            };
        }
    }

    private static bool ShouldSkipRoutineUrlParam(string name, string value)
    {
        if (RoutineOAuthParams.Contains(name))
            return true;
        if (CsrfTokenHeuristics.IsKnownCsrfFieldName(name))
            return true;
        if (CsrfTokenHeuristics.IsCsrfFieldCandidate(name, "hidden", value))
            return true;
        return false;
    }

    private static bool TryClassifySensitiveParam(string name, out string tier)
    {
        tier = "";
        if (string.IsNullOrWhiteSpace(name)) return false;
        var n = name.ToLowerInvariant().Replace('-', '_');

        if (n is "password" or "passwd" or "pwd" or "client_secret" or "clientsecret")
        {
            tier = "password";
            return true;
        }

        if (n is "api_key" or "apikey" or "x_api_key" or "secret_key")
        {
            tier = "api-key";
            return true;
        }

        if (n is "private_key" or "privatekey" or "signing_key" or "auth_key"
            or "credential" or "connection_string" or "secret")
        {
            tier = "secret";
            return true;
        }

        return false;
    }

    private static bool LooksLikeSensitiveUrlValue(string paramName, string value, string tier)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var minLen = tier == "password" ? 4 : 8;
        if (value.Length < minLen) return false;
        if (SecretsHarvestHeuristics.IsPlaceholderSecretValue(value)) return false;
        if (SecretsHarvestHeuristics.IsWeakCredentialAssignment(paramName, value)) return false;

        if (tier != "password" && value.Length <= 24)
        {
            if (value.All(char.IsDigit))
                return false;
            if (value.Length <= 16 && value.All(c => char.IsUpper(c) || char.IsDigit(c) || c is '_' or '-'))
                return false;
        }

        return true;
    }

    private static string SensitiveParamSeverity(string tier) => tier switch
    {
        "password" or "api-key" => "high",
        _ => "medium"
    };

    private static string JwtUrlSeverity(string parameter)
    {
        if (parameter.Equals("access_token", StringComparison.OrdinalIgnoreCase)
            || parameter.Equals("refresh_token", StringComparison.OrdinalIgnoreCase)
            || parameter.Equals("id_token", StringComparison.OrdinalIgnoreCase))
            return "medium";
        return "low";
    }

    internal static string DescribeJwtInUrl(string parameter, string where)
    {
        var place = string.IsNullOrEmpty(parameter)
            ? $"JWT in the URL {where}."
            : $"JWT in {where} parameter '{parameter}'.";
        return place + " Paste it at jwt.io and check that the payload has no sensitive claims.";
    }

    private static string FormatUrlParamLocation(string url, string parameter, string placement)
    {
        var label = string.IsNullOrEmpty(parameter) ? "value" : parameter;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var path = uri.GetLeftPart(UriPartial.Path);
            if (placement == "path")
                return Truncate(path, 180);
            var mark = placement == "fragment" ? "#" : "?";
            return Truncate($"{path}{mark}{label}=…", 180);
        }

        return Truncate($"{label}=…", 180);
    }

    private static string PlacementLabel(string placement) => placement switch
    {
        "fragment" => "fragment",
        "path" => "path",
        _ => "query"
    };

    private static string UnescapeUrlPart(string value)
    {
        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }

    private static string TokenFingerprint(string token)
    {
        if (string.IsNullOrEmpty(token)) return "";
        return token.Length <= 8 ? token : token[^8..];
    }

    private static string ValueDedupKey(string value) =>
        value.Length <= 16 ? value : value[..8] + "…" + value[^8..];

    private static string Truncate(string s, int max)
    {
        if (s.Length <= max) return s;
        return s[..(max - 3)] + "...";
    }
}