using System.Text.Json;
using System.Text.Json.Nodes;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Traffic-driven discovery for insecure-design probes (race, captcha replay, workflow skip).
/// Uses generic path/body heuristics — not tied to a specific application vertical.
/// </summary>
public static class InsecureDesignDiscovery
{
    public sealed class PostTarget
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string? BodyTemplate { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public string Source { get; init; } = "network";
        public string MatchReason { get; init; } = "";
        public bool RequiresAuth { get; init; }
    }

    public sealed class WorkflowCandidate
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string? BodyTemplate { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public int StageRank { get; init; }
        public string PathPrefix { get; init; } = "";
        public string Source { get; init; } = "network";
    }

    private static readonly string[] SingleUsePathSegments =
    [
        "feedback", "review", "comment", "like", "vote", "redeem", "claim", "withdraw",
        "checkout", "confirm", "submit", "apply", "consume", "activate", "approve",
        "finalize", "complete", "receipt", "transfer", "enrollment", "enroll"
    ];

    private static readonly string[] SingleUseBodyFieldHints =
    [
        "code", "coupon", "voucher", "promo", "token", "nonce", "otp", "captcha"
    ];

    private static readonly string[] LateStagePathSegments =
    [
        "complete", "confirm", "finalize", "submit", "execute", "redeem", "claim",
        "withdraw", "transfer", "approve", "publish", "activate", "verify", "checkout",
        "payment", "pay", "place", "commit", "process", "enroll", "issue", "grant", "close"
    ];

    private static readonly string[] EarlyStagePathSegments =
    [
        "create", "init", "start", "draft", "add", "prepare", "begin", "open", "new", "register"
    ];

    private static readonly string[] CaptchaServiceSegments =
    [
        "captcha", "challenge", "recaptcha", "hcaptcha", "turnstile", "verify-challenge"
    ];

    private static readonly string[] CaptchaIdKeys =
    [
        "captchaId", "captchaID", "challengeId", "challenge_id", "id"
    ];

    private static readonly string[] CaptchaAnswerKeys =
    [
        "answer", "solution", "result", "captcha", "response", "token"
    ];

    private static readonly string[] CaptchaBodyFieldHints =
    [
        "captchaId", "captcha", "challengeId", "challenge", "captchaResponse", "g-recaptcha-response"
    ];

    public static List<PostTarget> DiscoverSingleUsePostTargets(
        AutomationContext ctx,
        string origin,
        int maxCandidates,
        IReadOnlyList<string>? explicitUrls = null)
    {
        var list = new List<PostTarget>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (explicitUrls != null)
        {
            foreach (var url in explicitUrls.Where(u => !string.IsNullOrWhiteSpace(u)))
            {
                var target = BuildExplicitPostTarget(ctx, origin, url.Trim());
                if (target == null || !seen.Add($"{target.Url}|{target.Method}")) continue;
                list.Add(target);
                if (list.Count >= maxCandidates) return list;
            }
        }

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.Method is not ("POST" or "PUT" or "PATCH")) continue;
            if (entry.StatusCode is < 200 or >= 500) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var path = uri.AbsolutePath;
            var pathMatch = SingleUsePathSegments.FirstOrDefault(s =>
                PathContainsSegment(path, s));
            var bodyMatch = !string.IsNullOrEmpty(entry.RequestBody)
                            && SingleUseBodyFieldHints.Any(h =>
                                BodyContainsField(entry.RequestBody!, h));

            if (pathMatch == null && !bodyMatch) continue;

            var key = $"{entry.Method}|{entry.Url}";
            if (!seen.Add(key)) continue;

            list.Add(BuildTargetFromEntry(entry, pathMatch ?? (bodyMatch ? "body-field" : "single-use")));
            if (list.Count >= maxCandidates) return list;
        }

        return list;
    }

    public static List<PostTarget> DiscoverRedeemCodeTargets(
        AutomationContext ctx,
        string origin,
        int maxCandidates)
    {
        var list = new List<PostTarget>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.Method is not ("POST" or "PUT" or "PATCH")) continue;
            if (string.IsNullOrEmpty(entry.RequestBody)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            if (!SingleUseBodyFieldHints.Any(h => BodyContainsField(entry.RequestBody!, h)))
                continue;

            var key = $"{entry.Method}|{entry.Url}";
            if (!seen.Add(key)) continue;

            list.Add(BuildTargetFromEntry(entry, "redeem-code-body"));
            if (list.Count >= maxCandidates) return list;
        }

        return list;
    }

    public static List<string> DiscoverCaptchaServiceUrls(AutomationContext ctx, string origin, int maxCandidates)
    {
        var urls = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in ctx.Network.Entries)
        {
            if (!string.Equals(entry.Method, "GET", StringComparison.OrdinalIgnoreCase)) continue;
            if (entry.StatusCode is < 200 or >= 400) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            if (!CaptchaServiceSegments.Any(s => PathContainsSegment(uri.AbsolutePath, s))) continue;
            if (!seen.Add(entry.Url)) continue;
            urls.Add(entry.Url);
            if (urls.Count >= maxCandidates) break;
        }

        if (urls.Count == 0)
        {
            foreach (var path in new[] { "/api/captcha", "/captcha", "/api/challenge", "/challenge" })
            {
                var url = origin.TrimEnd('/') + path;
                if (seen.Add(url)) urls.Add(url);
            }
        }

        return urls.Take(maxCandidates).ToList();
    }

    public static List<PostTarget> DiscoverCaptchaSubmitTargets(
        AutomationContext ctx,
        string origin,
        int maxCandidates)
    {
        var list = new List<PostTarget>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.Method is not ("POST" or "PUT" or "PATCH")) continue;
            if (string.IsNullOrEmpty(entry.RequestBody)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            if (!CaptchaBodyFieldHints.Any(h => BodyContainsField(entry.RequestBody!, h))) continue;

            var key = $"{entry.Method}|{entry.Url}";
            if (!seen.Add(key)) continue;

            list.Add(BuildTargetFromEntry(entry, "captcha-gated-submit"));
            if (list.Count >= maxCandidates) return list;
        }

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.Method is not ("POST" or "PUT" or "PATCH")) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var path = uri.AbsolutePath;
            if (!SingleUsePathSegments.Any(s => PathContainsSegment(path, s))) continue;

            var key = $"{entry.Method}|{entry.Url}";
            if (!seen.Add(key)) continue;

            list.Add(BuildTargetFromEntry(entry, "comment-submit-fallback"));
            if (list.Count >= maxCandidates) return list;
        }

        return list;
    }

    public static List<WorkflowCandidate> DiscoverWorkflowSkipCandidates(
        AutomationContext ctx,
        string origin,
        int maxCandidates,
        IReadOnlyList<string>? explicitUrls = null)
    {
        var candidates = new List<WorkflowCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (explicitUrls != null)
        {
            foreach (var url in explicitUrls.Where(u => !string.IsNullOrWhiteSpace(u)))
            {
                var target = BuildExplicitPostTarget(ctx, origin, url.Trim());
                if (target == null) continue;
                if (!Uri.TryCreate(target.Url, UriKind.Absolute, out var uri)) continue;
                var key = $"{target.Method}|{target.Url}";
                if (!seen.Add(key)) continue;

                candidates.Add(new WorkflowCandidate
                {
                    Url = target.Url,
                    Method = target.Method,
                    BodyTemplate = target.BodyTemplate,
                    Headers = target.Headers,
                    StageRank = Math.Max(ScoreStageRank(uri.AbsolutePath), 1),
                    PathPrefix = GetPathPrefix(uri, 3),
                    Source = "explicit-url"
                });
            }

            if (candidates.Count > 0)
                return candidates.Take(maxCandidates).ToList();
        }

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.Method is not ("POST" or "PUT" or "PATCH")) continue;
            if (entry.StatusCode is < 200 or >= 500) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var path = uri.AbsolutePath;
            var late = LateStagePathSegments.FirstOrDefault(s => PathContainsSegment(path, s));
            if (late == null) continue;

            var rank = ScoreStageRank(path);
            if (rank < 2) continue;

            var key = $"{entry.Method}|{entry.Url}";
            if (!seen.Add(key)) continue;

            candidates.Add(new WorkflowCandidate
            {
                Url = entry.Url,
                Method = entry.Method.ToUpperInvariant(),
                BodyTemplate = entry.RequestBody,
                Headers = CopyHeaders(entry.RequestHeaders),
                StageRank = rank,
                PathPrefix = GetPathPrefix(uri, 3),
                Source = "network-late-stage"
            });
        }

        var grouped = candidates
            .GroupBy(c => c.PathPrefix, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() >= 1)
            .SelectMany(g => g.OrderByDescending(c => c.StageRank).Take(1))
            .OrderByDescending(c => c.StageRank)
            .ThenBy(c => c.Url)
            .Take(maxCandidates)
            .ToList();

        if (grouped.Count > 0) return grouped;

        return candidates
            .OrderByDescending(c => c.StageRank)
            .Take(maxCandidates)
            .ToList();
    }

    public static bool TryExtractCaptchaCredentials(string body, out object? captchaId, out object? answer)
    {
        captchaId = null;
        answer = null;
        try
        {
            var node = JsonNode.Parse(body);
            if (node is not JsonObject obj) return false;

            captchaId = CaptchaIdKeys.Select(k => obj[k]).FirstOrDefault(v => v != null);
            answer = CaptchaAnswerKeys.Select(k => obj[k]).FirstOrDefault(v => v != null);
            return captchaId != null && answer != null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public static JsonObject BuildCaptchaSubmitBody(
        object captchaId,
        object answer,
        string? templateBody,
        string commentSuffix)
    {
        if (!string.IsNullOrEmpty(templateBody))
        {
            try
            {
                var node = JsonNode.Parse(templateBody);
                if (node is JsonObject obj)
                {
                    foreach (var key in CaptchaIdKeys)
                        if (obj.ContainsKey(key)) obj[key] = JsonValue.Create(captchaId);
                    foreach (var key in CaptchaAnswerKeys)
                        if (obj.ContainsKey(key)) obj[key] = JsonValue.Create(answer);
                    if (obj.ContainsKey("comment")) obj["comment"] = $"trowser-captcha-{commentSuffix}";
                    else if (obj.ContainsKey("message")) obj["message"] = $"trowser-captcha-{commentSuffix}";
                    return obj;
                }
            }
            catch (JsonException) { }
        }

        return new JsonObject
        {
            ["captchaId"] = JsonValue.Create(captchaId),
            ["captcha"] = JsonValue.Create(answer),
            ["comment"] = $"trowser-captcha-{commentSuffix}"
        };
    }

    public static string NormalizeRaceBody(string? templateBody, int index)
    {
        if (string.IsNullOrWhiteSpace(templateBody))
            return JsonSerializer.Serialize(new { canary = $"trowser-race-{index}" });

        try
        {
            var node = JsonNode.Parse(templateBody);
            if (node is JsonObject obj)
            {
                foreach (var key in new[] { "comment", "message", "note", "text", "description", "idempotencyKey", "requestId" })
                {
                    if (obj.ContainsKey(key))
                        obj[key] = $"trowser-race-{index}";
                }
                return obj.ToJsonString();
            }
        }
        catch (JsonException) { }

        return templateBody;
    }

    public static bool IsSuccessStatus(int status) => status is >= 200 and < 300;

    public static bool LooksLikeWorkflowSkipAccepted(int status, string body)
    {
        if (!IsSuccessStatus(status)) return false;
        if (string.IsNullOrWhiteSpace(body)) return false;

        var lower = body.ToLowerInvariant();
        string[] rejectHints =
        [
            "validation", "required", "missing", "invalid", "forbidden", "unauthorized",
            "not allowed", "must complete", "previous step", "prerequisite", "denied"
        ];
        return !rejectHints.Any(h => lower.Contains(h, StringComparison.Ordinal));
    }

    public static bool LooksLikeProperRejection(int status, string body)
    {
        if (InsecureDesignProbeSupport.LooksLikeCsrfRejection(status, body))
            return true;

        if (status is 401 or 403 or 409 or 422) return true;
        if (status == 400 && !string.IsNullOrEmpty(body))
        {
            var lower = body.ToLowerInvariant();
            return lower.Contains("required", StringComparison.Ordinal)
                   || lower.Contains("missing", StringComparison.Ordinal)
                   || lower.Contains("invalid", StringComparison.Ordinal)
                   || lower.Contains("forbidden", StringComparison.Ordinal);
        }
        return false;
    }

    public static bool EndpointTemplateHadCsrf(string? bodyTemplate) =>
        !string.IsNullOrEmpty(bodyTemplate)
        && CsrfTokenHeuristics.TryExtractFromBody(bodyTemplate, out _);

    public static PostTarget? BuildExplicitPostTarget(AutomationContext ctx, string origin, string urlOrPath)
    {
        var abs = ToAbsolute(origin, urlOrPath);
        if (abs == null) return null;

        NetworkEntry? networkMatch = null;
        for (var i = ctx.Network.Entries.Count - 1; i >= 0; i--)
        {
            var entry = ctx.Network.Entries[i];
            if (entry.Method is not ("POST" or "PUT" or "PATCH")) continue;
            if (!UrlPathMatches(entry.Url, abs)) continue;
            networkMatch = entry;
            break;
        }

        if (networkMatch != null)
            return BuildTargetFromEntry(networkMatch, "explicit-url");

        return new PostTarget
        {
            Url = abs,
            Method = "POST",
            BodyTemplate = null,
            Headers = FormUrlEncodedHeaders(),
            Source = "explicit",
            MatchReason = "explicit-url"
        };
    }

    internal static int ScoreStageRank(string path)
    {
        var lower = path.ToLowerInvariant();
        var rank = 0;
        foreach (var s in LateStagePathSegments)
            if (PathContainsSegment(lower, s)) rank += 2;
        foreach (var s in EarlyStagePathSegments)
            if (PathContainsSegment(lower, s)) rank -= 1;
        return rank;
    }

    private static PostTarget BuildTargetFromEntry(NetworkEntry entry, string reason)
    {
        var headers = CopyHeaders(entry.RequestHeaders);
        var ct = headers.TryGetValue("Content-Type", out var c) ? c : "";
        if (string.IsNullOrEmpty(ct) && !string.IsNullOrEmpty(entry.RequestBody))
        {
            headers["Content-Type"] = entry.RequestBody.TrimStart().StartsWith('{')
                ? "application/json"
                : "application/x-www-form-urlencoded";
        }

        return new PostTarget
        {
            Url = entry.Url,
            Method = entry.Method.ToUpperInvariant(),
            BodyTemplate = entry.RequestBody ?? "{}",
            Headers = headers,
            Source = "network",
            MatchReason = reason
        };
    }

    private static Dictionary<string, string> JsonHeaders() =>
        new(StringComparer.OrdinalIgnoreCase) { ["Content-Type"] = "application/json" };

    private static Dictionary<string, string> FormUrlEncodedHeaders() =>
        new(StringComparer.OrdinalIgnoreCase) { ["Content-Type"] = "application/x-www-form-urlencoded" };

    private static bool UrlPathMatches(string entryUrl, string targetUrl)
    {
        if (string.Equals(entryUrl, targetUrl, StringComparison.OrdinalIgnoreCase))
            return true;
        if (!Uri.TryCreate(entryUrl, UriKind.Absolute, out var entryUri)
            || !Uri.TryCreate(targetUrl, UriKind.Absolute, out var targetUri))
            return false;
        return string.Equals(entryUri.AbsolutePath, targetUri.AbsolutePath, StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, string> CopyHeaders(Dictionary<string, string> source)
    {
        var copy = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in source)
        {
            if (kv.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
            copy[kv.Key] = kv.Value;
        }
        return copy;
    }

    private static string? ToAbsolute(string origin, string urlOrPath)
    {
        if (Uri.TryCreate(urlOrPath, UriKind.Absolute, out var abs)) return abs.ToString();
        if (urlOrPath.StartsWith('/'))
            return origin.TrimEnd('/') + urlOrPath;
        return null;
    }

    private static bool PathContainsSegment(string path, string segment) =>
        path.Contains($"/{segment}", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith($"/{segment}", StringComparison.OrdinalIgnoreCase);

    private static bool BodyContainsField(string body, string fieldName)
    {
        if (body.Contains($"\"{fieldName}\"", StringComparison.OrdinalIgnoreCase)) return true;
        if (body.Contains($"'{fieldName}'", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static string GetPathPrefix(Uri uri, int segmentCount)
    {
        var parts = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return "/";
        var take = Math.Min(segmentCount, parts.Length);
        return "/" + string.Join("/", parts.Take(take));
    }
}
