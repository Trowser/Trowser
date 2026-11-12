using System.IO;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security.SupplyChain;

/// <summary>
/// Probes for exposed CI/CD pipeline configuration files and runs heuristic security analysis.
/// </summary>
public static class CiCdExposureChecker
{
    public static readonly string[] DefaultCiCdPaths =
    [
        "/.github/workflows/ci.yml",
        "/.github/workflows/main.yml",
        "/.github/workflows/build.yml",
        "/.github/workflows/deploy.yml",
        "/.github/workflows/release.yml",
        "/.github/workflows/test.yml",
        "/.github/workflows/publish.yml",
        "/.gitlab-ci.yml",
        "/Jenkinsfile",
        "/azure-pipelines.yml",
        "/.circleci/config.yml",
        "/.travis.yml",
        "/bitbucket-pipelines.yml",
        "/buildspec.yml",
        "/.drone.yml",
        "/.woodpecker.yml",
        "/teamcity-settings.xml",
    ];

    public static async Task<List<ExposedCiCdFile>> FetchAsync(
        AutomationContext ctx,
        string pageUrl,
        IReadOnlyList<string>? extraPaths,
        int timeoutMs,
        bool includeBrowserCookies = true,
        CancellationToken ct = default)
    {
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before probing CI/CD paths.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in DefaultCiCdPaths) paths.Add(p);
        if (extraPaths != null)
            foreach (var p in extraPaths) paths.Add(p);

        var results = new List<ExposedCiCdFile>();
        var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in paths)
        {
            ct.ThrowIfCancellationRequested();
            var url = origin + (path.StartsWith('/') ? path : "/" + path);
            if (!seenUrls.Add(url)) continue;

            var fetch = await SecurityProbeHttp.FetchAsync(
                ctx, url, "GET", null, null, timeoutMs, includeBrowserCookies, ct);
            if (fetch.Status != 200 || string.IsNullOrWhiteSpace(fetch.Body)) continue;
            if (!LooksLikeCiCdBody(fetch.Body, path)) continue;

            var fileName = Path.GetFileName(path.TrimEnd('/'));
            if (string.IsNullOrEmpty(fileName)) fileName = path.Split('/').LastOrDefault(s => s.Length > 0) ?? "config.yml";
            var platform = ResolvePlatform(path, fetch.Body);
            var issues = CiCdContentAnalyzer.Analyze(fetch.Body, platform);

            results.Add(new ExposedCiCdFile
            {
                Url = url,
                Path = path,
                FileName = fileName,
                Platform = platform,
                ByteLength = fetch.Body.Length,
                Issues = issues
            });
        }

        return results;
    }

    public static async Task<int> ProbePathCountAsync(
        AutomationContext ctx, string pageUrl, int timeoutMs, bool includeBrowserCookies = true, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri)) return 0;
        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var count = 0;
        foreach (var path in DefaultCiCdPaths.Take(10))
        {
            ct.ThrowIfCancellationRequested();
            var url = origin + path;
            var fetch = await SecurityProbeHttp.FetchAsync(
                ctx, url, "GET", null, null, timeoutMs, includeBrowserCookies, ct);
            if (fetch.Status == 200 && LooksLikeCiCdBody(fetch.Body, path))
                count++;
        }
        return count;
    }

    private static bool LooksLikeCiCdBody(string body, string path)
    {
        if (string.IsNullOrWhiteSpace(body) || body.Length < 12) return false;
        var lower = body.ToLowerInvariant();
        var pathLower = path.ToLowerInvariant();

        if (pathLower.Contains("jenkinsfile"))
            return lower.Contains("pipeline") || lower.Contains("node(") || lower.Contains("stage(");

        if (pathLower.Contains("gitlab-ci"))
            return lower.Contains("stages:") || lower.Contains("script:") || lower.Contains("image:");

        if (pathLower.Contains("azure-pipelines") || pathLower.Contains("travis")
            || pathLower.Contains("circleci") || pathLower.Contains("bitbucket-pipelines")
            || pathLower.Contains("buildspec") || pathLower.Contains("drone")
            || pathLower.Contains("woodpecker"))
            return lower.Contains("steps:") || lower.Contains("script:") || lower.Contains("jobs:")
                   || lower.Contains("pipeline:") || lower.Contains("stages:");

        if (pathLower.Contains("workflows") || pathLower.Contains(".github"))
            return lower.Contains("on:") && (lower.Contains("jobs:") || lower.Contains("steps:"));

        return lower.Contains("jobs:") || lower.Contains("stages:") || lower.Contains("pipeline:")
               || lower.Contains("steps:") || lower.Contains("script:");
    }

    internal static string ResolvePlatform(string path, string body)
    {
        var p = path.ToLowerInvariant();
        if (p.Contains(".github/workflows")) return "github-actions";
        if (p.Contains("gitlab-ci")) return "gitlab-ci";
        if (p.Contains("jenkinsfile") || p.Contains("/jenkins")) return "jenkins";
        if (p.Contains("azure-pipelines")) return "azure-pipelines";
        if (p.Contains("circleci")) return "circleci";
        if (p.Contains("travis")) return "travis-ci";
        if (p.Contains("bitbucket-pipelines")) return "bitbucket-pipelines";
        if (p.Contains("buildspec")) return "aws-codebuild";
        if (p.Contains("drone")) return "drone";
        if (p.Contains("woodpecker")) return "woodpecker";
        if (p.Contains("teamcity")) return "teamcity";

        var lower = body.ToLowerInvariant();
        if (lower.Contains("on:") && lower.Contains("jobs:")) return "github-actions";
        if (lower.Contains("stages:") && lower.Contains("script:")) return "gitlab-ci";
        return "ci-cd";
    }
}

/// <summary>
/// Heuristic analysis of CI/CD configuration content.
/// </summary>
public static class CiCdContentAnalyzer
{
    private static readonly Regex AwsKey = new(@"AKIA[0-9A-Z]{16}", RegexOptions.Compiled);
    private static readonly Regex GitHubPat = new(@"ghp_[a-zA-Z0-9]{20,}", RegexOptions.Compiled);
    private static readonly Regex GitLabPat = new(@"glpat-[a-zA-Z0-9\-_]{20,}", RegexOptions.Compiled);
    private static readonly Regex StripeKey = new(@"sk_live_[a-zA-Z0-9]{16,}", RegexOptions.Compiled);
    private static readonly Regex SlackToken = new(@"xox[baprs]-[a-zA-Z0-9\-]{10,}", RegexOptions.Compiled);
    private static readonly Regex PrivateKeyBlock = new(@"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", RegexOptions.Compiled);
    private static readonly Regex InlineSecret = new(
        @"(?i)(?:password|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['""]?([a-zA-Z0-9_\-/+=]{12,})['""]?",
        RegexOptions.Compiled);
    private static readonly Regex UnpinnedAction = new(
        @"uses\s*:\s*[\w.\-/]+/[\w.\-/]+@(main|master|latest)\s*$",
        RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex PipeToShell = new(
        @"(?:curl|wget)\s+[^\n|]+\|\s*(?:ba)?sh",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex PullRequestTarget = new(
        @"pull_request_target\s*:",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static List<CiCdIssue> Analyze(string content, string platform)
    {
        var issues = new List<CiCdIssue>();
        var lines = content.Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var lineNum = i + 1;
            if (IsLikelyPlaceholder(line)) continue;

            if (AwsKey.IsMatch(line))
                AddIssue(issues, "hardcoded-secret", "critical", "AWS access key ID embedded in pipeline config", lineNum);
            if (GitHubPat.IsMatch(line))
                AddIssue(issues, "hardcoded-secret", "critical", "GitHub personal access token embedded in pipeline config", lineNum);
            if (GitLabPat.IsMatch(line))
                AddIssue(issues, "hardcoded-secret", "critical", "GitLab personal access token embedded in pipeline config", lineNum);
            if (StripeKey.IsMatch(line))
                AddIssue(issues, "hardcoded-secret", "critical", "Stripe live secret key embedded in pipeline config", lineNum);
            if (SlackToken.IsMatch(line))
                AddIssue(issues, "hardcoded-secret", "high", "Slack token embedded in pipeline config", lineNum);
            if (PrivateKeyBlock.IsMatch(line))
                AddIssue(issues, "hardcoded-secret", "critical", "Private key block embedded in pipeline config", lineNum);

            var secretMatch = InlineSecret.Match(line);
            if (secretMatch.Success && !IsSecretReference(line))
                AddIssue(issues, "hardcoded-secret", "high",
                    $"Inline credential assignment ({secretMatch.Groups[1].Value[..Math.Min(8, secretMatch.Groups[1].Value.Length)]}…)", lineNum);
        }

        if (platform == "github-actions")
        {
            foreach (Match m in UnpinnedAction.Matches(content))
                AddIssue(issues, "unpinned-action", "medium",
                    $"GitHub Action pinned to floating ref @{m.Groups[1].Value}", LineNumberForOffset(content, m.Index));

            if (PullRequestTarget.IsMatch(content))
            {
                var hasCheckout = content.Contains("actions/checkout", StringComparison.OrdinalIgnoreCase);
                var hasDeploy = content.Contains("deploy", StringComparison.OrdinalIgnoreCase)
                                || content.Contains("kubectl", StringComparison.OrdinalIgnoreCase)
                                || content.Contains("docker push", StringComparison.OrdinalIgnoreCase);
                if (hasCheckout || hasDeploy)
                    AddIssue(issues, "pull_request_target", "high",
                        "pull_request_target workflow with checkout or deploy steps — review for untrusted fork PR abuse", null);
            }
        }

        foreach (Match m in PipeToShell.Matches(content))
            AddIssue(issues, "pipe-to-shell", "high",
                "Remote script fetched and piped to shell", LineNumberForOffset(content, m.Index));

        return DedupeIssues(issues);
    }

    private static bool IsLikelyPlaceholder(string line)
    {
        if (line.Contains("${{", StringComparison.Ordinal)) return true;
        if (line.Contains("$CI_", StringComparison.Ordinal)) return true;
        if (line.Contains("secrets.", StringComparison.OrdinalIgnoreCase)) return true;
        if (line.Contains("changeme", StringComparison.OrdinalIgnoreCase)) return true;
        if (line.Contains("example", StringComparison.OrdinalIgnoreCase) && line.Contains("key", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static bool IsSecretReference(string line) =>
        line.Contains("${{", StringComparison.Ordinal)
        || line.Contains("secrets.", StringComparison.OrdinalIgnoreCase)
        || line.Contains("$CI_", StringComparison.Ordinal)
        || line.Contains("env.", StringComparison.OrdinalIgnoreCase);

    private static int? LineNumberForOffset(string content, int offset)
    {
        if (offset < 0 || offset >= content.Length) return null;
        return content[..offset].Count(c => c == '\n') + 1;
    }

    private static void AddIssue(List<CiCdIssue> issues, string category, string severity, string description, int? lineNumber)
    {
        issues.Add(new CiCdIssue
        {
            Category = category,
            Severity = severity,
            Description = description,
            LineNumber = lineNumber
        });
    }

    private static List<CiCdIssue> DedupeIssues(List<CiCdIssue> issues) =>
        issues
            .GroupBy(i => $"{i.Category}|{i.Description}|{i.LineNumber}")
            .Select(g => g.First())
            .OrderByDescending(i => i.Severity switch { "critical" => 3, "high" => 2, "medium" => 1, _ => 0 })
            .ToList();
}
