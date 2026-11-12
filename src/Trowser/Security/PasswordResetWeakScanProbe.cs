using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Weak password-reset via security questions — requires explicit success markers (not bare ""reset"" text).
/// Inspired by OWASP WSTG password-reset testing; also influenced by pentest-ai <c>web.password_reset_weak</c>.
/// Destructive reset only when <c>ConfirmDestructive</c> is true.
/// </summary>
public sealed class PasswordResetWeakScanProbe
{
    private readonly AutomationContext _ctx;

    public PasswordResetWeakScanProbe(AutomationContext context) => _ctx = context;

    public sealed class ScanOptions
    {
        public string? Email { get; set; }
        public string? ResetUrl { get; set; }
        public string? QuestionUrl { get; set; }
        public string NewPassword { get; set; } = "TrowserReset1!";
        public int TimeoutMs { get; set; } = 15000;
        public int MaxAttempts { get; set; } = 12;
        public bool ConfirmDestructive { get; set; }
        public bool RegisterChainFindings { get; set; } = true;
    }

    public sealed class ScanFinding
    {
        public string Category { get; init; } = "password-reset-weak";
        public string Severity { get; init; } = "critical";
        public string QuestionUrl { get; init; } = "";
        public string ResetUrl { get; init; } = "";
        public string Question { get; init; } = "";
        public string AnswerTried { get; init; } = "";
        public int Status { get; init; }
        public string Detail { get; init; } = "";
    }

    public sealed class ScanResult
    {
        public string Message { get; init; } = "";
        public int ElapsedMs { get; init; }
        public List<ScanFinding> Findings { get; init; } = [];
        public List<string> AttemptedAnswers { get; init; } = [];
        public string? QuestionText { get; init; }
        public string EmailUsed { get; init; } = "";
    }

    public async Task<ScanResult> RunAsync(ScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running password-reset-weak-scan.");

        var email = options.Email
                    ?? AuthProbeDiscovery.ExtractEmailFromNetwork(_ctx)
                    ?? AuthAccessHeuristics.DefaultEmailForHost(pageUri);
        var questionUrls = ResolveQuestionUrls(pageUri, options.QuestionUrl);
        var resetUrls = ResolveResetUrls(pageUri, options.ResetUrl);

        string? questionText = null;
        string? questionUrlUsed = null;

        foreach (var qUrl in questionUrls)
        {
            ct.ThrowIfCancellationRequested();
            var url = qUrl.Contains('?')
                ? qUrl
                : $"{qUrl}?email={Uri.EscapeDataString(email)}";
            var resp = await SecurityProbeHttp.FetchAsync(_ctx, url, "GET", null, null, options.TimeoutMs, true, ct);
            if (resp.Status is not (>= 200 and < 300) || string.IsNullOrWhiteSpace(resp.Body)) continue;
            questionText = ExtractQuestion(resp.Body);
            if (!string.IsNullOrWhiteSpace(questionText))
            {
                questionUrlUsed = url;
                break;
            }
        }

        if (string.IsNullOrWhiteSpace(questionText))
        {
            return new ScanResult
            {
                Message = "No security question endpoint returned a question. Browse forgot-password flow first or pass questionUrl.",
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                EmailUsed = email
            };
        }

        var answers = BuildAnswerCandidates(questionText).Take(options.MaxAttempts).ToList();
        var attempted = new List<string>();
        var resetUrl = resetUrls.FirstOrDefault() ?? questionUrlUsed?.Replace("security-question", "reset-password", StringComparison.OrdinalIgnoreCase)
                       ?? pageUri.GetLeftPart(UriPartial.Authority) + "/rest/user/reset-password";

        foreach (var answer in answers)
        {
            ct.ThrowIfCancellationRequested();
            attempted.Add(answer);
            if (!options.ConfirmDestructive) continue;

            var body = JsonSerializer.Serialize(new
            {
                email,
                answer,
                newPassword = options.NewPassword,
                repeatPassword = options.NewPassword
            });

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/json"
            };

            var reset = await SecurityProbeHttp.FetchAsync(
                _ctx, resetUrl, "POST", headers, body, options.TimeoutMs, true, ct);

            if (!LooksLikeResetSuccess(reset)) continue;

            var finding = new ScanFinding
            {
                QuestionUrl = questionUrlUsed ?? "",
                ResetUrl = resetUrl,
                Question = questionText,
                AnswerTried = answer,
                Status = reset.Status,
                Detail = $"Password reset accepted with canonical answer '{answer}' for question: {questionText}"
            };

            if (options.RegisterChainFindings)
            {
                AuthProbeDiscovery.RegisterChainFinding(_ctx, finding.Category, finding.Severity,
                    finding.Detail, resetUrl, "POST", finding.Detail);
            }

            return new ScanResult
            {
                Message = "Weak security-question reset — password change accepted.",
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                Findings = [finding],
                AttemptedAnswers = attempted,
                QuestionText = questionText,
                EmailUsed = email
            };
        }

        if (!options.ConfirmDestructive)
        {
            return new ScanResult
            {
                Message = "Security question fetched. Set confirmDestructive: true to attempt password reset with canonical answers.",
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                AttemptedAnswers = attempted,
                QuestionText = questionText,
                EmailUsed = email
            };
        }

        return new ScanResult
        {
            Message = $"Tried {attempted.Count} canonical answer(s); reset not accepted.",
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            AttemptedAnswers = attempted,
            QuestionText = questionText,
            EmailUsed = email
        };
    }

    private List<string> ResolveQuestionUrls(Uri pageUri, string? explicitUrl)
    {
        if (!string.IsNullOrWhiteSpace(explicitUrl))
        {
            var url = explicitUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? explicitUrl
                : pageUri.GetLeftPart(UriPartial.Authority) + (explicitUrl.StartsWith('/') ? explicitUrl : "/" + explicitUrl);
            return [url];
        }

        return AuthProbeDiscovery.DiscoverPaths(
            _ctx, pageUri, AuthProbeDiscovery.SecurityQuestionPathHints,
            AuthProbeDiscovery.LooksLikeResetPath, 6);
    }

    private List<string> ResolveResetUrls(Uri pageUri, string? explicitUrl)
    {
        if (!string.IsNullOrWhiteSpace(explicitUrl))
        {
            var url = explicitUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? explicitUrl
                : pageUri.GetLeftPart(UriPartial.Authority) + (explicitUrl.StartsWith('/') ? explicitUrl : "/" + explicitUrl);
            return [url];
        }

        return AuthProbeDiscovery.DiscoverPaths(
            _ctx, pageUri, AuthProbeDiscovery.ResetPathHints,
            p => AuthProbeDiscovery.LooksLikeResetPath(p) && !p.Contains("question", StringComparison.OrdinalIgnoreCase), 4);
    }

    private static string? ExtractQuestion(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            foreach (var name in new[] { "question", "securityQuestion", "security_question", "hint" })
            {
                if (doc.RootElement.TryGetProperty(name, out var q) && q.ValueKind == JsonValueKind.String)
                {
                    var text = q.GetString();
                    if (!string.IsNullOrWhiteSpace(text)) return text;
                }
            }
        }
        catch (JsonException) { }

        var m = Regex.Match(body, @"""question""\s*:\s*""([^""]+)""", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : null;
    }

    private static IEnumerable<string> BuildAnswerCandidates(string question)
    {
        var lower = question.ToLowerInvariant();
        var answers = new List<string>();
        foreach (var (needle, canonical) in AuthProbeDiscovery.CanonicalSecurityAnswers)
        {
            if (!lower.Contains(needle, StringComparison.Ordinal)) continue;
            answers.AddRange(canonical);
        }

        if (answers.Count == 0)
            answers.AddRange(AuthProbeDiscovery.CanonicalSecurityAnswers.SelectMany(x => x.Answers));

        return answers.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static readonly string[] ResetSuccessMarkers =
    [
        "password has been reset",
        "successfully changed",
        "password updated",
        "password successfully",
        "reset successful",
        "password change successful",
        "\"success\":true",
        "\"success\": true",
        "\"ok\":true",
        "\"ok\": true",
    ];

    private static bool LooksLikeResetSuccess(SecurityProbeHttp.FetchResult reset)
    {
        if (reset.Status is not (>= 200 and < 300)) return false;
        var body = (reset.Body ?? "").ToLowerInvariant();
        if (body.Contains("invalid") || body.Contains("incorrect") || body.Contains("failed")) return false;
        // Require clear success markers — bare "reset" / empty 204 are too loose.
        return ResetSuccessMarkers.Any(m => body.Contains(m, StringComparison.Ordinal));
    }
}
