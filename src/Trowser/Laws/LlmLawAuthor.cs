using System.Text;
using System.Text.RegularExpressions;
using Trowser.Chat;

namespace Trowser.Laws;

/// <summary>
/// Turns natural language into Law source, compiles, and dry-runs via <see cref="LawLoader"/>.
/// </summary>
public sealed class LlmLawAuthor
{
    private const int MaxRefineAttempts = 4;

    private static readonly string SystemPrompt = """
        You write Trowser Law files: small C# scripts (.csx) that declare invariants with a fluent API.
        Laws are read-only checks — no navigation, clicks, Fetch, or mutating APIs.

        Allowed surface:
        - Site("host-or-pattern") optional host filter for following Laws
        - Law("name").OnPage("/path*") with PageFacts: p.Url, p.Path, p.Host, p.Title, p.Text("css"), p.Texts("css") (list), p.Value("input-css"),
          p.Exists, p.Visible, p.Count, p.Attr("sel","attr"), p.Number("css") (parsed price/number, NaN when missing), p.Numbers("css")
        - Numbers: a.ApproxEquals(b, 0.01) or total.ApproxEquals(p.Numbers(".line"), 0.01) (sum) — never compare money with ==
        - Law("name").OnResponse("GET /api/*") with ResponseFacts: r.Status, r.Method, r.Url, r.ContentType, r.Body, r.Header("name"), r.Cookie("name"),
          r.Json.IsValid, r.Json.String("a.b"), r.Json.Number("items[0].price"), r.Json.HasValue("field"), r.Json.Count("items"), r.Json.Numbers("items", "price")
        - Law("name").OnConsole("error") with ConsoleFacts: c.Level, c.Message
        - .OnAction() / .OnTimer() also use PageFacts but run only in Shadow Heavy (explicit check, after scripts, serendipity timer) — use for slower or flow-dependent page checks
        - Always type lambda parameters: (PageFacts p), (ResponseFacts r), (ConsoleFacts c) — never untyped p => or c =>
        - .When(...) optional guard (use it to scope: only 2xx responses, only when an element exists); .Expect(...) required for pass; .Forbid(...) fails when true
        - .Severity(Severity.Info|Low|Medium|High|Critical), .Tags("a","b"), .Confirm() (re-check after a short delay to avoid flaky mid-render failures), .Cost(LawCostClass.Heavy)
        - Path patterns like /cart match that path only (not substrings of the full URL). Use * for globs.
        - Regex is allowed (System.Text.RegularExpressions); pass a timeout: new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100))
        - Do NOT include await CheckLaws() or await AssertLaws() — those are Script Console runners only, not saved Law files.

        Output ONLY valid C# Law source. Prefer a ```csharp fenced block or raw code with Law( calls.
        Code runs in an allowlist sandbox: LINQ, collections, strings, math, Regex, JSON and the Law facts only.
        Do not use classes, namespaces, reflection, Task.Run, GetType(), or I/O APIs (File, Process, HttpClient, etc.) — they are rejected.
        """;

    private readonly LawLoader _loader;
    private readonly Func<LlmClient?>? _clientFactory;

    public LlmLawAuthor(LawLoader loader, Func<LlmClient?>? clientFactory = null)
    {
        _loader = loader;
        _clientFactory = clientFactory;
    }

    public Task<(bool ok, string code, IReadOnlyList<string> errors)> AuthorAsync(
        string naturalLanguage,
        CancellationToken ct = default) =>
        GenerateAndRefineAsync(
            $"Write a Trowser Law (or small Law file) for this invariant:\n\n{naturalLanguage.Trim()}",
            fallbackTemplate: BuildTemplateFromDescription(naturalLanguage),
            ct);

    public Task<(bool ok, string code, IReadOnlyList<string> errors)> RefineMinedProposalAsync(
        string code,
        string? observationNotes,
        CancellationToken ct = default)
    {
        var prompt = new StringBuilder();
        prompt.AppendLine("Improve this mined Law candidate. Keep it read-only and compilable.");
        if (!string.IsNullOrWhiteSpace(observationNotes))
            prompt.AppendLine(observationNotes.Trim());
        prompt.AppendLine();
        prompt.AppendLine("Current code:");
        prompt.AppendLine(code.Trim());
        return GenerateAndRefineAsync(prompt.ToString(), fallbackTemplate: code, ct);
    }

    public Task<(bool ok, string code, IReadOnlyList<string> errors)> ProposeFromContextAsync(
        string contextDescription,
        CancellationToken ct = default) =>
        AuthorAsync(contextDescription, ct);

    public async Task<(bool ok, string? explanation, string? error)> ExplainViolationAsync(
        string lawName,
        string failureDetail,
        CancellationToken ct = default)
    {
        var client = _clientFactory?.Invoke();
        if (client == null)
            return (false, null, "LLM not available for Law explanations.");

        var user = $"""
            Law name: {lawName}
            Failure: {failureDetail}

            In 2–4 sentences, explain what this Law checks, why it failed, and one concrete fix (page or Law edit).
            Plain text only.
            """;
        var (ok, text, error) = await client.CompleteTextAsync(SystemPrompt, user, ct);
        return ok ? (true, text?.Trim(), null) : (false, null, error);
    }

    public async Task<(bool ok, string code, IReadOnlyList<string> errors)> RefineAsync(
        string code,
        CancellationToken ct = default)
    {
        var (ok, errors) = await _loader.ValidateAsync(code, ct);
        return (ok, code, errors);
    }

    private async Task<(bool ok, string code, IReadOnlyList<string> errors)> GenerateAndRefineAsync(
        string userPrompt,
        string fallbackTemplate,
        CancellationToken ct)
    {
        var code = fallbackTemplate;
        var client = _clientFactory?.Invoke();
        if (client != null)
        {
            var (genOk, text, genErr) = await client.CompleteTextAsync(SystemPrompt, userPrompt, ct);
            if (genOk && !string.IsNullOrWhiteSpace(text))
                code = ExtractCode(text) ?? code;
            else if (!genOk && !string.IsNullOrWhiteSpace(genErr))
                return (false, code, new[] { genErr });
        }

        return await RefineLoopAsync(code, client, ct);
    }

    private async Task<(bool ok, string code, IReadOnlyList<string> errors)> RefineLoopAsync(
        string code,
        LlmClient? client,
        CancellationToken ct)
    {
        IReadOnlyList<string> errors = Array.Empty<string>();
        for (var attempt = 0; attempt < MaxRefineAttempts; attempt++)
        {
            var (ok, compileErrors) = await _loader.ValidateAsync(code, ct);
            if (ok)
                return (true, LawCodeGenerator.StripConsoleRunnerLines(code), compileErrors);

            errors = compileErrors;
            if (client == null || attempt == MaxRefineAttempts - 1)
                break;

            var fixPrompt = new StringBuilder();
            fixPrompt.AppendLine("Fix the Law C# so it compiles. Return the full corrected file.");
            fixPrompt.AppendLine();
            fixPrompt.AppendLine("Compile errors:");
            foreach (var e in compileErrors)
                fixPrompt.AppendLine("- " + e);
            fixPrompt.AppendLine();
            fixPrompt.AppendLine("Code:");
            fixPrompt.AppendLine(code);

            var (fixOk, text, _) = await client.CompleteTextAsync(SystemPrompt, fixPrompt.ToString(), ct);
            if (!fixOk || string.IsNullOrWhiteSpace(text))
                break;
            code = ExtractCode(text) ?? code;
        }

        return (false, code, errors);
    }

    private static string BuildTemplateFromDescription(string naturalLanguage)
    {
        var snippet = naturalLanguage.Trim().Replace("\"", "\\\"");
        var title = snippet.Length > 60 ? snippet[..60] : snippet;
        return $$"""
            // Generated from description (LLM unavailable or failed)
            Law("{{title}}")
                .OnPage("*")
                .Expect(p => !string.IsNullOrWhiteSpace(p.Title) /* TODO: {{snippet}} */);
            """;
    }

    private static string? ExtractCode(string response)
    {
        var fenced = Regex.Match(response, @"```(?:csharp|cs|csx)?\s*([\s\S]*?)```", RegexOptions.IgnoreCase);
        if (fenced.Success)
            return fenced.Groups[1].Value.Trim();

        var idx = response.IndexOf("Law(", StringComparison.Ordinal);
        return idx >= 0 ? response[idx..].Trim() : response.Trim();
    }
}
