using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Chat;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.ResourceUsage;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.Laws;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class McpHandler
{
private Task<object> ToolSecuritySsrfScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySsrfScanAsync);

private Task<object> ToolSecuritySsrfOrchestrator(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySsrfOrchestratorAsync);

private Task<object> ToolSecurityOpenRedirectScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityOpenRedirectScanAsync);

private Task<object> ToolSecurityCacheDeceptionScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCacheDeceptionScanAsync);

private Task<object> ToolSecurityCacheMap(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCacheMapAsync);

private Task<object> ToolSecurityCachePollutionScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCachePollutionScanAsync);

private Task<object> ToolSecurityCachePoisonScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCachePoisonScanAsync);

// Security Shadow and OOB callback detection stay per-surface: both are stateful, action/mode-based,
// and the MCP variants fold in the REST GET/clear endpoints with their own text rendering.

private Task<object> ToolSecurityShadow(JsonElement args)
    {
        var shadow = _context.SecurityShadow;
        if (shadow == null)
            return Task.FromResult(ErrorContent("Shadow not initialized."));

        var action = GetString(args, "action");

        // Clear findings
        if (action == "clear")
        {
            var category = GetString(args, "category");
            shadow.ClearFindings(category);
            return Task.FromResult(TextContent(category != null
                ? $"Cleared {category} findings."
                : "All Shadow findings cleared."));
        }

        // Enable/disable
        if (args.TryGetProperty("enabled", out var enabledProp))
        {
            var enabled = enabledProp.GetBoolean();

            HashSet<string>? audits = null;
            if (args.TryGetProperty("audits", out var auditsEl) && auditsEl.ValueKind == JsonValueKind.Array)
                audits = auditsEl.EnumerateArray()
                    .Where(a => a.ValueKind == JsonValueKind.String)
                    .Select(a => a.GetString()!)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

            shadow.Configure(
                enabled,
                audits,
                GetString(args, "scope"),
                GetBoolOrNull(args, "suggestions"),
                null,
                null
            );

            if (args.TryGetProperty("laws", out var lawsProp))
                shadow.Config.LawsEnabled = lawsProp.GetBoolean();
            if (args.TryGetProperty("runHeavyAfterQuicktest", out var rhProp))
                shadow.Config.RunHeavyAfterQuicktest = rhProp.GetBoolean();
            if (args.TryGetProperty("lawsMining", out var lmProp))
                shadow.Config.LawsMiningEnabled = lmProp.GetBoolean();
            if (args.TryGetProperty("serendipityTimer", out var stProp))
            {
                shadow.Config.SerendipityTimerEnabled = stProp.GetBoolean();
                _context.Laws?.ConfigureSerendipityTimer(
                    shadow.Config.SerendipityTimerEnabled,
                    shadow.Config.SerendipityIntervalSeconds,
                    shadow.Config.SerendipityRandomize);
            }
            if (args.TryGetProperty("serendipityIntervalSeconds", out var siProp) && siProp.TryGetInt32(out var si))
                shadow.Config.SerendipityIntervalSeconds = si;
            if (args.TryGetProperty("disabledLaws", out var dlEl) && dlEl.ValueKind == JsonValueKind.Array)
            {
                shadow.Config.DisabledLaws = dlEl.EnumerateArray()
                    .Where(a => a.ValueKind == JsonValueKind.String)
                    .Select(a => a.GetString()!)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
            }
            if (args.TryGetProperty("activeLawSources", out var alsEl))
            {
                shadow.Config.ActiveLawSources = alsEl.ValueKind == JsonValueKind.Null
                    ? null
                    : alsEl.EnumerateArray()
                        .Where(a => a.ValueKind == JsonValueKind.String)
                        .Select(a => a.GetString()!)
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);
            }

            return Task.FromResult(TextContent(enabled
                ? $"Shadow enabled. Audits: [{string.Join(", ", shadow.Config.Audits)}], Scope: {shadow.Config.Scope}. Will audit on each navigation."
                : "Shadow disabled."));
        }

        // Status/findings query (default)
        Severity? minSeverity = GetString(args, "severity")?.ToLowerInvariant() switch
        {
            "info" => Severity.Info,
            "low" => Severity.Low,
            "medium" => Severity.Medium,
            "high" => Severity.High,
            "critical" => Severity.Critical,
            _ => null
        };
        var categoryFilter = GetString(args, "category");
        var findings = shadow.GetFindings(null, minSeverity, categoryFilter);
        shadow.MarkPolled();

        if (!shadow.Enabled && findings.Count == 0)
            return Task.FromResult(TextContent(
                "Shadow is not active. Call with enabled=true to start ambient monitoring."));

        return Task.FromResult(TextContent(shadow.FormatFindings()));
    }

private Task<object> ToolSecurityCallbacks(JsonElement args)
    {
        var detector = _context.CallbackDetector;
        if (detector == null)
            return Task.FromResult(ErrorContent("Callback detector not initialized."));

        var action = GetString(args, "action") ?? "status";

        switch (action)
        {
            case "start":
                var domain = GetString(args, "domain");
                detector.Start(domain);
                return Task.FromResult(TextContent(
                    $"OOB callback detection active.\n" +
                    $"Callback domain: {detector.CallbackDomain}\n" +
                    $"Callback URL: {detector.CallbackUrl}\n" +
                    $"Marker: {Security.CallbackDetector.Marker}\n\n" +
                    $"Use {Security.CallbackDetector.Marker} in fuzz payloads — it will be replaced with the callback URL.\n" +
                    $"Any browser request to {detector.CallbackDomain} will be detected and reported."));
            case "stop":
                detector.Stop();
                return Task.FromResult(TextContent("OOB callback detection stopped."));
            case "clear":
                detector.Clear();
                return Task.FromResult(TextContent("Callback interactions cleared."));
            case "status":
            default:
                detector.MarkPolled();
                return Task.FromResult(TextContent(detector.Format()));
        }
    }

private async Task<object> ToolShadowCheck(JsonElement args)
    {
        var laws = _context.Laws;
        if (laws == null)
            return ErrorContent("Law service not initialized.");
        var report = Host != null
            ? await Host.RunShadowHeavyOnUiAsync()
            : await laws.RunShadowHeavyAsync();
        var sb = new StringBuilder();
        sb.AppendLine(report.SummaryLine);
        if (!string.IsNullOrEmpty(report.PageUrl))
            sb.AppendLine($"Page: {report.PageUrl}");
        if (!report.Ran)
            return TextContent(sb.ToString().TrimEnd());
        foreach (var r in laws.LastResults.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
        {
            if (r.Verdict is LawVerdict.Pass or LawVerdict.NotApplicable)
                continue;
            sb.AppendLine($"- [{r.Verdict}/{r.Severity}] {r.Name}" + (string.IsNullOrEmpty(r.Message) ? "" : $": {r.Message}"));
            if (!string.IsNullOrEmpty(r.Evidence))
                sb.AppendLine($"    evidence: {r.Evidence}");
        }
        return TextContent(sb.ToString().TrimEnd());
    }

private Task<object> ToolLaws(JsonElement args)
    {
        var laws = _context.Laws;
        if (laws == null)
            return Task.FromResult<object>(ErrorContent("Law service not initialized."));

        var action = GetString(args, "action") ?? "list";
        switch (action.ToLowerInvariant())
        {
            case "list":
                return Task.FromResult(TextContent(FormatLawRegistryList(laws)));
            case "check":
                return ToolLawsCheckAsync(
                    GetString(args, "nameFilter"),
                    GetBoolOrNull(args, "allLoaded") ?? true,
                    GetBoolOrNull(args, "includeTraffic") ?? false);
            case "proposals":
                return Task.FromResult(TextContent(FormatLawProposals(laws)));
            case "replace":
                return ToolLawsReplaceAsync(GetString(args, "code") ?? "", GetString(args, "fileName"));
            case "delete":
                return ToolLawsDeleteAsync(GetString(args, "fileName"), GetString(args, "path"));
            case "validate":
                var code = GetString(args, "code") ?? "";
                return ToolLawsValidateAsync(code, GetString(args, "fileName"));
            case "author":
                return ToolLawsAuthorAsync(GetString(args, "text") ?? GetString(args, "prompt") ?? "");
            case "accept":
                return ToolLawsAcceptProposalAsync(GetString(args, "id") ?? "");
            case "reject":
                return ToolLawsRejectProposalAsync(GetString(args, "id") ?? "");
            case "add":
                return ToolLawsAddAsync(GetString(args, "code") ?? "", GetString(args, "fileName"));
            default:
                return Task.FromResult<object>(ErrorContent($"Unknown laws action: {action}"));
        }
    }

    private static string FormatLawRegistryList(LawService laws)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"User Laws folder: {LawService.UserLawsFolder}");
        var all = laws.Registry.All.OrderBy(l => l.Name, StringComparer.OrdinalIgnoreCase).ToList();
        if (all.Count == 0)
        {
            sb.AppendLine("No Laws loaded.");
        }
        else
        {
            foreach (var l in all)
            {
                var src = string.IsNullOrEmpty(l.SourceFile) ? "?" : Path.GetFileName(l.SourceFile);
                var verdict = l.LastVerdict?.ToString() ?? "not exercised";
                var failHint = l.LastFailDetail != null
                    ? $" | lastFail={TruncateLawListField(l.LastFailDetail)} @ {l.LastFailUrl ?? "?"}"
                    : "";
                sb.AppendLine(
                    $"- {l.Name} | id={l.Id} | {l.Trigger} | last={verdict} | pass={l.PassCount} fail={l.FailCount}{failHint} | {src}");
            }
        }

        var diags = laws.Loader.Diagnostics;
        if (diags.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Load diagnostics:");
            foreach (var d in diags)
                sb.AppendLine($"- {Path.GetFileName(d.SourceFile)}: {d.Message}");
        }

        return sb.ToString().TrimEnd();
    }

    private static string FormatLawProposals(LawService laws)
    {
        var props = laws.Proposals.Proposals;
        if (props.Count == 0)
            return "No Law proposals pending.";

        var sb = new StringBuilder();
        foreach (var p in props)
        {
            sb.AppendLine($"- [{p.Id}] {p.Title} ({p.Source}, {p.Kind ?? "proposal"})");
            if (!string.IsNullOrWhiteSpace(p.Rationale))
                sb.AppendLine($"  Why: {p.Rationale}");
            sb.AppendLine($"  Samples: {p.Observations} · counterexamples: {p.Counterexamples}");
            foreach (var line in p.Evidence.Take(3))
                sb.AppendLine($"  · {line}");
        }

        return sb.ToString().TrimEnd();
    }

    private static string FormatLawCheckSummary(LawCheckSummary summary)
    {
        var sb = new StringBuilder();
        foreach (var r in summary.Results.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
        {
            var suffix = r.Verdict switch
            {
                LawVerdict.Fail or LawVerdict.Error => string.IsNullOrEmpty(r.Detail) ? "" : $": {r.Detail} [{r.Severity}]",
                LawVerdict.NotApplicable => string.IsNullOrEmpty(r.Message) ? "" : $": {r.Message}",
                _ => ""
            };
            sb.AppendLine($"[{r.Verdict}] {r.Name}{suffix}");
        }

        sb.AppendLine(
            $"Summary: {summary.Passed} passed, {summary.Failed} failed, {summary.NotApplicable} N/A, {summary.Errors} error(s), {summary.Skipped} skipped");
        if (summary.ResponseEntriesChecked > 0 || summary.ConsoleEntriesChecked > 0)
            sb.AppendLine(
                $"Traffic replay: {summary.ResponseEntriesChecked} network, {summary.ConsoleEntriesChecked} console entries.");
        return sb.ToString().TrimEnd();
    }

    private static string TruncateLawListField(string s) =>
        s.Length <= 96 ? s : s[..93] + "...";

private async Task<object> ToolLawsCheckAsync(string? nameFilter, bool allLoaded, bool includeTraffic)
    {
        var laws = _context.Laws!;
        var scope = allLoaded ? LawCheckScope.AllLoaded : LawCheckScope.ScriptConsoleDeclared;
        var summary = Host != null
            ? await Host.CheckLawsOnUiAsync(nameFilter, scope, includeTraffic)
            : await laws.CheckLawsAsync(nameFilter, scope, includeTraffic);
        return TextContent(FormatLawCheckSummary(summary));
    }

private async Task<object> ToolLawsAuthorAsync(string text)
    {
        var laws = _context.Laws!;
        var (ok, code, errors) = await laws.CreateAuthor().AuthorAsync(text);
        code = LawCodeGenerator.StripConsoleRunnerLines(code);
        var body = ok
            ? $"Valid Law source (save with action add — no CheckLaws() in file):\n\n{code}"
            : $"Law compile errors:\n{string.Join("\n", errors)}\n\nDraft:\n{code}";
        return TextContent(body);
    }

private async Task<object> ToolLawsAcceptProposalAsync(string id)
    {
        var laws = _context.Laws!;
        var proposal = laws.Proposals.Accept(id);
        if (proposal == null)
            return ErrorContent("Proposal not found.");
        var path = await laws.AppendProposalToUserLawsAsync(proposal);
        return TextContent($"Accepted into {path}");
    }

    private Task<object> ToolLawsRejectProposalAsync(string id)
    {
        var laws = _context.Laws!;
        if (string.IsNullOrWhiteSpace(id))
            return Task.FromResult<object>(ErrorContent("Provide \"id\" of the proposal to reject."));
        if (!laws.Proposals.Reject(id))
            return Task.FromResult<object>(ErrorContent("Proposal not found."));
        return Task.FromResult<object>(TextContent("Proposal rejected."));
    }

private async Task<object> ToolLawsAddAsync(string code, string? fileName)
    {
        var laws = _context.Laws!;
        var (ok, error) = await laws.AppendUserLawSourceAsync(fileName ?? "custom.csx", code);
        if (!ok)
            return ErrorContent(error ?? "Law append failed.");
        var path = LawService.ResolveUserLawPath(fileName ?? "custom.csx");
        return TextContent($"Appended and loaded: {path}\n\n{FormatLawRegistryList(laws)}");
    }

private async Task<object> ToolLawsReplaceAsync(string code, string? fileName)
    {
        var laws = _context.Laws!;
        var (ok, errors, path) = await laws.ReplaceUserLawFileAsync(fileName ?? "custom.csx", code);
        if (!ok)
            return ErrorContent("Law replace failed:\n" + string.Join("\n", errors));
        return TextContent($"Replaced: {path}\n\n{FormatLawRegistryList(laws)}");
    }

private async Task<object> ToolLawsDeleteAsync(string? fileName, string? path)
    {
        var laws = _context.Laws!;
        var deleted = !string.IsNullOrWhiteSpace(path)
            ? await laws.DeleteUserLawFileAsync(path)
            : !string.IsNullOrWhiteSpace(fileName)
                ? await laws.DeleteUserLawByFileNameAsync(fileName!)
                : false;
        return deleted
            ? TextContent($"Deleted.\n\n{FormatLawRegistryList(laws)}")
            : ErrorContent("User Law file not found or not deletable.");
    }

private async Task<object> ToolLawsValidateAsync(string code, string? fileName)
    {
        var laws = _context.Laws!;
        var exclude = !string.IsNullOrWhiteSpace(fileName)
            ? LawService.ResolveUserLawPath(fileName)
            : null;
        var (ok, errors) = await laws.Loader.ValidateAgainstRegistryAsync(code, laws.Registry, exclude);
        return TextContent(ok ? "Valid." : string.Join("\n", errors));
    }
}
