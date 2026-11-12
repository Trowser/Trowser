using System.Net;
using Trowser.Security.Nuclei;
using Trowser.Security.Orchestration;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    private Task HandlePostSecurityNucleiScan(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityNucleiScanAsync);

    private async Task HandleGetSecurityNucleiTemplates(HttpListenerRequest request, HttpListenerResponse response)
    {
        var q = request.QueryString;
        var templatesDir = q["templatesDir"];
        var includeBuiltin = !string.Equals(q["includeBuiltinTemplates"], "false", StringComparison.OrdinalIgnoreCase);
        await WriteSuccess(response, BuildNucleiTemplatesInventory(templatesDir, includeBuiltin));
    }

    // Shared by the REST GET endpoint and the MCP browser_security_nuclei_templates tool.
    internal Task<object> BuildSecurityNucleiTemplatesAsync(JsonBody body)
    {
        var templatesDir = body.GetString("templatesDir");
        var includeBuiltin = body.GetBool("includeBuiltinTemplates", true);
        return Task.FromResult(BuildNucleiTemplatesInventory(templatesDir, includeBuiltin));
    }

    private static object BuildNucleiTemplatesInventory(string? templatesDir, bool includeBuiltin)
    {
        var load = NucleiRunner.GetAllTemplatesDetailed(templatesDir, includeBuiltin);
        var inventory = NucleiRunner.GetTemplateInventory(templatesDir, includeBuiltin);
        var tags = NucleiRunner.GetTagCatalog(templatesDir, includeBuiltin);
        var compatibility = NucleiRunner.GetCompatibilitySummary(templatesDir, includeBuiltin);

        return new
        {
            count = inventory.Count,
            templates = inventory.Select(t => new { t.Id, t.Name, t.Severity, t.Tags, t.Methods, t.Source }),
            tags = tags.Select(t => new { tag = t.Tag, count = t.Count }),
            skippedTemplates = load.Skipped.Select(s => new { s.Id, s.Reason, s.Source }),
            compatibilitySummary = FormatNucleiCompatibility(compatibility)
        };
    }

    private static object FormatNucleiCompatibility(NucleiCompatibilitySummary summary) => new
    {
        runnable = summary.RunnableCount,
        skipped = summary.SkippedCount,
        filesScanned = summary.FilesScanned,
        skippedByReason = summary.SkippedByReason
    };

    internal async Task<object> BuildSecurityNucleiScanAsync(JsonBody body)
    {
        // Accept targetUrls (array/comma-string) and/or a single targetUrl; default to current page.
        var targetUrls = ParseStringListParam(body, "targetUrls");
        var targetUrl = body.GetString("targetUrl");
        if (string.IsNullOrWhiteSpace(targetUrl) && targetUrls.Count == 0)
            targetUrl = await _context.GetCurrentUrl();

        if (string.IsNullOrWhiteSpace(targetUrl) && targetUrls.Count == 0)
            throw new ApiCommandException(400, "Missing targetUrl/targetUrls — navigate first or pass a target.");

        // tags accepts a JSON array OR a comma-separated string.
        var tags = ParseStringListParam(body, "tags");
        // severity is the documented alias; minSeverity kept for back-compat.
        var minSeverity = body.GetString("minSeverity") ?? body.GetString("severity");
        var maxTemplates = body.GetInt("maxTemplates", 50);
        var timeoutMs = body.GetInt("timeoutMs", 10_000);
        var registerChainFindings = body.GetBool("registerChainFindings", true);
        var templatesDir = body.GetString("templatesDir");
        var includeBuiltinTemplates = body.GetBool("includeBuiltinTemplates", true);
        var followRedirects = body.GetBool("followRedirects", false);
        var dryRun = body.GetBool("dryRun", false);
        var verboseTemplateTrace = body.GetBool("verboseTemplateTrace", false);
        var includeBrowserCookies = body.GetBool("includeBrowserCookies", true);

        var selected = NucleiRunner.LoadTemplates(tags, minSeverity, maxTemplates, templatesDir, includeBuiltinTemplates);
        if (selected.Count == 0)
            throw new ApiCommandException(400,
                "No templates matched — check tags/severity filters, templatesDir path, or includeBuiltinTemplates.");
        var requiresWriteVerbs = NucleiRunner.SelectedTemplatesRequireWriteVerbs(selected);

        var effective = SafetyGate.Resolve(body);

        // A dry run sends no HTTP, so skip the probe/write-verb safety gates entirely.
        if (!dryRun)
        {
            if (!effective.AllowsProbes())
            {
                var passiveError = SafetyGate.RequireAtLeast(effective, SafetyMode.Safe,
                    "Nuclei template scan sends outbound HTTP probes");
                if (passiveError != null)
                    throw new ApiCommandException(400, passiveError.Value);
            }

            if (requiresWriteVerbs)
            {
                var gateError = SafetyGate.RequireActive(body,
                    "Selected nuclei templates include non-GET/HEAD methods and require safetyMode active or aggressive");
                if (gateError != null)
                    throw new ApiCommandException(400, gateError.Value);
            }
        }

        var options = new NucleiRunner.NucleiScanOptions
        {
            TargetUrl = targetUrl ?? "",
            TargetUrls = targetUrls,
            Tags = tags,
            MinSeverity = minSeverity,
            MaxTemplates = maxTemplates,
            TimeoutMs = timeoutMs,
            SafetyMode = effective,
            RegisterChainFindings = registerChainFindings,
            TemplatesDir = templatesDir,
            IncludeBuiltinTemplates = includeBuiltinTemplates,
            FollowRedirects = followRedirects,
            DryRun = dryRun,
            VerboseTemplateTrace = verboseTemplateTrace,
            IncludeBrowserCookies = includeBrowserCookies
        };

        var result = await NucleiRunner.RunAsync(options, _context, _context.OperationCancellation);
        return new
        {
            isClean = result.IsClean,
            dryRun = result.DryRun,
            includeBrowserCookies = result.IncludeBrowserCookies,
            estimatedHttpRequests = result.EstimatedHttpRequests,
            compatibilitySummary = result.CompatibilitySummary != null
                ? FormatNucleiCompatibility(result.CompatibilitySummary)
                : null,
            targetUrl = result.TargetUrl,
            targetUrls = result.TargetUrls,
            templatesLoaded = result.TemplatesLoaded,
            templatesSelected = result.TemplatesSelected,
            templatesRun = result.TemplatesRun,
            // Alias: TemplatesRun counts individual HTTP requests sent. Exposed as httpRequests because
            // nuclei uses a dedicated HttpClient outside the generic request-trace chokepoint, so the
            // verbose trace's requestCount will not include these probes.
            httpRequests = result.TemplatesRun,
            // Templates loaded but excluded by tag/severity/max filters.
            templatesFilteredOut = result.TemplatesFilteredOut,
            templatesSkipped = result.TemplatesFilteredOut,
            selectedTemplateIds = result.SelectedTemplateIds,
            matchedTemplateIds = result.MatchedTemplateIds,
            // Templates that could not be run (unsupported DSL / parse error), with reasons.
            skippedTemplates = result.SkippedTemplates.Select(s => new { s.Id, s.Reason, s.Source }),
            findingCount = result.Findings.Count,
            summary = result.Summary,
            findings = result.Findings.Select(f => new
            {
                f.TemplateId,
                f.TemplateName,
                // Stable common aliases shared across scanners (title/description/severity/url).
                title = f.Title,
                description = f.Description,
                f.Severity,
                f.Category,
                f.Url,
                f.Method,
                statusCode = f.StatusCode,
                f.Detail,
                f.Tags
            }),
            templateTrace = result.TemplateTrace.Select(t => new
            {
                t.TemplateId,
                t.Url,
                t.Method,
                statusCode = t.StatusCode,
                t.Matched,
                t.Requested
            }),
            report = result.Format(includeDetails: false)
        };
    }

    /// <summary>
    /// Parse a param that may be a JSON array of strings or a single comma-separated string.
    /// Splits array elements on commas too, trims, and de-duplicates (case-insensitive).
    /// </summary>
    private static IReadOnlyList<string> ParseStringListParam(JsonBody body, string property)
    {
        var values = new List<string>();

        var arr = body.GetStringList(property) ?? body.GetStringArray(property);
        if (arr != null)
            values.AddRange(arr);
        else
        {
            var single = body.GetString(property);
            if (!string.IsNullOrWhiteSpace(single))
                values.Add(single);
        }

        return values
            .SelectMany(v => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(v => v.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
