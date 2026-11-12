using System.Text.Json;
using Trowser.Security.LlmRedTeam;

namespace Trowser.Api;

internal static class LlmRedTeamRequestParser
{
    public static LlmRedTeamScanOptions ParseScanOptions(JsonBody body)
    {
        var options = new LlmRedTeamScanOptions
        {
            Mode = body.GetString("mode") ?? "auto",
            Preset = body.GetString("preset"),
            MaxProbes = body.GetInt("maxProbes", 28),
            Concurrency = body.GetInt("concurrency", 2),
            TimeoutMs = body.GetInt("timeoutMs", 30000),
            ProbeDelayMs = body.GetInt("probeDelayMs", 1000),
            IncludeWebMcpAbuse = body.GetBool("includeWebMcpAbuse", true),
            IncludeIndirectInjection = body.GetBool("includeIndirectInjection", false),
            IncludeUnboundedConsumption = body.GetBool("includeUnboundedConsumption", false),
            IncludeRagPoison = body.GetBool("includeRagPoison", false),
            RegisterWhisperHints = body.GetBool("registerWhisperHints", true),
            ProbeAnonymousAccess = body.GetBool("probeAnonymousAccess", false),
            IndirectInjectionToken = body.GetString("indirectInjectionToken"),
            PeerBaseUrl = body.GetString("peerBaseUrl"),
            PeerApiKey = body.GetString("peerApiKey"),
            ProbeIds = body.GetStringArray("probeIds"),
            Categories = body.GetStringArray("categories")
        };

        var httpDoc = body.GetObject("httpTarget");
        if (httpDoc != null)
        {
            using (httpDoc)
                options.HttpTarget = ParseHttpTarget(new JsonBody(httpDoc));
        }

        var chatDoc = body.GetObject("chatTarget");
        if (chatDoc != null)
        {
            using (chatDoc)
                options.ChatTarget = ParseChatTarget(new JsonBody(chatDoc));
        }

        return options;
    }

    public static LlmHttpTargetConfig ParseHttpTarget(JsonBody body)
    {
        var (customBodyJson, customBodyRaw, customBody) = ParseCustomBody(body);
        return new LlmHttpTargetConfig
        {
            Url = body.GetString("url") ?? "",
            Schema = body.GetString("schema") ?? "openai",
            Model = body.GetString("model") ?? "gpt-3.5-turbo",
            Headers = body.GetStringDictionary("headers"),
            TimeoutMs = body.GetInt("timeoutMs", 30000),
            CustomResponseKey = body.GetString("customResponseKey") ?? "response",
            UseBackendFetch = body.GetBool("useBackendFetch", false),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            CustomBodyJson = customBodyJson,
            CustomBodyRaw = customBodyRaw,
            CustomBody = customBody
        };
    }

    public static LlmChatUiTarget ParseChatTarget(JsonBody body) => new()
    {
        InputSelector = body.GetString("inputSelector"),
        SubmitSelector = body.GetString("submitSelector"),
        ResponseSelector = body.GetString("responseSelector"),
        WaitAfterSubmitMs = body.GetInt("waitAfterSubmitMs", 4000),
        AutoDetect = body.HasProperty("autoDetect") ? body.GetBool("autoDetect", true) : true,
        ResetUi = body.GetBool("resetUi", false),
        FailoverToHttp = body.HasProperty("failoverToHttp") ? body.GetBool("failoverToHttp", true) : true
    };

    /// <summary>
    /// Accepts <c>customBody</c> as a JSON object (placeholders in string values) or a JSON string
    /// (form-urlencoded / raw body template with <c>{{PROMPT}}</c>).
    /// </summary>
    private static (string? Json, string? Raw, Dictionary<string, object>? Dict) ParseCustomBody(JsonBody body)
    {
        if (!body.HasProperty("customBody"))
            return (null, null, null);

        var el = body.GetJsonElement("customBody");
        if (el is null)
            return (null, null, null);

        var value = el.Value;
        if (value.ValueKind == JsonValueKind.String)
            return (null, value.GetString(), null);

        if (value.ValueKind == JsonValueKind.Object)
        {
            var json = value.GetRawText();
            Dictionary<string, object>? dict = null;
            try
            {
                dict = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
            }
            catch
            {
                // Keep CustomBodyJson even if dictionary shape is unusual.
            }

            return (json, null, dict);
        }

        // Messages-array wire format: [{"role":"user","content":"{{PROMPT}}"}]
        if (value.ValueKind == JsonValueKind.Array)
            return (value.GetRawText(), null, null);

        return (null, null, null);
    }

    public static object FormatSurface(LlmSurfaceSummary surface) => new
    {
        surface.ChatEndpointCount,
        surface.ChatWidgetCount,
        surface.WebMcpToolCount,
        surface.HttpMcpEndpointCount,
        surface.IframeCopilotCount,
        surface.HasAiIntegration,
        surface.BotGateDetected,
        suggestedHttpTarget = surface.SuggestedHttpTarget == null ? null : new
        {
            surface.SuggestedHttpTarget.Url,
            surface.SuggestedHttpTarget.Schema,
            customBody = surface.SuggestedHttpTarget.CustomBodyJson,
            surface.SuggestedHttpTarget.IncludeBrowserCookies
        },
        endpoints = surface.Endpoints.Select(e => new
        {
            e.Url,
            e.Method,
            e.Source,
            e.MatchReason,
            e.ContentType,
            e.IsSse,
            e.Confidence,
            hasSampleBody = !string.IsNullOrWhiteSpace(e.SampleRequestBody)
        }),
        httpMcpEndpoints = surface.HttpMcpEndpoints.Select(e => new
        {
            e.Url,
            e.Source,
            e.Confidence,
            e.MatchReason,
            toolNames = e.ToolNames
        }),
        chatWidgets = surface.ChatWidgets.Select(w => new
        {
            w.InputSelector,
            w.SubmitSelector,
            w.ResponseSelector,
            w.Placeholder,
            w.MatchReason
        })
    };

    public static object FormatProbeCatalog() => new
    {
        coverage = LlmProbeCorpus.BuildCoverageMetadata(),
        categories = LlmProbeCorpus.ListCategories(),
        probes = LlmProbeCorpus.ListCatalog()
    };

    public static object FormatScanResult(LlmRedTeamScanResult result) => new
    {
        result.Message,
        result.Transport,
        result.TotalProbes,
        firedCount = result.FiredCount,
        result.ElapsedMs,
        isClean = !result.HasFindings,
        hasFindings = result.HasFindings,
        coverage = result.Coverage ?? LlmProbeCorpus.BuildCoverageMetadata(),
        warnings = result.Warnings,
        surface = FormatSurface(result.Surface),
        findings = (result.AllFindings.Count > 0 ? result.AllFindings : result.Findings).Select(f => new
        {
            f.ProbeId,
            f.Category,
            f.Severity,
            f.Confidence,
            f.Matched,
            f.Rationale,
            f.Transport,
            f.TargetUrl,
            f.ResponseExcerpt,
            f.Error
        }),
        results = result.Results.Select(f => new
        {
            f.ProbeId,
            f.Category,
            f.Severity,
            fired = f.Fired,
            f.Confidence,
            f.Matched,
            f.Rationale,
            f.Transport,
            f.TargetUrl,
            f.ResponseExcerpt,
            f.Error
        }),
        webMcpAbuse = result.WebMcpAbuseFindings.Select(w => new
        {
            w.ToolName,
            w.PayloadKind,
            w.ArgumentJson,
            w.Detail,
            w.Severity
        }),
        indirectInjection = result.IndirectInjection == null ? null : new
        {
            result.IndirectInjection.Attempted,
            result.IndirectInjection.InjectionObserved,
            result.IndirectInjection.InjectedToken,
            result.IndirectInjection.UploadSelector,
            result.IndirectInjection.SummarizeUrl,
            result.IndirectInjection.Detail,
            result.IndirectInjection.ResponseExcerpt
        },
        unboundedConsumption = result.UnboundedConsumptionFindings.Select(u => new
        {
            u.ProbeId,
            u.Category,
            u.Severity,
            fired = u.Fired,
            u.Detail,
            u.TargetUrl,
            u.Evidence
        }),
        ragPoison = result.RagPoison == null ? null : new
        {
            result.RagPoison.Attempted,
            result.RagPoison.PersistenceObserved,
            result.RagPoison.CrossTenantLeakObserved,
            result.RagPoison.MemoryPoisonObserved,
            result.RagPoison.PoisonToken,
            result.RagPoison.Detail,
            result.RagPoison.ResponseExcerpt,
            findings = result.RagPoison.Findings.Select(f => new
            {
                f.ProbeId,
                f.Category,
                f.Severity,
                fired = f.Fired,
                f.Confidence,
                f.Matched,
                f.Rationale,
                f.ResponseExcerpt
            })
        }
    };

    public static object FormatChatInteract(LlmChatInteractResult result) => new
    {
        result.Success,
        result.Prompt,
        result.ResponseText,
        result.ResponseHtml,
        result.InputSelector,
        result.ResponseSelector,
        result.ResponseChanged,
        result.Warning,
        result.RecoveryHint,
        result.Error,
        result.ElapsedMs
    };
}
