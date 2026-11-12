using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Trowser.Chat;

/// <summary>
/// Lightweight helpers for Settings: connection test and model listing.
/// Does not require MCP / tool executor.
/// </summary>
public static class LlmSetupService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };

    public sealed record ConnectionTestResult(bool Ok, string Message);
    public sealed record ModelListResult(bool Ok, string Message, IReadOnlyList<string> Models);

    public static async Task<ConnectionTestResult> TestConnectionAsync(
        LlmSettings settings, CancellationToken ct = default)
    {
        try
        {
            if (settings.Provider == LlmProvider.GitHubCopilot)
                return await TestCopilotAsync(settings, ct).ConfigureAwait(false);

            if (settings.Provider == LlmProvider.Anthropic)
                return await TestAnthropicAsync(settings, ct).ConfigureAwait(false);

            return await TestOpenAiCompatibleAsync(settings, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new ConnectionTestResult(false, ex.Message);
        }
    }

    public static async Task<ModelListResult> ListModelsAsync(
        LlmSettings settings, CancellationToken ct = default)
    {
        try
        {
            if (settings.Provider == LlmProvider.Anthropic)
            {
                return new ModelListResult(false,
                    "Model listing is not available for this provider. Type the model id manually.",
                    Array.Empty<string>());
            }

            if (settings.Provider == LlmProvider.GitHubCopilot)
            {
                var copilotModels = await CopilotAuth.ListChatModelsAsync(Http, settings, ct).ConfigureAwait(false);
                if (copilotModels.Count == 0)
                {
                    return new ModelListResult(false,
                        "No Copilot chat models returned. Check GitHub host / gh auth, then try again.",
                        Array.Empty<string>());
                }

                return new ModelListResult(true,
                    $"Found {copilotModels.Count} Copilot chat model(s). Claude Sonnet 5 is `{LlmSettings.DefaultCopilotModel}`.",
                    copilotModels);
            }

            var url = settings.GetModelsListUrl();
            if (string.IsNullOrEmpty(url))
                return new ModelListResult(false, "No models endpoint for this configuration.", Array.Empty<string>());

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            ApplyAuthHeaders(request, settings);

            using var response = await Http.SendAsync(request, ct).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                return new ModelListResult(false, FormatHttpError(response.StatusCode, body), Array.Empty<string>());

            var models = ParseOpenAiModelIds(body);
            if (models.Count == 0)
                return new ModelListResult(false, "No models returned. Is the endpoint reachable?", Array.Empty<string>());

            // Prefer tool-capable OpenRouter models when the catalog exposes that hint.
            if (settings.UsesOpenRouter)
                models = PreferOpenRouterToolModels(body, models);

            return new ModelListResult(true, $"Found {models.Count} model(s).", models);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new ModelListResult(false, ex.Message, Array.Empty<string>());
        }
    }

    private static async Task<ConnectionTestResult> TestOpenAiCompatibleAsync(
        LlmSettings settings, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(settings.Endpoint))
            return new ConnectionTestResult(false, "Endpoint is required.");
        if (string.IsNullOrWhiteSpace(settings.Model))
            return new ConnectionTestResult(false, "Model is required.");
        if (settings.RequiresApiKey && string.IsNullOrWhiteSpace(settings.GetEffectiveApiKey()))
            return new ConnectionTestResult(false, "API key required (or set OPENAI_API_KEY / OPENROUTER_API_KEY).");

        // Prefer /models when available — cheaper and doesn't burn a completion.
        var modelsUrl = settings.GetModelsListUrl();
        if (!string.IsNullOrEmpty(modelsUrl))
        {
            using var listRequest = new HttpRequestMessage(HttpMethod.Get, modelsUrl);
            ApplyAuthHeaders(listRequest, settings);
            using var listResponse = await Http.SendAsync(listRequest, ct).ConfigureAwait(false);
            if (listResponse.IsSuccessStatusCode)
            {
                var listBody = await listResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                var ids = ParseOpenAiModelIds(listBody);
                if (ids.Count > 0 &&
                    !ids.Any(id => id.Equals(settings.Model, StringComparison.OrdinalIgnoreCase)))
                {
                    return new ConnectionTestResult(true,
                        $"Connected. Model \"{settings.Model}\" not in /models list ({ids.Count} models) — it may still work.");
                }

                return new ConnectionTestResult(true,
                    ids.Count > 0
                        ? $"Connected. {ids.Count} model(s) available."
                        : "Connected (models endpoint OK).");
            }

            // Some gateways don't expose /models; fall through to a tiny chat probe.
            if ((int)listResponse.StatusCode is not (401 or 403 or 404))
            {
                var err = await listResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                // Still try chat probe for 404-style gateways
                if ((int)listResponse.StatusCode != 404)
                    return new ConnectionTestResult(false, FormatHttpError(listResponse.StatusCode, err));
            }
            else if ((int)listResponse.StatusCode is 401 or 403)
            {
                var err = await listResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                return new ConnectionTestResult(false, FormatHttpError(listResponse.StatusCode, err));
            }
        }

        return await ProbeChatCompletionAsync(settings, ct).ConfigureAwait(false);
    }

    private static async Task<ConnectionTestResult> ProbeChatCompletionAsync(
        LlmSettings settings, CancellationToken ct)
    {
        var body = new Dictionary<string, object>
        {
            ["model"] = settings.Model,
            ["messages"] = new[] { new { role = "user", content = "ping" } },
            ["max_tokens"] = 1,
            ["temperature"] = 0
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, settings.GetCompletionsUrl())
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
        ApplyAuthHeaders(request, settings);

        using var response = await Http.SendAsync(request, ct).ConfigureAwait(false);
        var responseBody = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            return new ConnectionTestResult(false, FormatHttpError(response.StatusCode, responseBody));

        return new ConnectionTestResult(true, "Connected. Chat completions OK.");
    }

    private static async Task<ConnectionTestResult> TestAnthropicAsync(
        LlmSettings settings, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(settings.Model))
            return new ConnectionTestResult(false, "Model is required.");
        if (string.IsNullOrWhiteSpace(settings.GetEffectiveApiKey()))
            return new ConnectionTestResult(false, "API key required (or set ANTHROPIC_API_KEY).");

        var body = new Dictionary<string, object>
        {
            ["model"] = settings.Model,
            ["max_tokens"] = 1,
            ["messages"] = new[] { new { role = "user", content = "ping" } }
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, settings.GetCompletionsUrl())
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
        request.Headers.Add("x-api-key", settings.GetEffectiveApiKey());
        request.Headers.Add("anthropic-version", "2023-06-01");

        using var response = await Http.SendAsync(request, ct).ConfigureAwait(false);
        var responseBody = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            return new ConnectionTestResult(false, FormatHttpError(response.StatusCode, responseBody));

        return new ConnectionTestResult(true, "Connected. Anthropic messages OK.");
    }

    private static async Task<ConnectionTestResult> TestCopilotAsync(
        LlmSettings settings, CancellationToken ct)
    {
        try
        {
            var session = await CopilotAuth.CreateSessionAsync(Http, settings, ct).ConfigureAwait(false);
            var host = CopilotAuth.ResolveGitHubHost(settings);
            return new ConnectionTestResult(true,
                $"Connected. GitHub Copilot token OK ({host} → {session.CompletionsUrl}).");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ConnectionTestResult(false, ex.Message);
        }
    }

    private static void ApplyAuthHeaders(HttpRequestMessage request, LlmSettings settings)
    {
        var key = settings.GetEffectiveApiKey();
        if (!string.IsNullOrWhiteSpace(key))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);

        if (settings.UsesOpenRouter)
        {
            if (!request.Headers.Contains("HTTP-Referer"))
                request.Headers.TryAddWithoutValidation("HTTP-Referer", "https://trowser.local");
            if (!request.Headers.Contains("X-Title") && !request.Headers.Contains("X-OpenRouter-Title"))
                request.Headers.TryAddWithoutValidation("X-Title", "Trowser");
        }
    }

    private static List<string> ParseOpenAiModelIds(string json)
    {
        var ids = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var data) ||
                data.ValueKind != JsonValueKind.Array)
                return ids;

            foreach (var item in data.EnumerateArray())
            {
                if (item.TryGetProperty("id", out var idProp))
                {
                    var id = idProp.GetString();
                    if (!string.IsNullOrWhiteSpace(id))
                        ids.Add(id);
                }
            }
        }
        catch
        {
            return ids;
        }

        ids.Sort(StringComparer.OrdinalIgnoreCase);
        return ids;
    }

    /// <summary>
    /// When OpenRouter includes supported_parameters, surface tool-capable models first.
    /// </summary>
    private static List<string> PreferOpenRouterToolModels(string json, List<string> allIds)
    {
        var toolCapable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var data))
                return allIds;

            foreach (var item in data.EnumerateArray())
            {
                if (!item.TryGetProperty("id", out var idProp))
                    continue;
                var id = idProp.GetString();
                if (string.IsNullOrWhiteSpace(id))
                    continue;

                if (item.TryGetProperty("supported_parameters", out var parms) &&
                    parms.ValueKind == JsonValueKind.Array)
                {
                    foreach (var p in parms.EnumerateArray())
                    {
                        if (p.GetString() is "tools" or "tool_choice")
                        {
                            toolCapable.Add(id);
                            break;
                        }
                    }
                }
            }
        }
        catch
        {
            return allIds;
        }

        if (toolCapable.Count == 0)
            return allIds;

        var preferred = allIds.Where(toolCapable.Contains).ToList();
        preferred.AddRange(allIds.Where(id => !toolCapable.Contains(id)));
        return preferred;
    }

    private static string FormatHttpError(System.Net.HttpStatusCode status, string body)
    {
        var detail = Truncate(body, 240).Replace('\r', ' ').Replace('\n', ' ');
        return $"HTTP {(int)status}: {detail}";
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) ? "" : s.Length <= max ? s : s[..max] + "…";
}
