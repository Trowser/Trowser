using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser.Security;

namespace Trowser.Chat;

public enum LlmProvider
{
    OpenAiCompatible,
    OpenRouter,
    Anthropic,
    GitHubCopilot
}

public enum InteractionMode
{
    Chat,
    Full,
    Economical
}

/// <summary>
/// Per-provider LLM connection settings. Switching providers in LLM Settings
/// restores the last endpoint, API key, model, and GitHub host for that provider.
/// </summary>
public sealed class LlmProviderProfile
{
    public string Endpoint { get; set; } = "";
    public string ApiKey { get; set; } = "";
    public string Model { get; set; } = "";
    public string GitHubHost { get; set; } = "";

    public LlmProviderProfile Clone() => new()
    {
        Endpoint = Endpoint ?? "",
        ApiKey = ApiKey ?? "",
        Model = Model ?? "",
        GitHubHost = GitHubHost ?? ""
    };
}

/// <summary>
/// Persistent settings for the LLM chat integration.
/// Stored as JSON in %APPDATA%\Trowser\settings.json.
/// Top-level <see cref="Provider"/> / <see cref="Endpoint"/> / <see cref="ApiKey"/> / <see cref="Model"/>
/// are the last-used provider. Each provider's own values live in <see cref="Providers"/>.
/// </summary>
public class LlmSettings
{
    public const string OpenAiEndpoint = "https://api.openai.com/v1";
    public const string OpenRouterEndpoint = "https://openrouter.ai/api/v1";
    public const string AnthropicEndpoint = "https://api.anthropic.com";
    public const string CopilotEndpoint = "https://api.githubcopilot.com";
    public const string OllamaEndpoint = "http://localhost:11434/v1";

    public const string DefaultOpenAiModel = "gpt-4o";
    public const string DefaultOpenRouterModel = "openrouter/free";
    public const string DefaultAnthropicModel = "claude-sonnet-4-20250514";
    public const string DefaultOllamaModel = "llama3.2";
    public const string DefaultCopilotModel = "claude-sonnet-5";

    /// <summary>Fallback Copilot chat ids when Fetch models has not been run.</summary>
    public static readonly string[] DefaultCopilotModels =
    [
        DefaultCopilotModel,
        "claude-sonnet-4.6",
        "claude-sonnet-4.5",
        "claude-opus-5",
        "claude-opus-4.6",
        "claude-haiku-4.5",
        "gpt-5.4",
        "gpt-4.1",
        "gemini-3.6-flash",
        "gpt-4o"
    ];

    public LlmProvider Provider { get; set; } = LlmProvider.OpenRouter;
    public string Endpoint { get; set; } = OpenRouterEndpoint;
    public string ApiKey { get; set; } = "";
    public string Model { get; set; } = DefaultOpenRouterModel;

    /// <summary>
    /// GitHub hostname for Copilot (e.g. github.com or company.ghe.com).
    /// Empty = auto-detect from COPILOT_GH_HOST / GH_HOST, Copilot CLI, or gh.
    /// </summary>
    public string GitHubHost { get; set; } = "";

    /// <summary>
    /// Last-used connection settings for each <see cref="LlmProvider"/>.
    /// Keys are camelCase enum names (e.g. "openAiCompatible", "openRouter", "anthropic", "gitHubCopilot").
    /// </summary>
    public Dictionary<string, LlmProviderProfile> Providers { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Legacy per-provider API keys. Still read on load and rewritten from <see cref="Providers"/> on save.
    /// </summary>
    public Dictionary<string, string> ProviderApiKeys { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public double Temperature { get; set; } = 0.3;
    public int? MaxTokens { get; set; }
    public InteractionMode Mode { get; set; } = InteractionMode.Economical;

    /// <summary>
    /// Optional custom system prompts per interaction mode. Null/empty = use embedded default.
    /// Edited via LLM Settings → Prompt…
    /// </summary>
    public string? SystemPromptChat { get; set; }
    public string? SystemPromptFull { get; set; }
    public string? SystemPromptEconomical { get; set; }

    /// <summary>
    /// When true, assistant prose appears token-by-token in the chat UI.
    /// HTTP completions always stream so tool calls are not truncated; this flag
    /// does not limit tool rounds or follow-up messages.
    /// </summary>
    public bool StreamResponses { get; set; }

    /// <summary>
    /// True once the user has saved Stream responses from LLM Settings. Until then,
    /// <see cref="MigrateStreamResponsesDefault"/> may still apply the new default.
    /// </summary>
    public bool StreamResponsesUserSet { get; set; }

    /// <summary>
    /// When true, built-in Chat asks before sensitive tool calls (see <see cref="ChatToolApproval"/>).
    /// Tester-machine / session safety: script, fetch with cookies, mocks, identity changes, etc.
    /// Local paths still prompt when this is false. Active/aggressive probes use
    /// <see cref="ConfirmActiveSafetyProbes"/> (target-server safety).
    /// </summary>
    public bool ConfirmSensitiveAssistantActions { get; set; } = true;

    /// <summary>
    /// When true, built-in Chat asks before security tools run with active or aggressive safetyMode.
    /// Target-server safety: probes that can mutate application state on the loaded site.
    /// Kept separate from <see cref="ConfirmSensitiveAssistantActions"/> so users can allow
    /// local automation while still confirming state-changing scans. Local paths still prompt when off.
    /// </summary>
    public bool ConfirmActiveSafetyProbes { get; set; } = true;

    /// <summary>Approximate context budget for built-in chat compaction (tokens).</summary>
    public int ContextBudgetTokens { get; set; } = 128_000;

    /// <summary>When true, warn and force compact when context exceeds budget thresholds.</summary>
    public bool AutoCompactEnabled { get; set; } = true;

    public int CompactWarnPercent { get; set; } = 70;
    public int CompactForcePercent { get; set; } = 90;
    public int CompactKeepLastTurns { get; set; } = 10;

    // ─── Proxy ───
    public bool ProxyEnabled { get; set; }
    public string ProxyUrl { get; set; } = "http://localhost:8080";

    // ─── Security features (persisted here so they survive restarts) ───
    public ShadowConfig Shadow { get; set; } = new();
    public PowerModeConfig PowerMode { get; set; } = new();
    public WhisperConfig Whisper { get; set; } = new();

    // ─── Test data preferences ───
    public bool TestDataUseOnline { get; set; }
    public bool TestDataAsciiOnly { get; set; }
    public string TestDataOnlineUrl { get; set; } = TestDataService.DefaultOnlineUrl;
    public TestDataKind TestDataActiveKind { get; set; } = TestDataKind.Strings;

    /// <summary>
    /// True when Chat can actually send requests: model (+ endpoint) and credentials when required.
    /// Local endpoints and GitHub Copilot (gh CLI) do not require a stored API key.
    /// </summary>
    [JsonIgnore]
    public bool IsConfigured
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Model))
                return false;

            if (Provider == LlmProvider.GitHubCopilot)
                return true;

            if (string.IsNullOrWhiteSpace(Endpoint))
                return false;

            if (!RequiresApiKey)
                return true;

            return !string.IsNullOrWhiteSpace(GetEffectiveApiKey());
        }
    }

    /// <summary>
    /// Cloud providers need an API key (settings or environment). Localhost and Copilot do not.
    /// </summary>
    [JsonIgnore]
    public bool RequiresApiKey =>
        Provider != LlmProvider.GitHubCopilot && !IsLocalEndpoint(Endpoint);

    [JsonIgnore]
    public bool UsesOpenRouter =>
        Provider == LlmProvider.OpenRouter || IsOpenRouterEndpoint(Endpoint);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private static string SettingsPath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Trowser");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "settings.json");
        }
    }

    public static LlmSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                var loaded = JsonSerializer.Deserialize<LlmSettings>(json, JsonOptions) ?? new LlmSettings();
                loaded.MigrateUntouchedFactoryDefaults();
                loaded.MigrateStreamResponsesDefault();
                loaded.MigrateShadowFactoryDefaults();
                loaded.EnsureProviderProfiles();
                return loaded;
            }
        }
        catch (Exception ex) { TrowserLog.Error("Failed to load settings", ex); }
        var fresh = new LlmSettings();
        fresh.EnsureProviderProfiles();
        return fresh;
    }

    /// <summary>
    /// Users who never configured Chat still have the old OpenAI factory defaults.
    /// Move them to OpenRouter free so first-run Chat setup is cheaper/easier.
    /// </summary>
    private void MigrateUntouchedFactoryDefaults()
    {
        var looksUntouched =
            string.IsNullOrWhiteSpace(ApiKey) &&
            (
                // Pre–OpenRouter-default installs
                (Provider == LlmProvider.OpenAiCompatible &&
                 (string.IsNullOrWhiteSpace(Endpoint) ||
                  Endpoint.Trim().TrimEnd('/').Equals(OpenAiEndpoint, StringComparison.OrdinalIgnoreCase)) &&
                 (string.IsNullOrWhiteSpace(Model) ||
                  Model.Equals(DefaultOpenAiModel, StringComparison.OrdinalIgnoreCase)))
                ||
                // Brief intermediate default before free router
                (Provider == LlmProvider.OpenRouter &&
                 (string.IsNullOrWhiteSpace(Endpoint) ||
                  Endpoint.Trim().TrimEnd('/').Equals(OpenRouterEndpoint, StringComparison.OrdinalIgnoreCase)) &&
                 Model.Equals("openai/gpt-4o-mini", StringComparison.OrdinalIgnoreCase))
            );

        if (!looksUntouched)
            return;

        Provider = LlmProvider.OpenRouter;
        Endpoint = OpenRouterEndpoint;
        Model = DefaultOpenRouterModel;
    }

    /// <summary>
    /// Old factory default was streaming on. Turn UI streaming off once unless the
    /// user already chose a value in Settings.
    /// </summary>
    internal void MigrateStreamResponsesDefault()
    {
        if (StreamResponsesUserSet)
            return;

        StreamResponses = false;
    }

    /// <summary>
    /// Shadow used to ship off with audits <c>all</c>, then on with a factory audit set.
    /// Untouched installs get the current factory default (off; audits XSS, Retire.js, Headers, Network, Console).
    /// Customized configs are left alone.
    /// </summary>
    internal void MigrateShadowFactoryDefaults()
    {
        Shadow ??= new ShadowConfig();
        if (Shadow.ShouldApplyCurrentFactoryDefaults())
            Shadow.ApplyCurrentFactoryDefaults();
    }

    public void Save()
    {
        try
        {
            CaptureActiveToProfile();
            EnsureProviderProfiles();
            var json = JsonSerializer.Serialize(this, JsonOptions);
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex) { TrowserLog.Error("Failed to save settings", ex); }
    }

    /// <summary>
    /// Canonical dictionary key for <paramref name="provider"/> (camelCase enum name).
    /// </summary>
    public static string ProviderKey(LlmProvider provider) =>
        JsonNamingPolicy.CamelCase.ConvertName(provider.ToString());

    public static bool TryParseProviderKey(string? key, out LlmProvider provider)
    {
        foreach (var candidate in Enum.GetValues<LlmProvider>())
        {
            if (ProviderKey(candidate).Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                provider = candidate;
                return true;
            }
        }

        provider = default;
        return false;
    }

    public static LlmProviderProfile CreateDefaultProfile(LlmProvider provider) => new()
    {
        Endpoint = DefaultEndpoint(provider),
        Model = DefaultModel(provider)
    };

    public static Dictionary<string, LlmProviderProfile> CloneProfiles(
        IDictionary<string, LlmProviderProfile>? source)
    {
        var copy = new Dictionary<string, LlmProviderProfile>(StringComparer.OrdinalIgnoreCase);
        if (source == null)
            return copy;

        foreach (var kv in source)
            copy[kv.Key] = (kv.Value ?? new LlmProviderProfile()).Clone();
        return copy;
    }

    public LlmProviderProfile GetOrCreateProfile(LlmProvider provider)
    {
        EnsureDictionaries();
        var key = ProviderKey(provider);
        if (!Providers.TryGetValue(key, out var profile) || profile == null)
        {
            profile = CreateDefaultProfile(provider);
            Providers[key] = profile;
        }

        return profile;
    }

    /// <summary>
    /// Writes the top-level last-used connection fields into <see cref="Providers"/>.
    /// </summary>
    public void CaptureActiveToProfile()
    {
        var profile = GetOrCreateProfile(Provider);
        profile.Endpoint = Endpoint ?? "";
        profile.ApiKey = ApiKey ?? "";
        profile.Model = Model ?? "";
        profile.GitHubHost = GitHubHost ?? "";
        SyncLegacyApiKeys();
    }

    /// <summary>
    /// Copies a stored provider profile onto the top-level last-used fields.
    /// Missing endpoint/model fall back to that provider's defaults.
    /// </summary>
    public void ApplyProfile(LlmProvider provider)
    {
        Provider = provider;
        var profile = GetOrCreateProfile(provider);
        Endpoint = string.IsNullOrWhiteSpace(profile.Endpoint)
            ? DefaultEndpoint(provider)
            : profile.Endpoint;
        ApiKey = profile.ApiKey ?? "";
        Model = string.IsNullOrWhiteSpace(profile.Model)
            ? DefaultModel(provider)
            : profile.Model;
        GitHubHost = profile.GitHubHost ?? "";
        SyncLegacyApiKeys();
    }

    /// <summary>
    /// Fills <see cref="Providers"/> from last-used top-level fields and legacy
    /// <see cref="ProviderApiKeys"/> so older settings.json files keep working.
    /// </summary>
    public void EnsureProviderProfiles()
    {
        EnsureDictionaries();
        NormalizeProviderKeys();

        foreach (var provider in Enum.GetValues<LlmProvider>())
        {
            var key = ProviderKey(provider);
            if (!Providers.TryGetValue(key, out var profile) || profile == null)
                Providers[key] = CreateDefaultProfile(provider);
            else
            {
                if (string.IsNullOrWhiteSpace(profile.Endpoint))
                    profile.Endpoint = DefaultEndpoint(provider);
                if (string.IsNullOrWhiteSpace(profile.Model))
                    profile.Model = DefaultModel(provider);
                profile.ApiKey ??= "";
                profile.GitHubHost ??= "";
            }
        }

        // Last-used top-level fields win for the active provider.
        var active = GetOrCreateProfile(Provider);
        if (!string.IsNullOrWhiteSpace(Endpoint))
            active.Endpoint = Endpoint;
        if (ApiKey != null)
            active.ApiKey = ApiKey;
        if (!string.IsNullOrWhiteSpace(Model))
            active.Model = Model;
        if (!string.IsNullOrWhiteSpace(GitHubHost))
            active.GitHubHost = GitHubHost;

        foreach (var kv in ProviderApiKeys)
        {
            if (string.IsNullOrWhiteSpace(kv.Value))
                continue;
            if (!TryParseProviderKey(kv.Key, out var provider))
                continue;
            var profile = GetOrCreateProfile(provider);
            if (provider == Provider)
                continue; // top-level ApiKey already applied
            if (string.IsNullOrWhiteSpace(profile.ApiKey))
                profile.ApiKey = kv.Value;
        }

        SyncLegacyApiKeys();
    }

    private void EnsureDictionaries()
    {
        if (Providers == null || Providers.Comparer != StringComparer.OrdinalIgnoreCase)
        {
            var copy = new Dictionary<string, LlmProviderProfile>(StringComparer.OrdinalIgnoreCase);
            if (Providers != null)
            {
                foreach (var kv in Providers)
                    copy[kv.Key] = kv.Value ?? new LlmProviderProfile();
            }
            Providers = copy;
        }

        if (ProviderApiKeys == null || ProviderApiKeys.Comparer != StringComparer.OrdinalIgnoreCase)
        {
            var copy = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (ProviderApiKeys != null)
            {
                foreach (var kv in ProviderApiKeys)
                    copy[kv.Key] = kv.Value ?? "";
            }
            ProviderApiKeys = copy;
        }
    }

    private void NormalizeProviderKeys()
    {
        var normalized = new Dictionary<string, LlmProviderProfile>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in Providers)
        {
            var profile = kv.Value ?? new LlmProviderProfile();
            if (TryParseProviderKey(kv.Key, out var provider))
                normalized[ProviderKey(provider)] = profile;
            else
                normalized[kv.Key] = profile;
        }
        Providers = normalized;
    }

    private void SyncLegacyApiKeys()
    {
        EnsureDictionaries();
        ProviderApiKeys.Clear();
        foreach (var kv in Providers)
            ProviderApiKeys[kv.Key] = kv.Value?.ApiKey ?? "";
    }

    /// <summary>
    /// API key from Settings, else from a well-known environment variable for the provider.
    /// Environment keys are never written back to settings.json.
    /// </summary>
    public string GetEffectiveApiKey()
    {
        if (!string.IsNullOrWhiteSpace(ApiKey))
            return ApiKey.Trim();

        return GetEnvironmentApiKey(Provider, Endpoint) ?? "";
    }

    /// <summary>
    /// Returns the env var name that would supply a key when ApiKey is empty, or null if none applies.
    /// </summary>
    public string? GetEnvironmentApiKeySource()
    {
        if (!string.IsNullOrWhiteSpace(ApiKey))
            return null;

        return Provider switch
        {
            LlmProvider.OpenRouter => FirstPresentEnvName("OPENROUTER_API_KEY", "OPENAI_API_KEY"),
            LlmProvider.Anthropic => FirstPresentEnvName("ANTHROPIC_API_KEY"),
            LlmProvider.GitHubCopilot => FirstPresentEnvName("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"),
            LlmProvider.OpenAiCompatible when IsOpenRouterEndpoint(Endpoint) =>
                FirstPresentEnvName("OPENROUTER_API_KEY", "OPENAI_API_KEY"),
            LlmProvider.OpenAiCompatible => FirstPresentEnvName("OPENAI_API_KEY"),
            _ => null
        };
    }

    public static string? GetEnvironmentApiKey(LlmProvider provider, string endpoint)
    {
        return provider switch
        {
            LlmProvider.OpenRouter => FirstPresentEnv("OPENROUTER_API_KEY", "OPENAI_API_KEY"),
            LlmProvider.Anthropic => FirstPresentEnv("ANTHROPIC_API_KEY"),
            LlmProvider.GitHubCopilot => FirstPresentEnv("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"),
            LlmProvider.OpenAiCompatible when IsOpenRouterEndpoint(endpoint) =>
                FirstPresentEnv("OPENROUTER_API_KEY", "OPENAI_API_KEY"),
            LlmProvider.OpenAiCompatible => FirstPresentEnv("OPENAI_API_KEY"),
            _ => null
        };
    }

    /// <summary>
    /// Returns the effective chat completions URL for the configured provider.
    /// </summary>
    public string GetCompletionsUrl()
    {
        var baseUrl = Endpoint.TrimEnd('/');
        return Provider switch
        {
            LlmProvider.Anthropic => baseUrl.Contains("/v1") ? $"{baseUrl}/messages" : $"{baseUrl}/v1/messages",
            LlmProvider.GitHubCopilot => "https://api.githubcopilot.com/chat/completions",
            _ => baseUrl.Contains("/chat/completions") ? baseUrl : $"{baseUrl}/chat/completions"
        };
    }

    /// <summary>
    /// Base URL for OpenAI-compatible <c>/models</c> listing (null when not applicable).
    /// </summary>
    public string? GetModelsListUrl()
    {
        if (Provider is LlmProvider.Anthropic or LlmProvider.GitHubCopilot)
            return null;

        var baseUrl = Endpoint.TrimEnd('/');
        if (baseUrl.EndsWith("/chat/completions", StringComparison.OrdinalIgnoreCase))
            baseUrl = baseUrl[..^"/chat/completions".Length].TrimEnd('/');

        return $"{baseUrl}/models";
    }

    public static string DefaultEndpoint(LlmProvider provider) => provider switch
    {
        LlmProvider.OpenRouter => OpenRouterEndpoint,
        LlmProvider.Anthropic => AnthropicEndpoint,
        LlmProvider.GitHubCopilot => CopilotEndpoint,
        _ => OpenAiEndpoint
    };

    public static string DefaultModel(LlmProvider provider) => provider switch
    {
        LlmProvider.OpenRouter => DefaultOpenRouterModel,
        LlmProvider.Anthropic => DefaultAnthropicModel,
        LlmProvider.GitHubCopilot => DefaultCopilotModel,
        _ => DefaultOpenAiModel
    };

    public static bool IsLocalEndpoint(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
            return false;

        if (!Uri.TryCreate(endpoint.Trim(), UriKind.Absolute, out var uri))
            return false;

        if (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            uri.Host is "127.0.0.1" or "::1" or "[::1]")
            return true;

        // Private LAN hosts commonly used for LM Studio / vLLM
        if (System.Net.IPAddress.TryParse(uri.Host, out var ip))
        {
            var bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                if (bytes[0] == 10) return true;
                if (bytes[0] == 192 && bytes[1] == 168) return true;
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            }
        }

        return false;
    }

    public static bool IsOpenRouterEndpoint(string? endpoint) =>
        !string.IsNullOrWhiteSpace(endpoint) &&
        endpoint.Contains("openrouter.ai", StringComparison.OrdinalIgnoreCase);

    public static bool IsKnownPresetEndpoint(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
            return true;

        var e = endpoint.Trim().TrimEnd('/');
        return e.Equals(OpenAiEndpoint, StringComparison.OrdinalIgnoreCase) ||
               e.Equals(OpenRouterEndpoint, StringComparison.OrdinalIgnoreCase) ||
               e.Equals(AnthropicEndpoint, StringComparison.OrdinalIgnoreCase) ||
               e.Equals(CopilotEndpoint, StringComparison.OrdinalIgnoreCase) ||
               e.Equals(OllamaEndpoint, StringComparison.OrdinalIgnoreCase) ||
               e.Equals("https://api.anthropic.com/v1", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsDefaultModel(string? model)
    {
        if (string.IsNullOrWhiteSpace(model))
            return true;

        return model is DefaultOpenAiModel or DefaultOpenRouterModel or DefaultAnthropicModel
            or DefaultOllamaModel or DefaultCopilotModel or "llama3" or "gpt-4o-mini" or "openai/gpt-4o-mini";
    }

    private static string? FirstPresentEnv(params string[] names)
    {
        foreach (var name in names)
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrWhiteSpace(value))
                return value.Trim();
        }
        return null;
    }

    private static string? FirstPresentEnvName(params string[] names)
    {
        foreach (var name in names)
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrWhiteSpace(value))
                return name;
        }
        return null;
    }
}
