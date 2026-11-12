using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Trowser.Chat;

/// <summary>
/// GitHub Copilot authentication: resolve a GitHub host (github.com or Enterprise),
/// obtain a GitHub token, exchange it for a Copilot session, and pick the completions URL.
///
/// github.com tokens must be exchanged at api.github.com. GitHub Enterprise Cloud with
/// data residency (*.ghe.com) and GHES tokens are rejected there with HTTP 401
/// "Bad credentials" — they must be exchanged on the enterprise API host instead.
/// </summary>
public static class CopilotAuth
{
    public const string PublicApiHost = "github.com";
    public const string PublicCompletionsOrigin = "https://api.githubcopilot.com";
    public const string CopilotCliUserAgent = "GithubCopilot/1.155.0";

    /// <summary>
    /// Copilot CLI writes JSONC (<c>//</c> comments) to <c>~/.copilot/config.json</c>.
    /// </summary>
    private static readonly JsonDocumentOptions CopilotCliJsonOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public sealed record Session(string Token, DateTimeOffset ExpiresAt, string CompletionsUrl);

    public static string NormalizeHost(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return PublicApiHost;

        var raw = value.Trim();
        if (Uri.TryCreate(raw, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            raw = uri.Host;
        }
        else
        {
            raw = raw.Trim().TrimEnd('/');
            var slash = raw.IndexOf('/');
            if (slash > 0)
                raw = raw[..slash];
        }

        return string.IsNullOrWhiteSpace(raw) ? PublicApiHost : raw.Trim().ToLowerInvariant();
    }

    public static bool IsPublicGitHub(string host) =>
        NormalizeHost(host) is PublicApiHost or "www.github.com" or "api.github.com";

    public static bool IsGheCloudDataResidency(string host)
    {
        var h = NormalizeHost(host);
        return h.EndsWith(".ghe.com", StringComparison.Ordinal) &&
               !h.Equals("ghe.com", StringComparison.Ordinal);
    }

    public static bool LooksLikeCopilotCompletionsOrigin(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
            return false;

        var e = endpoint.Trim().TrimEnd('/').ToLowerInvariant();
        return e.Contains("githubcopilot.com", StringComparison.Ordinal) ||
               e.Contains("copilot-api.", StringComparison.Ordinal) ||
               e.Contains("copilot.githubusercontent.com", StringComparison.Ordinal);
    }

    /// <summary>
    /// Settings → env (COPILOT_GH_HOST, GH_HOST) → Copilot CLI last login → gh hosts.yml → github.com.
    /// Endpoint is used only when it looks like a GitHub host rather than the Copilot completions API.
    /// </summary>
    public static string ResolveGitHubHost(LlmSettings settings)
    {
        if (!string.IsNullOrWhiteSpace(settings.GitHubHost))
            return NormalizeHost(settings.GitHubHost);

        var envHost = FirstPresentEnv("COPILOT_GH_HOST", "GH_HOST");
        if (!string.IsNullOrWhiteSpace(envHost))
            return NormalizeHost(envHost);

        if (!string.IsNullOrWhiteSpace(settings.Endpoint) &&
            !LooksLikeCopilotCompletionsOrigin(settings.Endpoint) &&
            !LlmSettings.IsKnownPresetEndpoint(settings.Endpoint))
        {
            return NormalizeHost(settings.Endpoint);
        }

        var copilotHost = TryReadCopilotCliHost();
        if (!string.IsNullOrWhiteSpace(copilotHost))
            return NormalizeHost(copilotHost);

        var ghHost = TryReadGhCliHost();
        if (!string.IsNullOrWhiteSpace(ghHost))
            return NormalizeHost(ghHost);

        return PublicApiHost;
    }

    public static string GetTokenExchangeUrl(string host)
    {
        host = NormalizeHost(host);
        if (IsPublicGitHub(host))
            return "https://api.github.com/copilot_internal/v2/token";
        if (IsGheCloudDataResidency(host))
            return $"https://api.{host}/copilot_internal/v2/token";
        return $"https://{host}/api/v3/copilot_internal/v2/token";
    }

    public static string GetCopilotUserUrl(string host)
    {
        host = NormalizeHost(host);
        if (IsPublicGitHub(host))
            return "https://api.github.com/copilot_internal/user";
        if (IsGheCloudDataResidency(host))
            return $"https://api.{host}/copilot_internal/user";
        return $"https://{host}/api/v3/copilot_internal/user";
    }

    public static string GetDefaultCompletionsOrigin(string host)
    {
        host = NormalizeHost(host);
        if (IsGheCloudDataResidency(host))
            return $"https://copilot-api.{host}";
        return PublicCompletionsOrigin;
    }

    public static string CompletionsUrlFromOrigin(string origin)
    {
        var baseUrl = origin.Trim().TrimEnd('/');
        if (baseUrl.EndsWith("/chat/completions", StringComparison.OrdinalIgnoreCase))
            return baseUrl;
        return $"{baseUrl}/chat/completions";
    }

    public static string ModelsUrlFromSession(Session session)
    {
        var completions = session.CompletionsUrl.TrimEnd('/');
        const string suffix = "/chat/completions";
        var origin = completions.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
            ? completions[..^suffix.Length]
            : completions;
        return $"{origin.TrimEnd('/')}/models";
    }

    public static async Task<Session> CreateSessionAsync(
        HttpClient http, LlmSettings settings, CancellationToken ct,
        string? preferredModel = null)
    {
        var host = ResolveGitHubHost(settings);
        var tokens = await ResolveGitHubTokensAsync(settings, host, ct).ConfigureAwait(false);
        if (tokens.Count == 0)
        {
            throw new Exception(
                "GitHub Copilot needs a token from Copilot CLI, GitHub CLI, or Settings. " +
                "Run `copilot login` (use `--host` for GitHub Enterprise) or `gh auth login`, " +
                "or set COPILOT_GITHUB_TOKEN.");
        }

        Session? fallback = null;
        Exception? lastError = null;
        foreach (var token in tokens)
        {
            try
            {
                var session = await CreateSessionWithTokenAsync(http, host, token, ct).ConfigureAwait(false);
                fallback ??= session;
                if (string.IsNullOrWhiteSpace(preferredModel))
                    return session;

                var models = await TryListChatModelIdsAsync(http, session, ct).ConfigureAwait(false);
                if (models.Count == 0 ||
                    models.Contains(preferredModel, StringComparer.OrdinalIgnoreCase))
                    return session;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                lastError = ex;
            }
        }

        if (fallback != null)
            return fallback;

        throw lastError ?? new Exception("Copilot authentication failed.");
    }

    /// <summary>
    /// Chat-completions model ids from every available GitHub token (Copilot CLI and gh often
    /// expose different catalogs). Embeddings and /responses-only models are omitted.
    /// </summary>
    public static async Task<IReadOnlyList<string>> ListChatModelsAsync(
        HttpClient http, LlmSettings settings, CancellationToken ct)
    {
        var host = ResolveGitHubHost(settings);
        var tokens = await ResolveGitHubTokensAsync(settings, host, ct).ConfigureAwait(false);
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var token in tokens)
        {
            try
            {
                var session = await CreateSessionWithTokenAsync(http, host, token, ct).ConfigureAwait(false);
                foreach (var id in await TryListChatModelIdsAsync(http, session, ct).ConfigureAwait(false))
                    ids.Add(id);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                TrowserLog.Warn($"Copilot model listing skipped a token: {ex.Message}");
            }
        }

        if (ids.Count == 0)
            return Array.Empty<string>();

        return SortCopilotModelIds(ids);
    }

    public static async Task<string> ResolveGitHubTokenAsync(
        LlmSettings settings, string host, CancellationToken ct)
    {
        var tokens = await ResolveGitHubTokensAsync(settings, host, ct).ConfigureAwait(false);
        if (tokens.Count == 0)
        {
            throw new Exception(
                "GitHub Copilot needs a token from Copilot CLI, GitHub CLI, or Settings. " +
                "Run `copilot login` (use `--host` for GitHub Enterprise) or `gh auth login`, " +
                "or set COPILOT_GITHUB_TOKEN.");
        }

        return tokens[0];
    }

    private static async Task<List<string>> ResolveGitHubTokensAsync(
        LlmSettings settings, string host, CancellationToken ct)
    {
        var tokens = new List<string>();
        void Add(string? token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return;
            token = token.Trim();
            if (!tokens.Contains(token, StringComparer.Ordinal))
                tokens.Add(token);
        }

        Add(settings.ApiKey);
        Add(FirstPresentEnv("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"));

        // gh CLI has the current Copilot Business/Enterprise chat catalog (Claude Sonnet 5, …).
        // Copilot CLI's stored OAuth app often only lists legacy GPT-4o models.
        try { Add(await GetGhCliTokenAsync(host, ct).ConfigureAwait(false)); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            TrowserLog.Warn($"gh auth token unavailable: {ex.Message}");
        }

        Add(TryReadCopilotCliToken(host));
        return tokens;
    }

    private static async Task<Session> CreateSessionWithTokenAsync(
        HttpClient http, string host, string githubToken, CancellationToken ct)
    {
        if (IsGheCloudDataResidency(host))
        {
            var direct = await TryDirectBearerSessionAsync(http, githubToken, host, ct).ConfigureAwait(false);
            if (direct != null)
                return direct;
        }

        var exchangeUrl = GetTokenExchangeUrl(host);
        using var request = new HttpRequestMessage(HttpMethod.Get, exchangeUrl);
        ApplyGitHubTokenHeaders(request, githubToken);

        using var response = await http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (response.IsSuccessStatusCode)
            return ParseSession(body, host);

        var status = (int)response.StatusCode;
        if (status is 403 or 404)
        {
            var direct = await TryDirectBearerSessionAsync(http, githubToken, host, ct).ConfigureAwait(false);
            if (direct != null)
                return direct;
        }

        throw new Exception(FormatExchangeError(status, exchangeUrl, host, body));
    }

    private static async Task<List<string>> TryListChatModelIdsAsync(
        HttpClient http, Session session, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ModelsUrlFromSession(session));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session.Token);
            request.Headers.UserAgent.ParseAdd(CopilotCliUserAgent);
            request.Headers.TryAddWithoutValidation("Editor-Version", "vscode/1.95.0");

            using var response = await http.SendAsync(request, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                return [];

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return ParseCopilotChatModelIds(json);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            TrowserLog.Warn($"Copilot /models failed: {ex.Message}");
            return [];
        }
    }

    internal static List<string> ParseCopilotChatModelIds(string json)
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
                if (!item.TryGetProperty("id", out var idEl))
                    continue;
                var id = idEl.GetString();
                if (string.IsNullOrWhiteSpace(id))
                    continue;
                if (!IsCopilotChatCompletionsModel(id, item))
                    continue;
                if (!ids.Contains(id, StringComparer.OrdinalIgnoreCase))
                    ids.Add(id);
            }
        }
        catch (JsonException)
        {
            return ids;
        }

        return ids;
    }

    private static bool IsCopilotChatCompletionsModel(string id, JsonElement item)
    {
        if (id.Contains("embedding", StringComparison.OrdinalIgnoreCase) ||
            id.Contains("compaction", StringComparison.OrdinalIgnoreCase))
            return false;

        if (item.TryGetProperty("policy", out var policy) &&
            policy.ValueKind == JsonValueKind.Object &&
            policy.TryGetProperty("state", out var stateEl))
        {
            var state = stateEl.GetString();
            if (state is "disabled" or "blocked")
                return false;
        }

        if (item.TryGetProperty("capabilities", out var caps) &&
            caps.ValueKind == JsonValueKind.Object &&
            caps.TryGetProperty("type", out var typeEl))
        {
            var type = typeEl.GetString();
            if (!string.IsNullOrEmpty(type) &&
                !type.Equals("chat", StringComparison.OrdinalIgnoreCase))
                return false;
        }

        if (!item.TryGetProperty("supported_endpoints", out var endpoints))
            return true;

        var allowed = false;
        var any = false;
        void Consider(string? endpoint)
        {
            if (string.IsNullOrWhiteSpace(endpoint))
                return;
            any = true;
            if (endpoint.Contains("/chat/completions", StringComparison.OrdinalIgnoreCase) ||
                endpoint.Contains("/v1/messages", StringComparison.OrdinalIgnoreCase))
                allowed = true;
        }

        switch (endpoints.ValueKind)
        {
            case JsonValueKind.Array:
                foreach (var ep in endpoints.EnumerateArray())
                    Consider(ep.GetString());
                break;
            case JsonValueKind.String:
                Consider(endpoints.GetString());
                break;
        }

        return !any || allowed;
    }

    private static List<string> SortCopilotModelIds(IEnumerable<string> ids)
    {
        var preferred = LlmSettings.DefaultCopilotModels;
        var set = new HashSet<string>(ids, StringComparer.OrdinalIgnoreCase);
        var ordered = new List<string>();
        foreach (var id in preferred)
        {
            if (set.Remove(id))
                ordered.Add(id);
        }

        ordered.AddRange(set.OrderBy(id => id, StringComparer.OrdinalIgnoreCase));
        return ordered;
    }

    internal static Session ParseSession(string json, string host)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var token = root.TryGetProperty("token", out var tokenEl) ? tokenEl.GetString() : null;
        if (string.IsNullOrWhiteSpace(token))
            throw new Exception("Copilot token exchange succeeded but returned no token.");

        var expires = DateTimeOffset.UtcNow.AddMinutes(50);
        if (root.TryGetProperty("expires_at", out var expEl))
        {
            if (expEl.ValueKind == JsonValueKind.Number && expEl.TryGetInt64(out var unix))
                expires = DateTimeOffset.FromUnixTimeSeconds(unix);
            else if (expEl.ValueKind == JsonValueKind.String &&
                     DateTimeOffset.TryParse(expEl.GetString(), out var parsed))
                expires = parsed;
        }

        var origin = GetDefaultCompletionsOrigin(host);
        if (root.TryGetProperty("endpoints", out var endpoints) &&
            endpoints.ValueKind == JsonValueKind.Object &&
            endpoints.TryGetProperty("api", out var apiEl))
        {
            var api = apiEl.GetString();
            if (!string.IsNullOrWhiteSpace(api) &&
                Uri.TryCreate(api.Trim(), UriKind.Absolute, out var apiUri) &&
                apiUri.Scheme == Uri.UriSchemeHttps)
            {
                origin = $"{apiUri.Scheme}://{apiUri.Authority}{apiUri.AbsolutePath}".TrimEnd('/');
            }
        }

        return new Session(token, expires, CompletionsUrlFromOrigin(origin));
    }

    private static async Task<Session?> TryDirectBearerSessionAsync(
        HttpClient http, string githubToken, string host, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, GetCopilotUserUrl(host));
            ApplyGitHubTokenHeaders(request, githubToken);
            using var response = await http.SendAsync(request, ct).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                return null;

            var origin = GetDefaultCompletionsOrigin(host);
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("endpoints", out var endpoints) &&
                    endpoints.ValueKind == JsonValueKind.Object &&
                    endpoints.TryGetProperty("api", out var apiEl))
                {
                    var api = apiEl.GetString();
                    if (!string.IsNullOrWhiteSpace(api) &&
                        Uri.TryCreate(api.Trim(), UriKind.Absolute, out var apiUri) &&
                        apiUri.Scheme == Uri.UriSchemeHttps)
                    {
                        origin = $"{apiUri.Scheme}://{apiUri.Authority}{apiUri.AbsolutePath}".TrimEnd('/');
                    }
                }
            }
            catch (JsonException)
            {
                // Keep the host-derived default origin.
            }

            return new Session(
                githubToken,
                DateTimeOffset.UtcNow.AddMinutes(50),
                CompletionsUrlFromOrigin(origin));
        }
        catch
        {
            return null;
        }
    }

    private static void ApplyGitHubTokenHeaders(HttpRequestMessage request, string githubToken)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("token", githubToken);
        request.Headers.UserAgent.ParseAdd(CopilotCliUserAgent);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.TryAddWithoutValidation("Editor-Version", "vscode/1.95.0");
        request.Headers.TryAddWithoutValidation("Editor-Plugin-Version", "copilot-chat/0.22.4");
    }

    public static void ApplyCompletionsHeaders(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation("Copilot-Integration-Id", "vscode-chat");
        request.Headers.TryAddWithoutValidation("Editor-Version", "vscode/1.95.0");
        request.Headers.TryAddWithoutValidation("Editor-Plugin-Version", "copilot-chat/0.22.4");
        request.Headers.UserAgent.ParseAdd(CopilotCliUserAgent);
    }

    private static string FormatExchangeError(int status, string exchangeUrl, string host, string body)
    {
        var detail = Truncate(body, 240).Replace('\r', ' ').Replace('\n', ' ');
        var hint = status == 401
            ? $"The GitHub token is not valid for this API host. Trowser used '{host}'. " +
              "For GitHub Enterprise set GitHub host in Settings (e.g. company.ghe.com) " +
              "or COPILOT_GH_HOST / GH_HOST. Confirm with `gh auth status` and `copilot login --host HOST`."
            : "Ensure your GitHub account has an active Copilot license on this host.";

        return $"Copilot token exchange failed (HTTP {status}) at {exchangeUrl}. {hint} {detail}";
    }

    private static async Task<string> GetGhCliTokenAsync(string host, CancellationToken ct)
    {
        try
        {
            var args = IsPublicGitHub(host)
                ? "auth token"
                : $"auth token --hostname {host}";

            var psi = new ProcessStartInfo("gh", args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi)
                ?? throw new Exception("Could not start gh CLI.");

            var output = await process.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await process.WaitForExitAsync(ct).ConfigureAwait(false);

            if (process.ExitCode != 0)
                throw new Exception("gh auth token returned a non-zero exit code.");

            var token = output.Trim();
            if (string.IsNullOrEmpty(token))
                throw new Exception("gh auth token returned an empty token.");

            return token;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new Exception(
                "GitHub Copilot needs a token from Copilot CLI, GitHub CLI, or Settings. " +
                "Run `copilot login` (use `--host` for GitHub Enterprise) or `gh auth login`, " +
                "or set COPILOT_GITHUB_TOKEN. " +
                $"({ex.Message})");
        }
    }

    private static string? TryReadCopilotCliHost()
    {
        try
        {
            var json = TryReadCopilotCliConfigJson();
            return json == null ? null : ReadCopilotCliLastLoggedInField(json, "host");
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Failed to read Copilot CLI host: {ex.Message}");
            return null;
        }
    }

    private static string? TryReadCopilotCliLogin()
    {
        try
        {
            var json = TryReadCopilotCliConfigJson();
            return json == null ? null : ReadCopilotCliLastLoggedInField(json, "login");
        }
        catch
        {
            return null;
        }
    }

    private static string? TryReadCopilotCliConfigJson()
    {
        var path = CopilotConfigPath();
        if (path == null || !File.Exists(path))
            return null;
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Reads <c>lastLoggedInUser.{field}</c> from Copilot CLI config.json (JSONC).
    /// </summary>
    internal static string? ReadCopilotCliLastLoggedInField(string json, string field)
    {
        if (string.IsNullOrWhiteSpace(json) || string.IsNullOrWhiteSpace(field))
            return null;

        using var doc = JsonDocument.Parse(json, CopilotCliJsonOptions);
        if (doc.RootElement.TryGetProperty("lastLoggedInUser", out var user) &&
            user.ValueKind == JsonValueKind.Object &&
            user.TryGetProperty(field, out var el))
        {
            return el.GetString();
        }

        return null;
    }

    private static string? TryReadGhCliHost()
    {
        foreach (var path in GhHostsPaths())
        {
            try
            {
                if (!File.Exists(path))
                    continue;

                string? first = null;
                foreach (var line in File.ReadLines(path))
                {
                    if (line.Length == 0 || line[0] is ' ' or '\t' or '#' or '-')
                        continue;
                    var trimmed = line.Trim();
                    if (!trimmed.EndsWith(':'))
                        continue;

                    var key = trimmed.TrimEnd(':').Trim().Trim('"');
                    if (key.Length == 0 || key.Contains(' '))
                        continue;

                    if (IsPublicGitHub(key))
                    {
                        first ??= key;
                        continue;
                    }

                    // Prefer an enterprise host when both github.com and GHE are present.
                    return key;
                }

                if (first != null)
                    return first;
            }
            catch (Exception ex)
            {
                TrowserLog.Warn($"Failed to read gh hosts.yml: {ex.Message}");
            }
        }

        return null;
    }

    private static string? TryReadCopilotCliToken(string host)
    {
        var login = TryReadCopilotCliLogin();
        foreach (var target in CopilotCliCredentialTargets(host, login))
        {
            var secret = CredentialStore.ReadGeneric(target);
            if (!string.IsNullOrWhiteSpace(secret))
                return secret.Trim();
        }

        foreach (var secret in CredentialStore.ReadGenericPrefix("copilot-cli"))
        {
            if (!string.IsNullOrWhiteSpace(secret))
                return secret.Trim();
        }

        return null;
    }

    private static IEnumerable<string> CopilotCliCredentialTargets(string host, string? login)
    {
        host = NormalizeHost(host);
        var hosts = new[]
        {
            host,
            "https://" + host,
            "https://" + host + "/"
        };

        foreach (var h in hosts.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            yield return $"copilot-cli/{h}";
            if (string.IsNullOrEmpty(login))
                continue;

            yield return $"copilot-cli/{h}:{login}";
            yield return $"copilot-cli/{h}/:{login}";
            yield return $"{h}:{login}.copilot-cli";
        }
    }

    private static string? CopilotConfigPath()
    {
        var home = Environment.GetEnvironmentVariable("COPILOT_HOME");
        if (!string.IsNullOrWhiteSpace(home))
            return Path.Combine(home.Trim(), "config.json");

        var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(user))
            return null;

        return Path.Combine(user, ".copilot", "config.json");
    }

    private static IEnumerable<string> GhHostsPaths()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!string.IsNullOrEmpty(appData))
            yield return Path.Combine(appData, "GitHub CLI", "hosts.yml");

        var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(user))
            yield return Path.Combine(user, ".config", "gh", "hosts.yml");
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

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) ? "" : s.Length <= max ? s : s[..max] + "…";

    private static class CredentialStore
    {
        private const int CredTypeGeneric = 1;

        public static string? ReadGeneric(string target)
        {
            if (!CredRead(target, CredTypeGeneric, 0, out var ptr))
                return null;

            try
            {
                var cred = Marshal.PtrToStructure<CREDENTIAL>(ptr);
                return BlobToString(cred.CredentialBlob, cred.CredentialBlobSize);
            }
            catch
            {
                return null;
            }
            finally
            {
                CredFree(ptr);
            }
        }

        public static IEnumerable<string> ReadGenericPrefix(string prefix)
        {
            if (!CredEnumerate(prefix + "*", 0, out var count, out var ptr) || ptr == IntPtr.Zero)
                yield break;

            try
            {
                for (var i = 0; i < count; i++)
                {
                    var credPtr = Marshal.ReadIntPtr(ptr, i * IntPtr.Size);
                    if (credPtr == IntPtr.Zero)
                        continue;

                    CREDENTIAL cred;
                    try { cred = Marshal.PtrToStructure<CREDENTIAL>(credPtr); }
                    catch { continue; }

                    var secret = BlobToString(cred.CredentialBlob, cred.CredentialBlobSize);
                    if (!string.IsNullOrWhiteSpace(secret))
                        yield return secret;
                }
            }
            finally
            {
                CredFree(ptr);
            }
        }

        private static string? BlobToString(IntPtr blob, int size)
        {
            if (blob == IntPtr.Zero || size <= 0)
                return null;

            var bytes = new byte[size];
            Marshal.Copy(blob, bytes, 0, size);

            // keytar / Copilot CLI store UTF-8; some Windows creds are UTF-16.
            if (size >= 2 && bytes[1] == 0)
            {
                var utf16 = Encoding.Unicode.GetString(bytes).TrimEnd('\0').Trim();
                if (!string.IsNullOrEmpty(utf16))
                    return utf16;
            }

            return Encoding.UTF8.GetString(bytes).TrimEnd('\0').Trim();
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr credentials);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern void CredFree(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }
    }
}
