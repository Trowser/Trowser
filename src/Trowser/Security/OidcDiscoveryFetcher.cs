using System.Net.Http;
using System.Text.Json;

namespace Trowser.Security;

/// <summary>
/// Fetches OIDC/OAuth authorization server metadata. Not all issuers publish
/// <c>/.well-known/openid-configuration</c>; failures are normal and callers should continue other checks.
/// </summary>
public static class OidcDiscoveryFetcher
{
    private static readonly HttpClient Http = new(new HttpClientHandler
    {
        AllowAutoRedirect = true,
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    })
    {
        Timeout = TimeSpan.FromSeconds(15)
    };

    public sealed class DiscoveryResult
    {
        public bool Found { get; init; }
        public JsonElement? Configuration { get; init; }
        public string ConfigurationUrl { get; init; } = "";
        public IReadOnlyList<string> AttemptedUrls { get; init; } = [];
        public string? LastError { get; init; }
    }

    public static IReadOnlyList<string> BuildDiscoveryUrls(string issuer)
    {
        var baseUrl = issuer.Trim().TrimEnd('/');
        return
        [
            $"{baseUrl}/.well-known/openid-configuration",
            $"{baseUrl}/.well-known/oauth-authorization-server",
            $"{baseUrl}/.well-known/openid-configuration/",
            $"{baseUrl}/.well-known/oauth-authorization-server/"
        ];
    }

    public static async Task<DiscoveryResult> TryFetchAsync(string issuer, int timeoutMs, CancellationToken ct = default)
    {
        var attempted = new List<string>();
        string? lastError = null;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);

        foreach (var url in BuildDiscoveryUrls(issuer).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            attempted.Add(url);
            try
            {
                using var resp = await Http.GetAsync(url, cts.Token);
                if (!resp.IsSuccessStatusCode)
                {
                    lastError = $"HTTP {(int)resp.StatusCode} for {url}";
                    continue;
                }

                var body = await resp.Content.ReadAsStringAsync(cts.Token);
                if (string.IsNullOrWhiteSpace(body) || body.TrimStart().StartsWith('<')) // HTML error page
                {
                    lastError = $"Non-JSON response from {url}";
                    continue;
                }

                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement.Clone();
                if (!LooksLikeDiscoveryDocument(root))
                {
                    lastError = $"Response from {url} is not OIDC/OAuth metadata";
                    continue;
                }

                return new DiscoveryResult
                {
                    Found = true,
                    Configuration = root,
                    ConfigurationUrl = url,
                    AttemptedUrls = attempted,
                    LastError = null
                };
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                lastError = $"{url}: {ex.Message}";
            }
        }

        return new DiscoveryResult
        {
            Found = false,
            AttemptedUrls = attempted,
            LastError = lastError
        };
    }

    private static bool LooksLikeDiscoveryDocument(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return false;
        return root.TryGetProperty("issuer", out _)
               || root.TryGetProperty("authorization_endpoint", out _)
               || root.TryGetProperty("token_endpoint", out _)
               || root.TryGetProperty("jwks_uri", out _);
    }

    public static string? GetString(JsonElement config, string property) =>
        config.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;
}
