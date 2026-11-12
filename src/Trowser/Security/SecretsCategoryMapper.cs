namespace Trowser.Security;

/// <summary>
/// Maps granular secrets-harvest detector categories to VPX/chain taxonomy (A04 Crypto & Secrets).
/// </summary>
public static class SecretsCategoryMapper
{
    public static string ToVpxCategory(string? category, string? location = null)
    {
        var cat = (category ?? "").ToLowerInvariant();
        var loc = (location ?? "").ToLowerInvariant();

        return cat switch
        {
            "jwt-token" or "jwt-sensitive-claim" or "md5-password-hash-in-jwt"
                or "jwtinstorage" or "authtokeninstorage" or "bearertokeninstorage"
                => "token-in-storage",

            "api-key" or "bearer-token" or "password" or "aws-access-key" or "private-key"
                or "connection-string" or "secret-assignment" or "email-password-combo"
                or "hardcoded-credential" or "api-key-in-request" or "plaintext-password-in-transit"
                or "credit-card" or "secret" or "token"
                => "credential-exposure",

            "source-map-exposed" or "debug-mode-active" => "source-maps",

            _ when cat.Contains("jwt") || cat.Contains("token") || cat.Contains("bearer")
                => "token-in-storage",

            _ when cat.Contains("password") || cat.Contains("secret") || cat.Contains("credential")
                || cat.Contains("api-key") || cat.Contains("apikey") || cat.Contains("private-key")
                => "credential-exposure",

            _ when loc.Contains("localstorage") || loc.Contains("sessionstorage") || loc.Contains("storage")
                => "token-in-storage",

            _ when cat.Length > 0 => cat,
            _ => "credential-exposure"
        };
    }

    public static bool IsSecretLikeCategory(string? category) =>
        ToVpxCategory(category) is "credential-exposure" or "token-in-storage" or "sensitive-storage";
}
