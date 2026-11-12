namespace Trowser.Security;

/// <summary>
/// Severity and sensitivity classification for endpoint discovery results.
/// Used by playbooks and scanners to report all non-shell discoveries consistently.
/// </summary>
public static class EndpointDiscoveryClassifier
{
    private static readonly string[] HighSeverityTokens =
    [
        ".env", ".git/config", ".git/head", ".htpasswd", "backup.sql", "dump.sql",
        "db.sql", "database.sql", "credentials.json", "secrets.json", "id_rsa",
        "privatekey.pem", "server.key", ".aws/credentials", "wp-config.php"
    ];

    private static readonly string[] MediumSeverityTokens =
    [
        "admin", "debug", "phpinfo", "actuator", "swagger", "graphql", "api-docs",
        "openapi", "management", "metrics", "prometheus", "grafana", "kibana",
        "elmah", "trace.axd", "jolokia", "jmx-console", "phpmyadmin", "adminer",
        "server-status", "server-info", "pprof", "telescope", "horizon",
        "application-configuration", "internal/", "/rest/admin", "jenkinsfile",
        ".github/workflows", ".gitlab-ci.yml", "docker-compose",
        "nginx.conf", "/vendor", "/vendors", "node_modules", "directory listing"
    ];

    private static readonly string[] LowSeverityTokens =
    [
        "health", "healthcheck", "healthz", "ready", "live", "status", "metrics",
        "ftp", "package.json", "composer.json", "robots.txt", "sitemap",
        "well-known", "docs", "redoc", "graphiql", "playground"
    ];

    /// <summary>Classify severity for a discovered path (all discoveries should be reported).</summary>
    public static string ClassifySeverity(string? path, int statusCode, string? bodySnippet = null)
    {
        if (string.IsNullOrWhiteSpace(path)) return "info";

        // Bare redirects (login gates, SAML/OIDC IdP bounce, SPA catch-all) are not findings.
        // Existence of a path cannot be inferred from a uniform 302 — never elevate 3xx.
        if (statusCode is >= 300 and < 400)
            return "info";

        var p = path.ToLowerInvariant();
        var body = bodySnippet?.ToLowerInvariant() ?? "";

        // Access denied without readable content is not a leak — only 2xx (or denied with body evidence) elevates.
        if (statusCode is 401 or 403)
        {
            if (HighSeverityTokens.Any(t => p.Contains(t, StringComparison.Ordinal)))
                return SuggestsSecretLeakInBody(body) ? "medium" : "info";
            if (MediumSeverityTokens.Any(t => p.Contains(t, StringComparison.Ordinal)))
                return SuggestsSecretLeakInBody(body) ? "low" : "info";
            return "info";
        }

        if (HighSeverityTokens.Any(t => p.Contains(t, StringComparison.Ordinal)))
            return statusCode is >= 200 and < 300 ? "high" : "medium";

        if (MediumSeverityTokens.Any(t => p.Contains(t, StringComparison.Ordinal)))
            return statusCode is >= 200 and < 300 ? "medium" : "low";

        if (LowSeverityTokens.Any(t => p.Contains(t, StringComparison.Ordinal)))
            return statusCode is >= 200 and < 300 ? "low" : "info";

        if (statusCode is >= 200 and < 300)
        {
            if (body.Contains("password") || body.Contains("secret") || body.Contains("apikey"))
                return "medium";
            if (body.Contains("index of /") || body.Contains("directory listing")
                || body.Contains("<title>index of"))
                return "medium";
            return "low";
        }

        return "info";
    }

    private static bool SuggestsSecretLeakInBody(string body) =>
        !string.IsNullOrEmpty(body)
        && (body.Contains("root:", StringComparison.Ordinal)
            || body.Contains("password:", StringComparison.Ordinal)
            || body.Contains("BEGIN RSA PRIVATE KEY", StringComparison.Ordinal)
            || body.Contains("BEGIN OPENSSH PRIVATE KEY", StringComparison.Ordinal)
            || body.Contains("aws_access_key", StringComparison.Ordinal));

    /// <summary>Build a concise finding title for a discovered endpoint.</summary>
    public static string BuildTitle(string path, int statusCode)
    {
        var label = statusCode switch
        {
            >= 200 and < 300 => "accessible",
            401 => "auth required",
            403 => "forbidden",
            >= 300 and < 400 => "redirect",
            _ => $"HTTP {statusCode}"
        };
        return $"Discovered: {path} ({label})";
    }
}
