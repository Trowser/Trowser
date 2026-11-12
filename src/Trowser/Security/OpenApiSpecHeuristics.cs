namespace Trowser.Security;

/// <summary>Detect OpenAPI/Swagger documents in HTTP bodies and URLs.</summary>
public static class OpenApiSpecHeuristics
{
    /// <summary>
    /// True when the path (not the host) looks like an OpenAPI document.
    /// A host such as <c>petstore3.swagger.io</c> must not qualify by itself.
    /// </summary>
    public static bool UrlLooksLikeSpecDocument(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        var pathAndQuery = url;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            pathAndQuery = uri.AbsolutePath + uri.Query;
        var u = pathAndQuery.ToLowerInvariant();
        return u.Contains("openapi", StringComparison.Ordinal)
               || u.Contains("swagger", StringComparison.Ordinal)
               || u.Contains("api-docs", StringComparison.Ordinal);
    }

    /// <summary>404/410 on a guessed spec URL is a miss, not a warning.</summary>
    public static bool IsExpectedSpecMiss(string? errorMessage)
    {
        if (string.IsNullOrEmpty(errorMessage)) return false;
        return errorMessage.Contains("HTTP 404", StringComparison.Ordinal)
               || errorMessage.Contains("HTTP 410", StringComparison.Ordinal);
    }

    /// <summary>Message when discovery loaded nothing. Mentions login only when a spec URL was actually rejected.</summary>
    public static string DescribeMissingSpec(IEnumerable<string>? warnings)
    {
        var authBlocked = warnings?.Any(w =>
            w.Contains("HTTP 401", StringComparison.Ordinal)
            || w.Contains("HTTP 403", StringComparison.Ordinal)) == true;
        return authBlocked
            ? "No OpenAPI/Swagger document loaded. A spec URL returned 401 or 403 — log in, then retry."
            : "No OpenAPI/Swagger document found. Open the Swagger UI so the spec is captured, or pass specUrls.";
    }

    public static bool BodyLooksLikeOpenApi(string? contentType, string body)
    {
        if (string.IsNullOrWhiteSpace(body) || body.Length < 40)
            return false;

        var trim = body.TrimStart();
        if (trim.StartsWith('{'))
        {
            return trim.Contains("\"paths\"", StringComparison.OrdinalIgnoreCase)
                   && (trim.Contains("\"openapi\"", StringComparison.OrdinalIgnoreCase)
                       || trim.Contains("\"swagger\"", StringComparison.OrdinalIgnoreCase));
        }

        if (trim.StartsWith("openapi:", StringComparison.OrdinalIgnoreCase)
            || trim.StartsWith("swagger:", StringComparison.OrdinalIgnoreCase))
        {
            return trim.Contains("paths:", StringComparison.OrdinalIgnoreCase);
        }

        var ct = contentType ?? "";
        if ((ct.Contains("yaml", StringComparison.OrdinalIgnoreCase)
             || ct.Contains("yml", StringComparison.OrdinalIgnoreCase))
            && trim.Contains("paths:", StringComparison.OrdinalIgnoreCase)
            && trim.Contains("openapi:", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    public static bool IsLikelyTruncatedJson(string body)
    {
        if (!body.TrimStart().StartsWith('{'))
            return false;
        try
        {
            using var _ = System.Text.Json.JsonDocument.Parse(body);
            return false;
        }
        catch (System.Text.Json.JsonException)
        {
            return true;
        }
    }

    /// <summary>URLs to try when the user is on Swagger UI HTML.</summary>
    public static IEnumerable<string> DeriveSpecUrlsFromSwaggerUiPage(Uri pageUri)
    {
        var path = pageUri.AbsolutePath;
        if (!path.Contains("swagger", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("api/index", StringComparison.OrdinalIgnoreCase)
            && !path.EndsWith("index.html", StringComparison.OrdinalIgnoreCase))
            yield break;

        var authority = pageUri.GetLeftPart(UriPartial.Authority);
        var dir = path.Contains('/')
            ? path[..path.LastIndexOf('/', path.Length - 1)]
            : "";

        foreach (var name in new[] { "swagger.json", "openapi.json", "v1/swagger.json", "swagger/v1/swagger.json" })
        {
            yield return authority + (string.IsNullOrEmpty(dir) ? "/" : dir + "/") + name;
        }

        if (path.EndsWith("index.html", StringComparison.OrdinalIgnoreCase))
        {
            var without = path[..^"index.html".Length];
            yield return authority + without + "swagger.json";
            yield return authority + without + "openapi.json";
        }
    }
}
