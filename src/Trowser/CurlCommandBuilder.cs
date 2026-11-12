using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Trowser;

/// <summary>
/// Builds a pasteable curl command from HTTP Request Editor fields.
/// The clipboard form is one bash line (Chrome DevTools style): single-quoted
/// arguments with <c>'\''</c> for embedded apostrophes. Browser headers that do
/// not change the response are omitted. JSON bodies are compacted.
/// </summary>
internal static class CurlCommandBuilder
{
    /// <summary>
    /// Hop-by-hop and browser chrome. Kept headers are the ones that can change
    /// the response: Cookie, Authorization, Content-Type, Accept, and anything
    /// application-specific.
    /// </summary>
    private static readonly HashSet<string> NoiseHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Accept-Encoding",
        "Accept-Language",
        "Cache-Control",
        "Connection",
        "Content-Length",
        "DNT",
        "Keep-Alive",
        "Origin",
        "Pragma",
        "Priority",
        "Proxy-Connection",
        "Referer",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Upgrade-Insecure-Requests",
        "User-Agent"
    };

    private static readonly JsonSerializerOptions CompactJson = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// Unquoted curl arguments (excluding the executable). Suitable for
    /// <see cref="System.Diagnostics.ProcessStartInfo.ArgumentList"/>.
    /// </summary>
    public static List<string> BuildArguments(
        string method,
        string url,
        IReadOnlyDictionary<string, string>? headers,
        string? body,
        bool followRedirects = false)
    {
        if (string.IsNullOrWhiteSpace(url))
            throw new ArgumentException("URL is required.", nameof(url));

        var verb = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();
        var args = new List<string>();

        if (followRedirects)
            args.Add("--location");

        args.Add("-X");
        args.Add(verb);

        foreach (var (name, value) in SignificantHeaders(headers, url))
        {
            args.Add("-H");
            args.Add($"{name}: {value}");
        }

        if (!string.IsNullOrEmpty(body))
        {
            args.Add("--data-raw");
            args.Add(body);
        }

        if (url.StartsWith('-'))
        {
            args.Add("--url");
            args.Add(url);
        }
        else
        {
            args.Add(url);
        }

        return args;
    }

    /// <summary>One-line curl command for the clipboard (bash).</summary>
    public static string ToCommandLine(
        string method,
        string url,
        IReadOnlyDictionary<string, string>? headers,
        string? body,
        bool followRedirects = false)
    {
        var flatUrl = StripNewlines(url.Trim());
        if (flatUrl.Length == 0)
            throw new ArgumentException("URL is required.", nameof(url));

        var flatBody = string.IsNullOrEmpty(body) ? null : FlattenBody(body);
        var hasBody = !string.IsNullOrEmpty(flatBody);
        var verb = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();

        var parts = new List<string> { "curl", BashQuote(flatUrl) };

        if (followRedirects)
            parts.Add("--location");

        if (IncludeMethodFlag(verb, hasBody))
        {
            parts.Add("-X");
            parts.Add(verb);
        }

        foreach (var (name, value) in SignificantHeaders(headers, flatUrl))
        {
            parts.Add("-H");
            parts.Add(BashQuote(name + ": " + value));
        }

        if (hasBody)
        {
            parts.Add("--data-raw");
            parts.Add(BashQuote(flatBody!));
        }

        return string.Join(" ", parts);
    }

    /// <summary>POST with a body is curl's default, and GET without a body needs no <c>-X</c>.</summary>
    internal static bool IncludeMethodFlag(string method, bool hasBody)
    {
        if (hasBody)
            return !method.Equals("POST", StringComparison.OrdinalIgnoreCase);
        return !method.Equals("GET", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsNoiseHeader(string name, string value, string url)
    {
        if (name.Length == 0 || name.StartsWith(':'))
            return true;
        if (name.StartsWith("sec-ch-", StringComparison.OrdinalIgnoreCase))
            return true;
        if (name.StartsWith("Sec-Fetch-", StringComparison.OrdinalIgnoreCase))
            return true;
        if (NoiseHeaders.Contains(name))
            return true;
        if (name.Equals("Host", StringComparison.OrdinalIgnoreCase) && HostMatchesUrl(value, url))
            return true;
        return false;
    }

    /// <summary>
    /// Compacts JSON (pretty-print in the editor stays equivalent) or strips CR/LF
    /// so the body stays one argument.
    /// </summary>
    internal static string FlattenBody(string body)
    {
        if (TryCompactJson(body, out var compact))
            return compact;
        return StripNewlines(body);
    }

    internal static bool TryCompactJson(string body, out string compact)
    {
        compact = body;
        var trimmed = body.AsSpan().TrimStart();
        if (trimmed.IsEmpty || (trimmed[0] != '{' && trimmed[0] != '['))
            return false;
        try
        {
            using var doc = JsonDocument.Parse(body);
            compact = JsonSerializer.Serialize(doc.RootElement, CompactJson);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>Bash single quotes. Embedded apostrophes use <c>'\''</c>.</summary>
    internal static string BashQuote(string value)
    {
        if (!value.Contains('\''))
            return "'" + value + "'";

        var sb = new StringBuilder(value.Length + 4);
        sb.Append('\'');
        foreach (var c in value)
        {
            if (c == '\'')
                sb.Append("'\\''");
            else
                sb.Append(c);
        }

        sb.Append('\'');
        return sb.ToString();
    }

    internal static string StripNewlines(string value) =>
        value.Replace("\r", "", StringComparison.Ordinal)
             .Replace("\n", "", StringComparison.Ordinal);

    private static List<(string Name, string Value)> SignificantHeaders(
        IReadOnlyDictionary<string, string>? headers,
        string url)
    {
        var kept = new List<(string Name, string Value)>();
        if (headers == null)
            return kept;

        foreach (var kv in headers)
        {
            var name = kv.Key.Trim();
            if (IsNoiseHeader(name, kv.Value, url))
                continue;
            kept.Add((name, StripNewlines(kv.Value)));
        }
        return kept;
    }

    private static bool HostMatchesUrl(string hostHeader, string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        var host = hostHeader.Trim();
        if (host.Equals(uri.Host, StringComparison.OrdinalIgnoreCase))
            return true;
        if (host.Equals(uri.Authority, StringComparison.OrdinalIgnoreCase))
            return true;
        return host.Equals($"{uri.Host}:{uri.Port}", StringComparison.OrdinalIgnoreCase);
    }
}
