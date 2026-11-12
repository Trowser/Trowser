using System.IO;
using System.Text.RegularExpressions;

namespace Trowser.Automation;

/// <summary>
/// Heuristics for saving top-level navigations to non-HTML resources when WebView2 does not raise
/// <see cref="Microsoft.Web.WebView2.Core.CoreWebView2.DownloadStarting"/> (e.g. direct .yaml URLs).
/// </summary>
internal static class DocumentDownloadHeuristics
{
    private static readonly HashSet<string> DownloadExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".yaml", ".yml", ".json", ".xml", ".csv", ".tsv", ".txt", ".md", ".markdown",
        ".bin", ".dat", ".zip", ".gz", ".tar", ".7z", ".rar", ".pdf",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".sql", ".log", ".conf", ".config", ".ini", ".properties",
        ".wasm", ".apk", ".msi", ".exe", ".dmg", ".pkg",
        ".openapi", ".swagger", ".har", ".pem", ".crt", ".cer", ".key"
    };

    private static readonly HashSet<string> HtmlExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".html", ".htm", ".asp", ".aspx", ".php", ".jsp", ".cshtml", ".vue"
    };

    private static readonly Regex ContentDispositionFilename = new(
        @"filename\*=UTF-8''([^;]+)|filename=""([^""]+)""|filename=([^;\s]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static bool ShouldTreatDirectNavigationAsDownload(
        string url,
        IReadOnlyDictionary<string, string> headers)
    {
        if (TryGetHeader(headers, "Content-Disposition", out var cd) &&
            cd.Contains("attachment", StringComparison.OrdinalIgnoreCase))
            return true;

        if (TryGetContentType(headers, out var mime))
        {
            if (mime.Contains("text/html", StringComparison.OrdinalIgnoreCase))
                return false;

            if (mime.Contains("application/octet-stream", StringComparison.OrdinalIgnoreCase))
                return true;

            if (mime.Contains("application/zip", StringComparison.OrdinalIgnoreCase) ||
                mime.Contains("application/pdf", StringComparison.OrdinalIgnoreCase) ||
                mime.Contains("application/gzip", StringComparison.OrdinalIgnoreCase) ||
                mime.Contains("application/x-yaml", StringComparison.OrdinalIgnoreCase) ||
                mime.Contains("application/yaml", StringComparison.OrdinalIgnoreCase) ||
                mime.Contains("text/yaml", StringComparison.OrdinalIgnoreCase) ||
                mime.Contains("application/json", StringComparison.OrdinalIgnoreCase) ||
                mime.Contains("application/xml", StringComparison.OrdinalIgnoreCase) ||
                mime.Contains("text/csv", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        var ext = Path.GetExtension(GetPathFromUrl(url));
        if (string.IsNullOrEmpty(ext))
            return false;
        if (HtmlExtensions.Contains(ext))
            return false;

        return DownloadExtensions.Contains(ext);
    }

    public static bool UrlsEquivalent(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!Uri.TryCreate(a, UriKind.Absolute, out var ua) ||
            !Uri.TryCreate(b, UriKind.Absolute, out var ub))
            return false;

        return ua.Scheme.Equals(ub.Scheme, StringComparison.OrdinalIgnoreCase) &&
               ua.Host.Equals(ub.Host, StringComparison.OrdinalIgnoreCase) &&
               ua.Port == ub.Port &&
               string.Equals(
                   ua.AbsolutePath.TrimEnd('/'),
                   ub.AbsolutePath.TrimEnd('/'),
                   StringComparison.OrdinalIgnoreCase);
    }

    public static string ResolveSuggestedFileName(string url, IReadOnlyDictionary<string, string> headers)
    {
        if (TryGetHeader(headers, "Content-Disposition", out var cd))
        {
            var m = ContentDispositionFilename.Match(cd);
            if (m.Success)
            {
                var raw = m.Groups[1].Success ? m.Groups[1].Value
                    : m.Groups[2].Success ? m.Groups[2].Value
                    : m.Groups[3].Value;
                try
                {
                    raw = Uri.UnescapeDataString(raw.Trim());
                }
                catch { /* use raw */ }

                var name = Path.GetFileName(raw);
                if (!string.IsNullOrWhiteSpace(name))
                    return SanitizeFileName(name);
            }
        }

        var fromUrl = Path.GetFileName(GetPathFromUrl(url));
        if (!string.IsNullOrWhiteSpace(fromUrl))
            return SanitizeFileName(fromUrl);

        return "download.bin";
    }

    public static string SanitizeFileName(string suggested)
    {
        var safe = string.Join("_", suggested.Split(Path.GetInvalidFileNameChars(),
            StringSplitOptions.RemoveEmptyEntries));
        return string.IsNullOrWhiteSpace(safe) ? "download.bin" : safe;
    }

    public static string BuildDestinationPath(string directory, string suggestedFileName)
    {
        var safeName = SanitizeFileName(suggestedFileName);
        return Path.Combine(directory, $"{DateTime.UtcNow:yyyyMMddHHmmssfff}_{safeName}");
    }

    private static string GetPathFromUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.Split('?')[0].Split('#')[0];

        return uri.AbsolutePath;
    }

    private static bool TryGetContentType(IReadOnlyDictionary<string, string> headers, out string mime)
    {
        mime = "";
        if (!TryGetHeader(headers, "Content-Type", out var raw))
            return false;
        mime = raw.Split(';')[0].Trim();
        return mime.Length > 0;
    }

    private static bool TryGetHeader(IReadOnlyDictionary<string, string> headers, string name, out string value)
    {
        foreach (var kv in headers)
        {
            if (!kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                continue;
            value = kv.Value;
            return true;
        }

        value = "";
        return false;
    }
}
