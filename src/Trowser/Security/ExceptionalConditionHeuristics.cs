using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Shared heuristics for fail-open and missing-parameter scans (OWASP A10).
/// </summary>
public static class ExceptionalConditionHeuristics
{
    private static readonly string[] CrashPatterns =
    [
        "NullPointerException", "NullReferenceException", "NullPointer",
        "java.lang.NullPointerException", "Traceback (most recent call last)",
        "at System.", "at java.", "at org.springframework",
        "Unhandled Exception", "Internal Server Error", "stack trace", "stacktrace",
        "SyntaxError:", "TypeError:", "ReferenceError:", "PHP Fatal error"
    ];

    private static readonly string[] ErrorBodyHints =
    [
        "\"error\"", "\"message\":\"error", "unauthorized", "forbidden", "invalid",
        "bad request", "validation failed", "not found"
    ];

    private static readonly Regex NpeFieldRegex = new(
        @"(?:NullPointerException|NullReferenceException).*?(?:field|property|column|parameter)\s+['""]?(\w+)['""]?|" +
        @"Cannot read propert(?:y|ies) ['""](\w+)['""]|" +
        @"undefined (?:property|field) ['""](\w+)['""]|" +
        @"missing (?:required )?(?:field|parameter|property) ['""](\w+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool IsDenyStatus(int status) =>
        status is 401 or 403 or 407;

    public static bool IsSuccessStatus(int status) =>
        status is >= 200 and < 300;

    public static bool LooksLikeErrorBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return true;
        if (body.Length < 40) return true;
        var lower = body.ToLowerInvariant();
        return ErrorBodyHints.Any(h => lower.Contains(h, StringComparison.Ordinal));
    }

    public static bool LooksLikeSensitiveBody(string? body) =>
        LooksLikeSensitiveBody(body, null, null, out _);

    public static bool LooksLikeSensitiveBody(
        string? body,
        string? contentType,
        string? contentEncoding,
        out string? decodeDetail)
    {
        decodeDetail = null;
        var norm = NormalizeResponseBody(body, contentType, contentEncoding);
        if (!norm.Decoded)
        {
            decodeDetail = norm.DecodeDetail ?? "body-not-decoded";
            return false;
        }

        body = norm.Text;
        if (string.IsNullOrWhiteSpace(body) || body.Length < 80) return false;
        if (HasCrashPattern(body)) return false;
        if (LooksLikeErrorBody(body) && body.Length < 200) return false;

        var trimmed = body.TrimStart();
        if (trimmed.StartsWith('[') && trimmed.Length > 100) return true;
        if (trimmed.StartsWith('{') && trimmed.Count(c => c == ':') >= 2) return true;
        if (trimmed.Contains("<html", StringComparison.OrdinalIgnoreCase) && body.Length > 500) return true;
        return body.Length >= 200;
    }

    public static bool HasCrashPattern(string? body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        return CrashPatterns.Any(p => body.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    public static bool BodiesSimilar(string? a, string? b) =>
        BodiesSimilar(a, b, null, null, null, null);

    public static bool BodiesSimilar(
        string? a,
        string? b,
        string? contentTypeA,
        string? contentEncodingA,
        string? contentTypeB,
        string? contentEncodingB)
    {
        var na = NormalizeResponseBody(a, contentTypeA, contentEncodingA);
        var nb = NormalizeResponseBody(b, contentTypeB, contentEncodingB);
        if (!na.Decoded || !nb.Decoded)
            return false;

        a = na.Text;
        b = nb.Text;
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
        if (string.Equals(a, b, StringComparison.Ordinal)) return true;

        if (na.JsonFingerprint != null && nb.JsonFingerprint != null)
            return string.Equals(na.JsonFingerprint, nb.JsonFingerprint, StringComparison.Ordinal);

        var lenA = a.Length;
        var lenB = b.Length;
        if (lenA == 0 || lenB == 0) return false;
        var ratio = (double)Math.Min(lenA, lenB) / Math.Max(lenA, lenB);
        if (ratio < 0.65) return false;

        var sampleA = a.Length > 400 ? a[..400] : a;
        var sampleB = b.Length > 400 ? b[..400] : b;
        var prefixA = sampleA.Length >= 80 ? sampleA[..80] : sampleA;
        var prefixB = sampleB.Length >= 80 ? sampleB[..80] : sampleB;
        return sampleA.Contains(prefixB, StringComparison.OrdinalIgnoreCase)
               || sampleB.Contains(prefixA, StringComparison.OrdinalIgnoreCase);
    }

    public sealed class NormalizedBody
    {
        public string Text { get; init; } = "";
        public bool Decoded { get; init; }
        public string? DecodeDetail { get; init; }
        public string? JsonFingerprint { get; init; }
    }

    public static NormalizedBody NormalizeResponseBody(string? body, string? contentType, string? contentEncoding)
    {
        if (string.IsNullOrEmpty(body))
            return new NormalizedBody { Text = "", Decoded = true };

        var bytes = TryGetRawBytes(body);
        var decodedText = DecodeBytes(bytes, contentEncoding) ?? body;
        if (LooksLikeBinary(decodedText) && decodedText == body && bytes.Length > 32)
        {
            return new NormalizedBody
            {
                Text = body,
                Decoded = false,
                DecodeDetail = "body-not-decoded"
            };
        }

        if (IsJsonContentType(contentType) || LooksLikeJson(decodedText))
        {
            try
            {
                using var doc = JsonDocument.Parse(decodedText);
                return new NormalizedBody
                {
                    Text = decodedText,
                    Decoded = true,
                    JsonFingerprint = JsonStructureFingerprint(doc.RootElement)
                };
            }
            catch
            {
                // fall through — treat as plain text
            }
        }

        return new NormalizedBody { Text = decodedText, Decoded = true };
    }

    private static byte[] TryGetRawBytes(string body)
    {
        try
        {
            return Convert.FromBase64String(body);
        }
        catch
        {
            return Encoding.UTF8.GetBytes(body);
        }
    }

    private static string? DecodeBytes(byte[] bytes, string? contentEncoding)
    {
        if (bytes.Length == 0) return "";
        var enc = contentEncoding?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            ?? [];
        try
        {
            foreach (var e in enc.Reverse())
            {
                bytes = e.ToLowerInvariant() switch
                {
                    "gzip" or "x-gzip" => DecompressGzip(bytes),
                    "deflate" => DecompressDeflate(bytes),
                    "br" or "brotli" => DecompressBrotli(bytes),
                    _ => bytes
                };
            }
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return null;
        }
    }

    private static byte[] DecompressGzip(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzip.CopyTo(output);
        return output.ToArray();
    }

    private static byte[] DecompressDeflate(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        deflate.CopyTo(output);
        return output.ToArray();
    }

    private static byte[] DecompressBrotli(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var brotli = new BrotliStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        brotli.CopyTo(output);
        return output.ToArray();
    }

    private static bool LooksLikeBinary(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        var sample = text.Length > 200 ? text[..200] : text;
        var nonPrintable = sample.Count(c =>
            (c < 32 && c != '\r' && c != '\n' && c != '\t') || (c > 126 && c < 160));
        return nonPrintable > sample.Length / 4;
    }

    private static bool IsJsonContentType(string? contentType) =>
        contentType != null && contentType.Contains("json", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeJson(string text)
    {
        var t = text.TrimStart();
        return t.StartsWith('{') || t.StartsWith('[');
    }

    private static string JsonStructureFingerprint(JsonElement root)
    {
        return root.ValueKind switch
        {
            JsonValueKind.Object => "obj:" + string.Join(",", root.EnumerateObject()
                .Select(p => p.Name + ":" + JsonStructureFingerprint(p.Value))
                .OrderBy(s => s, StringComparer.Ordinal)),
            JsonValueKind.Array => "arr:" + root.GetArrayLength(),
            JsonValueKind.String => "str",
            JsonValueKind.Number => "num",
            JsonValueKind.True or JsonValueKind.False => "bool",
            JsonValueKind.Null => "null",
            _ => root.ValueKind.ToString()
        };
    }

    public static List<string> ExtractNullFieldHints(string? body)
    {
        var hints = new List<string>();
        if (string.IsNullOrEmpty(body)) return hints;

        foreach (Match m in NpeFieldRegex.Matches(body))
        {
            for (var i = 1; i < m.Groups.Count; i++)
            {
                var g = m.Groups[i].Value;
                if (!string.IsNullOrWhiteSpace(g) && g.Length is >= 2 and <= 40)
                    hints.Add(g);
            }
        }

        return hints.Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToList();
    }

    public static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
