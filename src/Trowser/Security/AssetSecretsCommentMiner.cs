using System.Text;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Mines HTML/JS comments and decoded blobs for secret-like signals and hidden URLs (recon).
/// Inspired by secret-scanning practice and OWASP secrets guidance; also influenced by pentest-ai <c>web.asset_secrets_scan</c>.
/// Hygiene keywords (TODO/localhost) stay low/info; real credential patterns are elevated by harvest heuristics.
/// </summary>
public static class AssetSecretsCommentMiner
{
    public sealed class CommentHit
    {
        public string Category { get; init; } = "";
        public string Source { get; init; } = "";
        public int Offset { get; init; }
        public string Snippet { get; init; } = "";
        public string? Decoded { get; init; }
    }

    private const int MinCommentLen = 30;
    private const int MaxCommentsPerBody = 40;
    private const int MaxBase64PerBody = 40;

    private static readonly Regex HtmlComment = new(
        @"<!--([\s\S]*?)-->",
        RegexOptions.Compiled, TimeSpan.FromSeconds(3));

    private static readonly Regex JsBlockComment = new(
        @"/\*([\s\S]*?)\*/",
        RegexOptions.Compiled, TimeSpan.FromSeconds(3));

    private static readonly Regex JsLineComment = new(
        @"//([^\n\r]+)",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex Base64Token = new(
        @"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])",
        RegexOptions.Compiled, TimeSpan.FromSeconds(3));

    private static readonly Regex HiddenUrlPattern = new(
        @"(?i)(/(?:secret|hidden|admin|debug|internal|private|dev|staging|backup)[/\w\-./]*)",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly string[] SecretKeywords =
    [
        "password", "apikey", "api_key", "secret", "token", "credential",
    ];

    private static readonly string[] HygieneKeywords =
    [
        "TODO:", "FIXME:", "HACK:", "XXX:", "BUG:", "OPTIMIZE:", "NOTE:",
        "staging", "localhost", "127.0.0.1", "password here", "changeme",
    ];

    public static List<CommentHit> ScanText(string text, string sourceLabel)
    {
        var hits = new List<CommentHit>();
        if (string.IsNullOrEmpty(text)) return hits;

        var commentCount = 0;
        foreach (Match m in HtmlComment.Matches(text))
        {
            if (++commentCount > MaxCommentsPerBody) break;
            ProcessComment(m.Groups[1].Value.Trim(), sourceLabel, "html-comment", m.Index, hits);
        }

        foreach (Match m in JsBlockComment.Matches(text))
        {
            if (++commentCount > MaxCommentsPerBody) break;
            var inner = m.Groups[1].Value.Trim();
            if (inner.Length >= MinCommentLen)
                ProcessComment(inner, sourceLabel, "js-block-comment", m.Index, hits);
        }

        foreach (Match m in JsLineComment.Matches(text))
        {
            if (++commentCount > MaxCommentsPerBody) break;
            var inner = m.Groups[1].Value.Trim();
            if (inner.Length >= MinCommentLen)
                ProcessComment(inner, sourceLabel, "js-line-comment", m.Index, hits);
        }

        var b64Count = 0;
        foreach (Match m in Base64Token.Matches(text))
        {
            if (++b64Count > MaxBase64PerBody) break;
            TryDecodeBase64(m.Groups[1].Value, sourceLabel, m.Index, hits);
        }

        return hits
            .GroupBy(h => (h.Category, h.Snippet[..Math.Min(60, h.Snippet.Length)]))
            .Select(g => g.First())
            .Take(80)
            .ToList();
    }

    private static void ProcessComment(string inner, string source, string category, int offset, List<CommentHit> hits)
    {
        if (inner.Length < MinCommentLen) return;

        var snippet = Truncate(inner, 200);
        var hasHygieneKeyword = HygieneKeywords.Any(k => inner.Contains(k, StringComparison.OrdinalIgnoreCase));
        var hasHiddenUrl = HiddenUrlPattern.IsMatch(inner);

        if (!hasHygieneKeyword && !hasHiddenUrl && inner.Length < 80) return;

        // Comment text is hygiene/recon only — credentials come from JS, network, and storage heuristics.
        var hitCategory = hasHygieneKeyword
            ? "comment-hygiene"
            : hasHiddenUrl
                ? "hidden-url-in-comment"
                : "comment-block";

        hits.Add(new CommentHit
        {
            Category = hitCategory,
            Source = source,
            Offset = offset,
            Snippet = snippet
        });

        foreach (Match um in HiddenUrlPattern.Matches(inner))
        {
            hits.Add(new CommentHit
            {
                Category = "hidden-url-in-comment",
                Source = source,
                Offset = offset,
                Snippet = um.Value
            });
        }
    }

    private static void TryDecodeBase64(string token, string source, int offset, List<CommentHit> hits)
    {
        try
        {
            var padded = token;
            while (padded.Length % 4 != 0) padded += "=";
            var bytes = Convert.FromBase64String(padded);
            if (bytes.Length < 8 || bytes.Length > 4096) return;
            var decoded = Encoding.UTF8.GetString(bytes);
            if (LooksLikeSvgPathData(decoded))
                return;
            if (!decoded.Contains("http://", StringComparison.OrdinalIgnoreCase)
                && !decoded.Contains("https://", StringComparison.OrdinalIgnoreCase)
                && !SecretKeywords.Any(k => decoded.Contains(k, StringComparison.OrdinalIgnoreCase)))
                return;

            // Slash alone is too weak — minified JS / binary soup often decodes with path-like '/'.
            if (SecretsHarvestHeuristics.IsChromiumOriginTrialMetadata(decoded)
                || SecretsHarvestHeuristics.IsBinaryGarbage(decoded)
                || LooksLikeMinifiedCodeSoup(decoded))
                return;

            hits.Add(new CommentHit
            {
                Category = "base64-decoded-url-or-secret",
                Source = source,
                Offset = offset,
                Snippet = Truncate(decoded, 160),
                Decoded = decoded.Length > 200 ? decoded[..200] + "…" : decoded
            });
        }
        catch
        {
            // not valid base64
        }
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    /// <summary>SVG path commands and numeric coordinates often base64-decode with '/' and look like URLs.</summary>
    internal static bool LooksLikeSvgPathData(string decoded)
    {
        if (string.IsNullOrWhiteSpace(decoded) || decoded.Length < 16)
            return false;

        var sample = decoded.Trim();
        if (sample.Length == 0 || !"MmZzLlCcHhVvTtQqAa".Contains(sample[0]))
            return false;

        var pathLike = 0;
        foreach (var c in sample)
        {
            if (char.IsDigit(c) || "MmZzLlCcHhVvTtQqAa ,.-+eE".Contains(c))
                pathLike++;
        }

        return pathLike >= sample.Length * 0.85;
    }

    /// <summary>Minified JS/CSS blobs that happen to base64-decode with slashes but aren't secrets.</summary>
    internal static bool LooksLikeMinifiedCodeSoup(string decoded)
    {
        if (string.IsNullOrWhiteSpace(decoded) || decoded.Length < 24)
            return false;

        var sample = decoded.Trim();
        // High density of punctuation typical of packed JS, without a real URL host.
        var punct = sample.Count(c => c is '{' or '}' or '(' or ')' or ';' or ',' or '=' or ':' or '[' or ']');
        if (punct >= sample.Length * 0.18
            && !sample.Contains("://", StringComparison.Ordinal)
            && !SecretKeywords.Any(k => sample.Contains(k, StringComparison.OrdinalIgnoreCase)))
            return true;

        // Mostly alphanumeric + slash noise without whitespace (asset soup).
        var whitespace = sample.Count(char.IsWhiteSpace);
        if (whitespace == 0 && sample.Length >= 40
            && !sample.Contains("://", StringComparison.Ordinal)
            && sample.Count(c => c == '/') >= 2
            && !SecretKeywords.Any(k => sample.Contains(k, StringComparison.OrdinalIgnoreCase)))
            return true;

        return false;
    }
}
