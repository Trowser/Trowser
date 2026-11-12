using System.IO;
using System.Text;

namespace Trowser;

/// <summary>
/// Parses a pasted curl command into HTTP Request Editor fields.
/// Supports bash quoting (as produced by <see cref="CurlCommandBuilder"/> and Chrome DevTools),
/// line continuations (<c>\</c> and <c>^</c>), and double-quoted cmd copies when pasted.
/// </summary>
internal static class CurlCommandParser
{
    internal sealed class ParsedRequest
    {
        public required string Method { get; init; }
        public required string Url { get; init; }
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string? Body { get; init; }
        public bool FollowRedirects { get; init; }
    }

    public static ParsedRequest Parse(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            throw new FormatException("Paste a curl command first.");

        var flat = JoinContinuations(text);
        var tokens = Tokenize(flat);
        if (tokens.Count == 0)
            throw new FormatException("Could not read any curl arguments.");

        var start = 0;
        if (IsCurlExecutable(tokens[0]))
            start = 1;

        string? method = null;
        string? url = null;
        string? body = null;
        var followRedirects = false;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (var i = start; i < tokens.Count; i++)
        {
            var tok = tokens[i];
            if (!tok.StartsWith('-'))
            {
                url ??= tok;
                continue;
            }

            if (IsNoArgFlag(tok, ref method, ref followRedirects))
                continue;

            if (!TryConsumeOptionValue(tok, tokens, ref i, out var value))
                throw new FormatException($"Missing value after {tok}.");

            ApplyOption(tok, value, ref method, ref url, ref body, ref followRedirects, headers);
        }

        if (string.IsNullOrWhiteSpace(url))
            throw new FormatException("No URL found in the curl command.");

        method ??= body != null ? "POST" : "GET";

        return new ParsedRequest
        {
            Method = method.Trim().ToUpperInvariant(),
            Url = url.Trim(),
            Headers = headers,
            Body = body,
            FollowRedirects = followRedirects
        };
    }

    private static void ApplyOption(
        string flag,
        string value,
        ref string? method,
        ref string? url,
        ref string? body,
        ref bool followRedirects,
        Dictionary<string, string> headers)
    {
        if (flag.Equals("-X", StringComparison.Ordinal))
        {
            method = value;
            return;
        }

        switch (flag.ToLowerInvariant())
        {
            case "--request":
                method = value;
                break;
            case "-h":
            case "--header":
                AddHeader(headers, value);
                break;
            case "-d":
            case "--data":
            case "--data-raw":
            case "--data-binary":
                if (value.StartsWith('@'))
                    throw new FormatException("Reading the request body from a file (@…) is not supported — paste the body inline.");
                body = AppendBody(body, value);
                if (method == null && flag is "-d" or "--data")
                    method = "POST";
                break;
            case "--data-urlencode":
                if (value.StartsWith('@'))
                    throw new FormatException("Reading the request body from a file (@…) is not supported — paste the body inline.");
                body = AppendBody(body, Uri.UnescapeDataString(value.Replace('+', ' ')));
                if (method == null)
                    method = "POST";
                break;
            case "--url":
                url = value;
                break;
            case "-b":
            case "--cookie":
                MergeHeader(headers, "Cookie", value);
                break;
            case "-a":
            case "--user-agent":
                headers["User-Agent"] = value;
                break;
            case "-e":
            case "--referer":
                headers["Referer"] = value;
                break;
            case "-u":
            case "--user":
                headers["Authorization"] = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
                break;
            case "-x":
            case "--proxy":
            case "-o":
            case "--output":
            case "-m":
            case "--max-time":
            case "--connect-timeout":
            case "-w":
            case "--write-out":
                break;
            default:
                break;
        }
    }

    private static bool IsNoArgFlag(string tok, ref string? method, ref bool followRedirects)
    {
        if (tok.Equals("-L", StringComparison.OrdinalIgnoreCase) ||
            tok.Equals("--location", StringComparison.OrdinalIgnoreCase))
        {
            followRedirects = true;
            return true;
        }

        if (tok.Equals("-I", StringComparison.OrdinalIgnoreCase) ||
            tok.Equals("--head", StringComparison.OrdinalIgnoreCase))
        {
            method = "HEAD";
            return true;
        }

        if (RequiresValue(tok))
            return false;

        if (tok.Length == 2 && tok[0] == '-' && char.IsLetter(tok[1]))
            return true;

        return tok.StartsWith("--", StringComparison.Ordinal);
    }

    private static bool RequiresValue(string flag) =>
        flag.Equals("-X", StringComparison.Ordinal) ||
        flag.Equals("--request", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("-H", StringComparison.Ordinal) ||
        flag.Equals("--header", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("-d", StringComparison.Ordinal) ||
        flag.Equals("--data", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("--data-raw", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("--data-binary", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("--data-urlencode", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("--url", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("-b", StringComparison.Ordinal) ||
        flag.Equals("--cookie", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("-A", StringComparison.Ordinal) ||
        flag.Equals("--user-agent", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("-e", StringComparison.Ordinal) ||
        flag.Equals("--referer", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("-u", StringComparison.Ordinal) ||
        flag.Equals("--user", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("-x", StringComparison.Ordinal) ||
        flag.Equals("--proxy", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("-o", StringComparison.Ordinal) ||
        flag.Equals("--output", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("-m", StringComparison.Ordinal) ||
        flag.Equals("--max-time", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("--connect-timeout", StringComparison.OrdinalIgnoreCase) ||
        flag.Equals("-w", StringComparison.Ordinal) ||
        flag.Equals("--write-out", StringComparison.OrdinalIgnoreCase);

    private static bool TryConsumeOptionValue(string flag, List<string> tokens, ref int index, out string value)
    {
        value = "";
        if (!RequiresValue(flag))
            return false;

        if (index + 1 >= tokens.Count)
            return false;

        value = tokens[++index];
        return true;
    }

    private static string AppendBody(string? existing, string next) =>
        existing == null ? next : existing + "&" + next;

    private static void AddHeader(Dictionary<string, string> headers, string headerLine)
    {
        var colon = headerLine.IndexOf(':');
        if (colon <= 0)
            throw new FormatException($"Invalid header: {headerLine}");
        headers[headerLine[..colon].Trim()] = headerLine[(colon + 1)..].Trim();
    }

    private static void MergeHeader(Dictionary<string, string> headers, string name, string value)
    {
        if (headers.TryGetValue(name, out var existing) && !string.IsNullOrEmpty(existing))
            headers[name] = existing + "; " + value;
        else
            headers[name] = value;
    }

    private static bool IsCurlExecutable(string token)
    {
        var trimmed = token.Trim();
        if (trimmed.StartsWith('"') && trimmed.EndsWith('"') && trimmed.Length >= 2)
            trimmed = trimmed[1..^1];
        var name = Path.GetFileName(trimmed);
        return name.Equals("curl", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("curl.exe", StringComparison.OrdinalIgnoreCase);
    }

    internal static string JoinContinuations(string text)
    {
        var lines = text.Split('\n');
        var sb = new StringBuilder(text.Length);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            var trimmedEnd = line.TrimEnd();
            if (trimmedEnd.EndsWith('\\'))
            {
                sb.Append(trimmedEnd[..^1].TrimEnd());
                sb.Append(' ');
                continue;
            }

            if (trimmedEnd.EndsWith('^'))
            {
                sb.Append(trimmedEnd[..^1].TrimEnd());
                sb.Append(' ');
                continue;
            }

            sb.Append(line);
            if (i < lines.Length - 1)
                sb.Append(' ');
        }

        return sb.ToString().Trim();
    }

    internal static List<string> Tokenize(string input)
    {
        var tokens = new List<string>();
        var i = 0;
        while (i < input.Length)
        {
            SkipWhitespace(ref i, input);
            if (i >= input.Length)
                break;

            tokens.Add(input[i] switch
            {
                '"' => ReadDoubleQuoted(ref i, input),
                '\'' => ReadSingleQuoted(ref i, input),
                _ => ReadUnquoted(ref i, input)
            });
        }

        return tokens;
    }

    private static void SkipWhitespace(ref int i, string input)
    {
        while (i < input.Length && char.IsWhiteSpace(input[i]))
            i++;
    }

    private static string ReadDoubleQuoted(ref int i, string input)
    {
        if (input[i] != '"')
            throw new FormatException("Expected opening double quote.");
        i++;
        var sb = new StringBuilder();
        while (i < input.Length)
        {
            var c = input[i++];
            if (c == '"')
                return sb.ToString();

            if (c == '\\' && i < input.Length)
            {
                var next = input[i++];
                sb.Append(next);
                continue;
            }

            if (c == '^' && i < input.Length)
            {
                var next = input[i++];
                sb.Append(next);
                continue;
            }

            sb.Append(c);
        }

        throw new FormatException("Unclosed double-quoted string.");
    }

    private static string ReadSingleQuoted(ref int i, string input)
    {
        if (input[i] != '\'')
            throw new FormatException("Expected opening single quote.");
        i++;
        var sb = new StringBuilder();
        while (i < input.Length)
        {
            var c = input[i++];
            if (c == '\'')
                return sb.ToString();
            sb.Append(c);
        }

        throw new FormatException("Unclosed single-quoted string.");
    }

    private static string ReadUnquoted(ref int i, string input)
    {
        var sb = new StringBuilder();
        while (i < input.Length)
        {
            var c = input[i];
            if (char.IsWhiteSpace(c))
                break;

            if (c == '^' && i + 1 < input.Length)
            {
                sb.Append(input[i + 1]);
                i += 2;
                continue;
            }

            sb.Append(c);
            i++;
        }

        return sb.ToString();
    }
}
