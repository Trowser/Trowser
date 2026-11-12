using System.IO;
using System.Text.RegularExpressions;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using YamlMemberAttribute = YamlDotNet.Serialization.YamlMemberAttribute;

namespace Trowser.Security.Nuclei;

public static class NucleiTemplateParser
{
    public const int MaxPathPayloadValues = 128;

    private static readonly Regex UnsupportedVariable = new(
        @"\{\{(?!BaseURL|RootURL|Hostname|Host|Port|Scheme|Path|File|paths)[A-Za-z0-9_.-]+\}\}",
        RegexOptions.Compiled);

    private static readonly string[] UnsupportedTopLevelKeys =
    [
        "dns:", "tcp:", "ssl:", "file:", "websocket:", "code:", "headless:",
        "workflow:", "self-contained:", "flow:"
    ];

    public static bool TryParse(
        string yaml,
        out NucleiTemplate? template,
        out string? skipReason,
        string? templateFilePath = null)
    {
        template = null;
        skipReason = null;

        if (string.IsNullOrWhiteSpace(yaml))
        {
            skipReason = "empty template";
            return false;
        }

        var normalized = yaml.Replace("\r\n", "\n", StringComparison.Ordinal);
        if (ContainsUnsupportedTopLevelFeature(normalized))
        {
            skipReason = "unsupported protocol or feature";
            return false;
        }

        if (UnsupportedVariable.IsMatch(normalized))
        {
            skipReason = "unsupported template variables (supported: BaseURL, RootURL, Hostname, Host, Port, Scheme, Path, File, paths)";
            return false;
        }

        YamlRoot? root;
        try
        {
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();
            root = deserializer.Deserialize<YamlRoot>(yaml);
        }
        catch (Exception ex)
        {
            skipReason = $"parse error: {ex.Message}";
            return false;
        }

        if (root?.Http == null || root.Http.Count == 0)
        {
            skipReason = "no http section";
            return false;
        }

        var templateDir = string.IsNullOrWhiteSpace(templateFilePath)
            ? null
            : Path.GetDirectoryName(templateFilePath);

        var requests = new List<NucleiHttpRequest>();
        foreach (var block in root.Http)
        {
            if (block == null) continue;
            if (block.Raw is { Count: > 0 })
            {
                skipReason = "raw HTTP blocks not supported";
                return false;
            }

            if (!string.IsNullOrWhiteSpace(block.Attack))
            {
                skipReason = "payload attack modes (clusterbomb/pitchfork/…) not supported";
                return false;
            }

            if (!TryParsePathPayloads(block.Payloads, templateDir, out var pathPayloads, out var payloadError))
            {
                skipReason = payloadError;
                return false;
            }

            var paths = (block.Paths ?? block.Path)?.Where(p => !string.IsNullOrWhiteSpace(p)).ToList() ?? [];
            if (paths.Count == 0)
                continue;

            if (pathPayloads.Count > 0)
            {
                var usesPathsPlaceholder = paths.Any(p =>
                    p.Contains("{{paths}}", StringComparison.OrdinalIgnoreCase));
                if (!usesPathsPlaceholder)
                {
                    skipReason = "payloads.paths requires {{paths}} in path templates";
                    return false;
                }
            }

            var matchers = ParseMatchers(block.Matchers);
            if (matchers.Count == 0)
                continue;

            requests.Add(new NucleiHttpRequest
            {
                Method = NormalizeMethod(block.Method),
                Paths = paths,
                PathPayloadValues = pathPayloads,
                Headers = ParseHeaders(block.Headers),
                Body = block.Body,
                MatchersCondition = NormalizeCondition(block.MatchersCondition, "and"),
                Matchers = matchers,
                StopAtFirstMatch = block.StopAtFirstMatch == true
            });
        }

        if (requests.Count == 0)
        {
            skipReason = "no supported HTTP request blocks";
            return false;
        }

        var info = root.Info ?? new YamlInfo();
        template = new NucleiTemplate
        {
            Id = string.IsNullOrWhiteSpace(root.Id) ? "unknown" : root.Id.Trim(),
            Name = info.Name?.Trim() ?? root.Id?.Trim() ?? "Unnamed template",
            Author = info.Author?.Trim() ?? "",
            Severity = NormalizeSeverity(info.Severity),
            Tags = ParseTags(info.Tags),
            Description = info.Description?.Trim() ?? "",
            HttpRequests = requests
        };
        return true;
    }

    private static bool ContainsUnsupportedTopLevelFeature(string yaml)
    {
        foreach (var key in UnsupportedTopLevelKeys)
        {
            if (yaml.Contains('\n' + key, StringComparison.OrdinalIgnoreCase)
                || yaml.StartsWith(key.TrimEnd(':'), StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // Top-level (column 0) payloads/attack — not http-block payloads.
        if (Regex.IsMatch(yaml, @"(?m)^payloads\s*:", RegexOptions.IgnoreCase))
            return true;
        if (Regex.IsMatch(yaml, @"(?m)^attack\s*:", RegexOptions.IgnoreCase))
            return true;

        return false;
    }

    private static bool TryParsePathPayloads(
        YamlPayloadsBlock? payloads,
        string? templateDir,
        out List<string> pathValues,
        out string? error)
    {
        pathValues = [];
        error = null;
        if (payloads?.Paths == null)
            return true;

        var list = CoerceStringList(payloads.Paths);
        if (list == null && payloads.Paths is string single && LooksLikePayloadFile(single))
        {
            list = LoadPayloadFileLines(single, templateDir, out error);
            if (list == null)
                return false;
        }

        list ??= CoerceStringList(payloads.Paths);
        if (list == null || list.Count == 0)
        {
            error = "payloads.paths is empty or unsupported";
            return false;
        }

        pathValues = list.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).ToList();
        if (pathValues.Count > MaxPathPayloadValues)
        {
            error = $"payloads.paths exceeds limit ({MaxPathPayloadValues})";
            return false;
        }

        return true;
    }

    private static bool LooksLikePayloadFile(string value)
    {
        var v = value.Trim();
        return v.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
            || v.EndsWith(".lst", StringComparison.OrdinalIgnoreCase)
            || v.Contains('/') || v.Contains('\\');
    }

    private static List<string>? LoadPayloadFileLines(string relativePath, string? templateDir, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(templateDir))
        {
            error = "payload file paths require loading templates from a directory";
            return null;
        }

        var combined = Path.Combine(templateDir, relativePath.Trim());
        if (!File.Exists(combined))
        {
            error = $"payload file not found: {relativePath}";
            return null;
        }

        try
        {
            return File.ReadAllLines(combined)
                .Select(l => l.Trim())
                .Where(l => l.Length > 0 && !l.StartsWith('#'))
                .Take(MaxPathPayloadValues)
                .ToList();
        }
        catch (Exception ex)
        {
            error = $"payload file read error: {ex.Message}";
            return null;
        }
    }

    private static List<string>? CoerceStringList(object? raw)
    {
        if (raw == null) return null;
        if (raw is string s)
            return LooksLikePayloadFile(s) ? null : [s];
        if (raw is IEnumerable<string> strEnum)
            return strEnum.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).ToList();
        if (raw is IEnumerable<object> objs)
            return objs.Select(o => o?.ToString()?.Trim() ?? "").Where(x => x.Length > 0).ToList();
        return null;
    }

    private static List<NucleiMatcher> ParseMatchers(List<YamlMatcher>? matchers)
    {
        var result = new List<NucleiMatcher>();
        if (matchers == null) return result;

        foreach (var m in matchers)
        {
            if (m == null || string.IsNullOrWhiteSpace(m.Type)) continue;
            var type = m.Type.Trim().ToLowerInvariant();
            if (type is not ("status" or "word" or "regex" or "header"))
                continue;

            result.Add(new NucleiMatcher
            {
                Type = type,
                Part = string.IsNullOrWhiteSpace(m.Part) ? "body" : m.Part.Trim().ToLowerInvariant(),
                Words = m.Words?.Where(w => !string.IsNullOrWhiteSpace(w)).ToList() ?? [],
                Regex = m.Regex?.Where(r => !string.IsNullOrWhiteSpace(r)).ToList() ?? [],
                Status = m.Status ?? [],
                Headers = m.Headers?.Where(h => !string.IsNullOrWhiteSpace(h)).ToList() ?? [],
                Condition = NormalizeCondition(m.Condition, "or"),
                Negative = m.Negative == true
            });
        }

        return result;
    }

    private static Dictionary<string, string> ParseHeaders(object? headers)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (headers == null) return map;

        switch (headers)
        {
            case Dictionary<object, object> dict:
                foreach (var (key, value) in dict)
                {
                    if (key == null || value == null) continue;
                    map[key.ToString() ?? ""] = value.ToString() ?? "";
                }
                break;
            case Dictionary<string, string> strDict:
                foreach (var (key, value) in strDict)
                    map[key] = value;
                break;
        }

        return map;
    }

    private static List<string> ParseTags(object? tags)
    {
        if (tags == null) return [];
        return tags switch
        {
            string s => s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList(),
            IEnumerable<object> list => list.Select(x => x?.ToString()?.Trim() ?? "")
                .Where(x => x.Length > 0).ToList(),
            _ => []
        };
    }

    private static string NormalizeMethod(string? method) =>
        string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();

    private static string NormalizeSeverity(string? severity) =>
        string.IsNullOrWhiteSpace(severity) ? "info" : severity.Trim().ToLowerInvariant();

    private static string NormalizeCondition(string? condition, string defaultValue)
    {
        if (string.IsNullOrWhiteSpace(condition)) return defaultValue;
        var c = condition.Trim().ToLowerInvariant();
        return c is "and" or "or" ? c : defaultValue;
    }

    private sealed class YamlRoot
    {
        public string? Id { get; set; }
        public YamlInfo? Info { get; set; }
        public List<YamlHttpRequest>? Http { get; set; }
    }

    private sealed class YamlInfo
    {
        public string? Name { get; set; }
        public string? Author { get; set; }
        public string? Severity { get; set; }
        public string? Description { get; set; }
        public object? Tags { get; set; }
    }

    private sealed class YamlHttpRequest
    {
        public string? Method { get; set; }
        public List<string>? Path { get; set; }
        public List<string>? Paths { get; set; }
        public object? Headers { get; set; }
        public string? Body { get; set; }
        public string? MatchersCondition { get; set; }
        public List<YamlMatcher>? Matchers { get; set; }
        public List<string>? Raw { get; set; }
        public YamlPayloadsBlock? Payloads { get; set; }
        public string? Attack { get; set; }

        [YamlMember(Alias = "stop-at-first-match", ApplyNamingConventions = false)]
        public bool? StopAtFirstMatch { get; set; }
    }

    private sealed class YamlPayloadsBlock
    {
        public object? Paths { get; set; }
    }

    private sealed class YamlMatcher
    {
        public string? Type { get; set; }
        public string? Part { get; set; }
        public List<string>? Words { get; set; }
        public List<string>? Regex { get; set; }
        public List<int>? Status { get; set; }
        public List<string>? Headers { get; set; }
        public string? Condition { get; set; }
        public bool? Negative { get; set; }
    }
}
