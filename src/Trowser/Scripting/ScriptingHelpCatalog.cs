using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;

namespace Trowser.Scripting;

/// <summary>
/// Loads the embedded C# scripting cheat sheet and returns topic sections for MCP/REST.
/// </summary>
public static class ScriptingHelpCatalog
{
    private const string ResourceName = "Trowser.Resources.scripting-help.txt";

    private static readonly Lazy<string> FullText = new(LoadFullText);
    private static readonly Lazy<Dictionary<string, string>> Sections = new(ParseSections);

    public static IReadOnlyCollection<string> TopicNames =>
        Sections.Value.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray();

    public static string ResolveTopic(string? topic)
    {
        if (string.IsNullOrWhiteSpace(topic))
            return "overview";

        return topic.Trim().ToLowerInvariant() switch
        {
            "maps" or "mcp" or "rest" or "translate" or "translation" => "map",
            "asserts" or "assertions" => "assert",
            "interact" or "locators" or "click" or "clicks" => "interaction",
            "waiting" or "waits" => "wait",
            "console" or "errors" => "network",
            "mocks" or "fault" or "faults" => "mock",
            "sec" or "scans" => "security",
            "law" or "invariant" or "invariants" => "laws",
            "templates" or "example" or "examples" => "template",
            "list" or "index" or "help" => "topics",
            "default" or "cheat" or "cheatsheet" => "overview",
            _ => topic.Trim().ToLowerInvariant()
        };
    }

    /// <summary>
    /// Returns help text for a topic, or null if the topic is unknown.
    /// When topic is overview, appends the topics index so callers know they can go deeper.
    /// </summary>
    public static string? GetTopic(string? topic, out string resolvedTopic, out string? error)
    {
        resolvedTopic = ResolveTopic(topic);
        error = null;

        var sections = Sections.Value;
        if (sections.Count == 0)
        {
            error = "Scripting help resource has no topic sections.";
            return null;
        }

        if (resolvedTopic is "all" or "*")
            return FullText.Value.Trim();

        if (!sections.TryGetValue(resolvedTopic, out var body))
        {
            var known = string.Join(", ", TopicNames);
            error = $"Unknown scripting help topic '{resolvedTopic}'. Available: {known}";
            return null;
        }

        if (resolvedTopic == "overview" && sections.TryGetValue("topics", out var topicsBody))
            return body.TrimEnd() + "\n\n---\n" + topicsBody.Trim();

        return body.Trim();
    }

    private static string LoadFullText()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName);
        if (stream == null)
            throw new InvalidOperationException("Scripting help resource not found.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static Dictionary<string, string> ParseSections()
    {
        var full = FullText.Value;
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var matches = Regex.Matches(
            full,
            @"^## topic:([a-z0-9_-]+)\s*$",
            RegexOptions.Multiline | RegexOptions.IgnoreCase);

        for (var i = 0; i < matches.Count; i++)
        {
            var name = matches[i].Groups[1].Value.Trim();
            var start = matches[i].Index + matches[i].Length;
            var end = i + 1 < matches.Count ? matches[i + 1].Index : full.Length;
            if (start < 0 || end < start || start > full.Length)
                continue;
            var body = full[start..end].Trim();
            if (!string.IsNullOrEmpty(name))
                result[name] = $"## topic:{name}\n\n{body}";
        }

        return result;
    }
}
