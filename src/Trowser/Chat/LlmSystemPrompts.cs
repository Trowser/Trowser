using System.IO;
using System.Reflection;
using System.Text;

namespace Trowser.Chat;

/// <summary>
/// Loads embedded default LLM system prompts and resolves effective prompts
/// (custom override from settings, or built-in default).
/// </summary>
public static class LlmSystemPrompts
{
    private static readonly Dictionary<InteractionMode, string> DefaultCache = new();

    public static string? GetOverride(LlmSettings settings, InteractionMode mode) => mode switch
    {
        InteractionMode.Chat => settings.SystemPromptChat,
        InteractionMode.Economical => settings.SystemPromptEconomical,
        _ => settings.SystemPromptFull
    };

    public static void SetOverride(LlmSettings settings, InteractionMode mode, string? value)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? null : value;
        switch (mode)
        {
            case InteractionMode.Chat:
                settings.SystemPromptChat = normalized;
                break;
            case InteractionMode.Economical:
                settings.SystemPromptEconomical = normalized;
                break;
            default:
                settings.SystemPromptFull = normalized;
                break;
        }
    }

    /// <summary>
    /// Effective prompt for the given mode: custom override if set, otherwise embedded default.
    /// </summary>
    public static string GetEffective(LlmSettings settings, InteractionMode mode)
    {
        var custom = GetOverride(settings, mode);
        if (!string.IsNullOrWhiteSpace(custom))
            return custom;
        return GetDefault(mode);
    }

    /// <summary>
    /// Built-in prompt for a mode (heuristics are on demand via get_test_heuristics).
    /// </summary>
    public static string GetDefault(InteractionMode mode)
    {
        lock (DefaultCache)
        {
            if (DefaultCache.TryGetValue(mode, out var cached))
                return cached;
        }

        var resourceName = mode switch
        {
            InteractionMode.Chat => "Trowser.Resources.llm-system-prompt-chat.txt",
            InteractionMode.Economical => "Trowser.Resources.llm-system-prompt-economical.txt",
            _ => "Trowser.Resources.llm-system-prompt.txt"
        };

        var text = LoadEmbedded(resourceName);

        if (string.IsNullOrEmpty(text))
        {
            text = "You are a browser testing assistant. You can interact with the browser using the provided tools. Always start by calling browser_snapshot to see the current page state.";
        }

        lock (DefaultCache)
        {
            DefaultCache[mode] = text;
        }

        return text;
    }

    /// <summary>
    /// Store custom text only when it differs from the default; otherwise clear the override.
    /// </summary>
    public static string? NormalizeOverride(InteractionMode mode, string? editedText)
    {
        if (string.IsNullOrWhiteSpace(editedText))
            return null;

        var trimmed = editedText.TrimEnd();
        var defaultText = GetDefault(mode).TrimEnd();
        if (string.Equals(trimmed, defaultText, StringComparison.Ordinal))
            return null;

        return editedText;
    }

    private static string LoadEmbedded(string resourceName)
    {
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream(resourceName);
            if (stream == null) return "";
            using var reader = new StreamReader(stream, Encoding.UTF8);
            return reader.ReadToEnd();
        }
        catch (Exception ex)
        {
            TrowserLog.Error($"Failed to load embedded prompt {resourceName}", ex);
            return "";
        }
    }
}
