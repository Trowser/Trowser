using System.Text.Json;

namespace Trowser.Chat;

/// <summary>
/// Decides which built-in Chat tool calls need the user's explicit approval before they run.
/// The model reads page content, so text on a hostile page can steer it. Two policy buckets:
/// by-name tools below (tester / session safety — see <see cref="LlmSettings.ConfirmSensitiveAssistantActions"/>)
/// and active/aggressive <c>safetyMode</c> (target-server safety — see <see cref="LlmSettings.ConfirmActiveSafetyProbes"/>).
/// Local path arguments always prompt regardless of those settings.
/// </summary>
public static class ChatToolApproval
{
    /// <summary>By-name confirmations: user rights, cookies, local session, and in-browser execution.</summary>
    private static readonly Dictionary<string, string> AlwaysConfirm = new(StringComparer.Ordinal)
    {
        ["browser_run_script"] = "runs C# inside Trowser with your user rights",
        ["browser_execute_js"] = "runs JavaScript in the page",
        ["browser_upload"] = "uploads a local file to the page",
        ["browser_fetch"] = "sends an HTTP request with the browser's cookies",
        ["browser_fetch_batch"] = "sends HTTP requests with the browser's cookies",
        ["browser_fetch_raw"] = "sends a raw HTTP request outside the browser",
        ["browser_peer_fetch"] = "sends an HTTP request as another session",
        ["browser_surpriseme"] = "runs an unattended exploration that may submit forms",
        ["browser_header_overrides"] = "changes headers on every request",
        ["browser_mock"] = "changes responses the page receives",
        ["browser_intercept"] = "intercepts and changes network traffic",
        ["browser_clear_all"] = "deletes cookies, storage and cache",
        ["browser_identity_apply"] = "replaces the session's cookies and storage",
        ["browser_identity_handoff"] = "copies an identity into another session",
    };

    /// <summary>
    /// The reason a tool needs approval regardless of its arguments, or null. Only calls whose
    /// reason is exactly this may be approved for a whole chat session.
    /// </summary>
    public static string? NameReason(string toolName) =>
        AlwaysConfirm.TryGetValue(toolName, out var reason) ? reason : null;

    /// <summary>
    /// True when <paramref name="reason"/> is the fixed by-name reason for <paramref name="toolName"/>
    /// (session-wide approval may apply; argument-based reasons do not match).
    /// </summary>
    public static bool IsNameOnlyReason(string toolName, string reason) =>
        reason == NameReason(toolName);

    /// <summary>
    /// Returns a short reason when <paramref name="toolName"/> with <paramref name="args"/> needs
    /// confirmation, or null when it may run directly. Argument-based reasons win over the
    /// by-name reason so a session-wide approval never covers a new local path.
    /// </summary>
    public static string? RequiresConfirmation(string toolName, JsonElement args)
    {
        if (args.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in args.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.String)
                    continue;
                var value = prop.Value.GetString();
                if (string.IsNullOrWhiteSpace(value))
                    continue;

                if (IsPathArgument(prop.Name))
                    return $"reads or writes the local path '{value}'";

                // Server-side risk: same tool may be fine in passive/safe mode without confirmation.
                if (prop.Name.Equals("safetyMode", StringComparison.OrdinalIgnoreCase)
                    && (value.Equals("active", StringComparison.OrdinalIgnoreCase)
                        || value.Equals("aggressive", StringComparison.OrdinalIgnoreCase)))
                    return SafetyModeReason(value);
            }
        }

        return NameReason(toolName);
    }

    /// <summary>Reason shown when <paramref name="safetyMode"/> is active or aggressive.</summary>
    public static string SafetyModeReason(string safetyMode) =>
        $"runs probes in '{safetyMode}' safety mode, which can change server state";

    /// <summary>True when <paramref name="reason"/> came from an active/aggressive safetyMode argument.</summary>
    public static bool TryParseSafetyModeReason(string reason, out string safetyMode)
    {
        const string prefix = "runs probes in '";
        const string suffix = "' safety mode, which can change server state";
        if (reason.StartsWith(prefix, StringComparison.Ordinal)
            && reason.EndsWith(suffix, StringComparison.Ordinal)
            && reason.Length > prefix.Length + suffix.Length)
        {
            safetyMode = reason[prefix.Length..^suffix.Length];
            return true;
        }

        safetyMode = "";
        return false;
    }

    private static bool IsPathArgument(string name) =>
        name.Equals("path", StringComparison.OrdinalIgnoreCase)
        || name.Equals("file", StringComparison.OrdinalIgnoreCase)
        || name.Equals("directory", StringComparison.OrdinalIgnoreCase)
        || name.EndsWith("Path", StringComparison.Ordinal)
        || name.EndsWith("Dir", StringComparison.Ordinal);
}
