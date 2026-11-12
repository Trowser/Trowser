using System.Text.Json;

namespace Trowser.Api;

/// <summary>Parse <c>tools/call</c> bodies for gate bypass before the API semaphore.</summary>
internal static class McpRoutingHelpers
{
    public static string? TryGetToolsCallName(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("method", out var m) &&
                m.ValueKind == JsonValueKind.String &&
                m.GetString() == "tools/call" &&
                root.TryGetProperty("params", out var p) &&
                p.TryGetProperty("name", out var n) &&
                n.ValueKind == JsonValueKind.String)
                return n.GetString();
        }
        catch { /* invalid JSON */ }

        return null;
    }

    /// <summary>Tools that must run even when the gate is held (abort, health ping, force-navigate, dialog).</summary>
    public static bool BypassesGate(string? toolName) =>
        toolName is "browser_abort" or "browser_ping" or "browser_force_navigate"
            or "browser_handle_dialog" or "browser_dialog";

    /// <summary>Read-only MCP tools that never touch WebView2 — may run parallel to a long scan.</summary>
    public static bool IsGateFreeReadOnly(string? toolName) =>
        toolName is
            "browser_console" or
            "browser_network" or
            "browser_network_har" or
            "browser_journal_get" or
            "browser_journal_export" or
            "browser_decisions" or
            "browser_pointers" or
            "browser_peers" or
            "browser_security_callbacks" or
            "browser_security_chain_patterns" or
            "browser_security_llm_redteam_probes" or
            "browser_orchestrate_list";
}
