using System.Text.Json;
using Trowser.Security.Orchestration;

namespace Trowser.Api;

/// <summary>
/// The one list of operations that <c>--safe</c> blocks, shared by REST, MCP (external and
/// built-in Chat), batches and test scenarios.
/// <para>
/// Entries are operation keys. A REST route maps to its key by dropping <c>/api/</c> and turning
/// <c>/</c> and <c>-</c> into <c>_</c> (<c>/api/security/xss-scan</c> → <c>security_xss_scan</c>).
/// An MCP tool maps by dropping <c>browser_</c>; tools that omit the <c>security_</c> prefix of
/// their route (<c>browser_dom_xss_audit</c>) also match the prefixed key. Names that do not
/// follow the convention are listed in <see cref="ToolAliases"/>. Blocking an operation here
/// therefore blocks it on every surface; <c>SafeModePolicyTests</c> checks that against the API index.
/// </para>
/// </summary>
internal static class SafeModePolicy
{
    internal static readonly HashSet<string> BlockedOperations = new(StringComparer.Ordinal)
    {
        // Code execution and unattended exploration
        "execute_js",
        "execute_script",
        "surpriseme",
        "fuzz",
        "load_test",

        // Law sources are compiled and executed C# (sandboxed, but still code)
        "laws_add",
        "laws_author",
        "laws_delete",
        "laws_proposals_accept",
        "laws_replace",
        "laws_validate",

        // Raw HTTP outside the page, mocks, interception, header rewriting
        "fetch",
        "fetch_batch",
        "fetch_direct",
        "fetch_raw",
        "header_overrides",
        "mock",
        "mock_clear",
        "mock_remove",
        "intercept",
        "intercept_abort",
        "intercept_clear",
        "intercept_continue",
        "intercept_fulfill",
        "intercept_remove",
        "intercept_replay",
        "upload",
        "websocket_close",
        "websocket_send",

        // Session state, identities, client certificates
        "cookies_clear",
        "cookies_delete",
        "cookies_set",
        "storage",
        "storage_clear",
        "storage_delete",
        "storage_set",
        "identity_apply",
        "identity_capture",
        "peer_identity_apply",
        "ssl_certificates",
        "ssl_certificates_active",

        // Proof and replay
        "authz_role_matrix",
        "repro_verify",
        "race_lab_baseline",
        "race_lab_run",
        "race_lab_synchronize",

        // Security probes
        "security_account_enumeration_scan",
        "security_auth_bypass_pivot",
        "security_auth_control_identifier",
        "security_auto_scan",
        "security_bfla_probe",
        "security_body_size_limit_scan",
        "security_brute_force",
        "security_cache_deception_scan",
        "security_cache_poison_scan",
        "security_cache_pollution_scan",
        "security_captcha_replay_scan",
        "security_chain_prove",
        "security_clickjack_test",
        "security_client_prototype_pollution",
        "security_client_surface",
        "security_cmd_canary",
        "security_cookie_prefix_bypass",
        "security_costly_operations",
        "security_crawl_light",
        "security_csrf",
        "security_csti_scan",
        "security_cswsh_test",
        "security_default_credential_canary",
        "security_deserialization_scan",
        "security_dom_flows",
        "security_dom_xss_audit",
        "security_fail_open_scan",
        "security_file_upload_scan",
        "security_firewall_test",
        "security_forced_error_scan",
        "security_gadget_chains",
        "security_gadget_radar",
        "security_graphql_analyze",
        "security_harvest_ids",
        "security_host_header",
        "security_idor_scan",
        "security_js_audit",
        "security_jwt_acceptance_sweep",
        "security_jwt_analyze",
        "security_jwt_forge",
        "security_jwt_header_abuse",
        "security_ldap_scan",
        "security_llm_chat_interact",
        "security_llm_endpoint_discover",
        "security_llm_http_mcp_list",
        "security_llm_http_send",
        "security_llm_redteam_probes",
        "security_llm_redteam_scan",
        "security_llm_sink_assist",
        "security_logout_invalidation_probe",
        "security_mass_assignment_patch",
        "security_mass_assignment_register",
        "security_mass_assignment_scan",
        "security_methods",
        "security_missing_parameter_scan",
        "security_nextjs_rsc_scan",
        "security_nosql_scan",
        "security_nuclei_scan",
        "security_nuclei_templates",
        "security_oauth_flow_test",
        "security_open_redirect_scan",
        "security_openapi_smoke",
        "security_parser_probe",
        "security_password_reset_weak_scan",
        "security_path_filter_bypass",
        "security_path_traversal",
        "security_postmessage",
        "security_prototype_pollution_scan",
        "security_race_condition_scan",
        "security_rate_limit_audit",
        "security_redos_scan",
        "security_response_field_diff",
        "security_rest_scaffold",
        "security_saml_replay",
        "security_secrets_harvest",
        "security_service_worker_audit",
        "security_session_fixation_scan",
        "security_smuggling",
        "security_sqli_login_sweep",
        "security_sqli_scan",
        "security_ssrf_orchestrator",
        "security_ssrf_scan",
        "security_ssti_polyglot_scan",
        "security_ssti_scan",
        "security_ssti_stored_scan",
        "security_supply_chain_scan",
        "security_swaggering",
        "security_tls_introspection",
        "security_trace_input",
        "security_trusted_header_bypass",
        "security_verify",
        "security_verify_batch",
        "security_verify_workflow",
        "security_waf_bypass",
        "security_websocket_audit",
        "security_websocket_authz",
        "security_websocket_fuzz",
        "security_sse_audit",
        "security_workflow_skip_scan",
        "security_xs_leaks",
        "security_xss_scan",
        "security_xssi_scan",
    };

    /// <summary>MCP tools whose name does not follow the route naming convention.</summary>
    internal static readonly Dictionary<string, string> ToolAliases = new(StringComparer.Ordinal)
    {
        ["browser_run_script"] = "execute_script",
        ["browser_postmessage_audit"] = "security_postmessage",
        ["browser_ssl_add"] = "ssl_certificates",
        ["browser_ssl_remove"] = "ssl_certificates",
        ["browser_ssl_set_active"] = "ssl_certificates_active",
    };

    internal static string RouteKey(string path)
    {
        var p = path.Trim('/');
        if (p.StartsWith("api/", StringComparison.OrdinalIgnoreCase))
            p = p[4..];
        return p.Replace('/', '_').Replace('-', '_').ToLowerInvariant();
    }

    /// <summary>The blocked-operation key a tool maps to, or null when it maps to none.</summary>
    internal static string? ToolKey(string toolName)
    {
        if (ToolAliases.TryGetValue(toolName, out var alias))
            return alias;
        var k = toolName.StartsWith("browser_", StringComparison.Ordinal) ? toolName[8..] : toolName;
        if (BlockedOperations.Contains(k)) return k;
        if (BlockedOperations.Contains("security_" + k)) return "security_" + k;
        return null;
    }

    /// <summary>
    /// True when <paramref name="method"/> <paramref name="path"/> must be refused in safe mode.
    /// Reads (GET/HEAD) are never blocked. <paramref name="body"/> is only consulted for
    /// operations with a passive variant.
    /// </summary>
    internal static bool IsRouteBlocked(string path, string method, string? body)
    {
        if (method is "GET" or "HEAD" or "OPTIONS")
            return false;

        // Playbooks call scanners directly, so a run is as strong as its strongest step.
        if (path.StartsWith("/api/orchestrate/", StringComparison.OrdinalIgnoreCase))
            return !path.StartsWith("/api/orchestrate/dry-run/", StringComparison.OrdinalIgnoreCase);

        var key = RouteKey(path);
        if (!BlockedOperations.Contains(key))
            return false;
        if (key == "security_oauth_flow_test" && TrowserApiServer.BodyRequestsPassiveOAuthFlowTest(body))
            return false;
        return true;
    }

    /// <summary>True when the tool is blocked whatever its arguments are (used to hide it from tools/list).</summary>
    internal static bool IsToolAlwaysBlocked(string toolName) =>
        toolName is not ("browser_header_overrides" or "browser_security_oauth_flow_test" or "browser_laws")
        && IsToolBlocked(toolName, default);

    private static string? ActionArg(JsonElement args) =>
        args.ValueKind == JsonValueKind.Object
        && args.TryGetProperty("action", out var a) && a.ValueKind == JsonValueKind.String
            ? a.GetString()?.Trim().ToLowerInvariant()
            : null;

    /// <summary>True when this tool call must be refused in safe mode.</summary>
    internal static bool IsToolBlocked(string toolName, JsonElement args)
    {
        if (toolName == "browser_orchestrate_run")
            return true;

        if (toolName == "browser_header_overrides")
            return ActionArg(args) is not (null or "" or "get" or "list");

        // Listing, checking and rejecting proposals only run already-loaded Laws.
        if (toolName == "browser_laws")
            return ActionArg(args) is not (null or "" or "list" or "check" or "proposals" or "reject");

        // Read-only probe catalogs (REST GET is gate-free).
        if (toolName is "browser_security_llm_redteam_probes" or "browser_security_nuclei_templates")
            return false;

        var key = ToolKey(toolName);
        if (key == null)
            return false;
        if (key == "security_oauth_flow_test"
            && args.ValueKind == JsonValueKind.Object
            && SafetyGate.OAuthFlowTestIsPassiveOnly(new JsonBody(JsonDocument.Parse(args.GetRawText()))))
            return false;
        return true;
    }
}
