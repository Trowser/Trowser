using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Chat;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.ResourceUsage;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class McpHandler
{
    #region MCP Protocol

    private object Initialize()
    {
        _sessionId = Guid.NewGuid().ToString("N")[..16];
        return new
        {
            protocolVersion = "2025-03-26",
            capabilities = new { tools = new { } },
            serverInfo = new
            {
                name = "Trowser",
                version = "1.0",
                description = "Windows WebView2 browser with built-in C# scripting for web test automation"
            }
        };
    }

    private static string SafeModeBlockedMessage(string toolName) =>
        $"Tool '{toolName}' is blocked by safe mode. Safe mode disables scripting, raw HTTP, mocks, session manipulation and active security probes.";

    /// <summary>
    /// The single tool dispatch: MCP <c>tools/call</c> and the built-in Chat (<c>LlmToolExecutor</c>)
    /// both land here, so safe mode, pack availability and tracing apply identically.
    /// </summary>
    internal async Task<object> ExecuteToolAsync(string toolName, JsonElement arguments)
    {
        toolName = CanonicalToolName(toolName, arguments);

        if (SafeMode && SafeModePolicy.IsToolBlocked(toolName, arguments))
            return ErrorContent(SafeModeBlockedMessage(toolName));

        if (!IsToolAvailable(toolName))
            return ErrorContent(ToolUnavailableMessage(toolName));

        using var traceScope = IsTraceableSecurityTool(toolName) && GetBool(arguments, "verbose", false)
            ? _context.BeginRequestTrace()
            : null;

        try
        {
            var result = toolName switch
            {
                "browser_snapshot" => await ToolSnapshot(arguments),
                "browser_state_refresh" => await ToolStateRefresh(),
                "browser_diff_state" => ToolDiffState(arguments),
                "browser_navigate" => await ToolNavigate(arguments),
                "browser_force_navigate" => await ToolForceNavigate(arguments),
                "browser_go_back" => await ToolGoBack(),
                "browser_go_forward" => await ToolGoForward(),
                "browser_click" => await ToolClick(arguments),
                "browser_click_at" => await ToolClickAt(arguments),
                "browser_drag" => await ToolDrag(arguments),
                "browser_type" => await ToolType(arguments),
                "browser_upload" => await ToolUpload(arguments),
                "browser_select_option" => await ToolSelect(arguments),
                "browser_hover" => await ToolHover(arguments),
                "browser_press_key" => await ToolPressKey(arguments),
                "browser_scroll" => await ToolScroll(arguments),
                "browser_take_screenshot" => await ToolScreenshot(arguments),
                "browser_screenshot_compare" => await ToolScreenshotCompare(arguments),
                "browser_text" => await ToolGetText(arguments),
                "browser_extract" => await ToolExtract(arguments),
                "browser_find" => await ToolFind(arguments),
                "browser_find_clear" => await ToolFindClear(),
                "browser_page_text" => await ToolPageText(),
                "browser_page_text_all" => await ToolPageTextAll(),
                "browser_page_text_screen_reader" => await ToolPageTextScreenReader(),
                "browser_page_source" => await ToolPageSource(),
                "browser_execute_js" => await ToolExecuteJs(arguments),
                "browser_accessibility" => await ToolAccessibility(arguments),
                "browser_tab_order" => await ToolTabOrder(arguments),
                "browser_performance" => await ToolPerformance(),
                "browser_resource_snapshot" => await ToolResourceSnapshot(arguments),
                "browser_resource_compare" => await ToolResourceCompare(arguments),
                "browser_resource_probe" => await ToolResourceProbe(arguments),
                "browser_security" => await ToolSecurity(),
                "browser_security_js_libraries" => await ToolSecurityJsLibraries(),
                "browser_security_headers" => await ToolSecurityHeaders(),
                "browser_security_cors" => await ToolSecurityCors(arguments),
                "browser_security_forced_error_scan" => await ToolSecurityForcedErrorScan(arguments),
                "browser_security_trusted_header_bypass" => await ToolSecurityTrustedHeaderBypass(arguments),
                "browser_security_default_credential_canary" => await ToolSecurityDefaultCredentialCanary(arguments),
                "browser_security_discover" => await ToolSecurityDiscover(arguments),
                "browser_security_crawl_light" => await ToolSecurityCrawlLight(arguments),
                "browser_attack_surface" => await ToolAttackSurface(arguments),
                "browser_security_api_inventory" => await ToolSecurityApiInventory(arguments),
                "browser_security_clickjack_test" => await ToolSecurityClickjackTest(arguments),
                "browser_security_csrf" => await ToolSecurityCsrf(arguments),
                "browser_security_path_traversal" => await ToolSecurityPathTraversal(arguments),
                "browser_security_ssrf_scan" => await ToolSecuritySsrfScan(arguments),
                "browser_security_ssrf_orchestrator" => await ToolSecuritySsrfOrchestrator(arguments),
                "browser_security_open_redirect_scan" => await ToolSecurityOpenRedirectScan(arguments),
                "browser_security_cache_deception_scan" => await ToolSecurityCacheDeceptionScan(arguments),
                "browser_security_cache_map" => await ToolSecurityCacheMap(arguments),
                "browser_security_cache_pollution_scan" => await ToolSecurityCachePollutionScan(arguments),
                "browser_security_cache_poison_scan" => await ToolSecurityCachePoisonScan(arguments),
                "browser_security_methods" => await ToolSecurityMethods(arguments),
                "browser_security_smuggling" => await ToolSecuritySmuggling(arguments),
                "browser_security_host_header" => await ToolSecurityHostHeader(arguments),
                "browser_security_waf_bypass" => await ToolSecurityWafBypass(arguments),
                "browser_security_shadow" => await ToolSecurityShadow(arguments),
                "browser_shadow_check" => await ToolShadowCheck(arguments),
                "browser_laws" => await ToolLaws(arguments),
                "browser_firewall_test" => await ToolFirewallTest(arguments),
                "browser_client_surface" => await ToolClientSurface(arguments),
                "browser_security_service_worker_audit" => await ToolServiceWorkerAudit(arguments),
                "browser_security_xssi_scan" => await ToolSecurityXssiScan(arguments),
                "browser_postmessage_audit" => await ToolPostMessageAudit(arguments),
                "browser_security_client_prototype_pollution" => await ToolClientPrototypePollution(arguments),
                "browser_dom_flows" => await ToolDomFlows(arguments),
                "browser_dom_xss_audit" => await ToolDomXssAudit(arguments),
                "browser_security_xs_leaks" => await ToolSecurityXsLeaks(arguments),
                "browser_security_gadget_chains" => await ToolSecurityGadgetChains(arguments),
                "browser_gadget_radar" => await ToolGadgetRadar(arguments),
                "browser_security_callbacks" => await ToolSecurityCallbacks(arguments),
                "browser_trace_input" => await ToolTraceInput(arguments),
                "browser_security_sqli_scan" => await ToolSecuritySqliScan(arguments),
                "browser_security_sqli_login_sweep" => await ToolSecuritySqliLoginSweep(arguments),
                "browser_security_nosql_scan" => await ToolSecurityNosqlScan(arguments),
                "browser_security_ldap_scan" => await ToolSecurityLdapScan(arguments),
                "browser_security_ssti_scan" => await ToolSecuritySstiScan(arguments),
                "browser_security_ssti_polyglot_scan" => await ToolSecuritySstiPolyglotScan(arguments),
                "browser_security_ssti_stored_scan" => await ToolSecuritySstiStoredScan(arguments),
                "browser_security_prototype_pollution_scan" => await ToolSecurityPrototypePollutionScan(arguments),
                "browser_security_supply_chain_scan" => await ToolSecuritySupplyChainScan(arguments),
                "browser_security_osv_check" => await ToolSecurityOsvCheck(arguments),
                "browser_security_csti_scan" => await ToolSecurityCstiScan(arguments),
                "browser_security_xss_scan" => await ToolSecurityXssScan(arguments),
                "browser_security_parser_probe" => await ToolSecurityParserProbe(arguments),
                "browser_security_deserialization_scan" => await ToolSecurityDeserializationScan(arguments),
                "browser_security_file_upload_scan" => await ToolSecurityFileUploadScan(arguments),
                "browser_security_nextjs_rsc_scan" => await ToolSecurityNextJsRscScan(arguments),
                "browser_security_race_condition_scan" => await ToolSecurityRaceConditionScan(arguments),
                "browser_security_captcha_replay_scan" => await ToolSecurityCaptchaReplayScan(arguments),
                "browser_security_llm_redteam_scan" => await ToolSecurityLlmRedteamScan(arguments),
                "browser_security_llm_redteam_probes" => await ToolSecurityLlmRedteamProbes(arguments),
                "browser_security_llm_endpoint_discover" => await ToolSecurityLlmEndpointDiscover(arguments),
                "browser_security_llm_chat_interact" => await ToolSecurityLlmChatInteract(arguments),
                "browser_security_llm_http_send" => await ToolSecurityLlmHttpSend(arguments),
                "browser_security_llm_http_mcp_list" => await ToolSecurityLlmHttpMcpList(arguments),
                "browser_security_llm_sink_assist" => await ToolSecurityLlmSinkAssist(arguments),
                "browser_security_rate_limit_audit" => await ToolSecurityRateLimitAudit(arguments),
                "browser_security_redos_scan" => await ToolSecurityReDoSScan(arguments),
                "browser_security_body_size_limit_scan" => await ToolSecurityBodySizeLimitScan(arguments),
                "browser_security_costly_operations" => await ToolSecurityCostlyOperations(arguments),
                "browser_security_swaggering" => await ToolSecuritySwaggering(arguments),
                "browser_security_workflow_skip_scan" => await ToolSecurityWorkflowSkipScan(arguments),
                "browser_security_fail_open_scan" => await ToolSecurityFailOpenScan(arguments),
                "browser_security_auth_control_identifier" => await ToolSecurityAuthControlIdentifier(arguments),
                "browser_security_missing_parameter_scan" => await ToolSecurityMissingParameterScan(arguments),
                "browser_security_session_fixation_scan" => await ToolSecuritySessionFixationScan(arguments),
                "browser_security_password_reset_weak_scan" => await ToolSecurityPasswordResetWeakScan(arguments),
                "browser_security_account_enumeration_scan" => await ToolSecurityAccountEnumerationScan(arguments),
                "browser_security_logout_invalidation_probe" => await ToolSecurityLogoutInvalidationProbe(arguments),
                "browser_security_cmd_canary" => await ToolSecurityCmdCanary(arguments),
                "browser_security_js_audit" => await ToolSecurityJsAudit(arguments),
                "browser_security_nuclei_scan" => await ToolSecurityNucleiScan(arguments),
                "browser_security_nuclei_templates" => await ToolSecurityNucleiTemplates(arguments),
                "browser_security_jwt_analyze" => await ToolSecurityJwtAnalyze(arguments),
                "browser_security_jwt_forge" => await ToolSecurityJwtForge(arguments),
                "browser_security_jwt_acceptance_sweep" => await ToolSecurityJwtAcceptanceSweep(arguments),
                "browser_security_jwt_header_abuse" => await ToolSecurityJwtHeaderAbuse(arguments),
                "browser_security_cookie_prefix_bypass" => await ToolSecurityCookiePrefixBypass(arguments),
                "browser_security_tls_introspection" => await ToolSecurityTlsIntrospection(arguments),
                "browser_security_auth_bypass_pivot" => await ToolSecurityAuthBypassPivot(arguments),
                "browser_security_rest_scaffold" => await ToolSecurityRestScaffold(arguments),
                "browser_security_path_filter_bypass" => await ToolSecurityPathFilterBypass(arguments),
                "browser_security_harvest_ids" => await ToolSecurityHarvestIds(arguments),
                "browser_security_brute_force" => await ToolSecurityBruteForce(arguments),
                "browser_security_idor_scan" => await ToolSecurityIdorScan(arguments),
                "browser_security_mass_assignment_scan" => await ToolSecurityMassAssignmentScan(arguments),
                "browser_security_mass_assignment_patch" => await ToolSecurityMassAssignmentPatch(arguments),
                "browser_security_mass_assignment_register" => await ToolSecurityMassAssignmentRegister(arguments),
                "browser_security_bfla_probe" => await ToolSecurityBflaProbe(arguments),
                "browser_security_response_field_diff" => await ToolSecurityResponseFieldDiff(arguments),
                "browser_authz_role_matrix" => await ToolAuthzRoleMatrix(arguments),
                "browser_websocket_send" => await ToolWebSocketSend(arguments),
                "browser_websocket_close" => await ToolWebSocketClose(arguments),
                "browser_security_websocket_fuzz" => await ToolSecurityWebSocketFuzz(arguments),
                "browser_security_websocket_authz" => await ToolSecurityWebSocketAuthz(arguments),
                "browser_sse_connections" => await ToolSseConnections(arguments),
                "browser_sse_messages" => await ToolSseMessages(arguments),
                "browser_security_sse_audit" => await ToolSecuritySseAudit(arguments),
                "browser_security_auto_scan" => await ToolSecurityAutoScan(arguments),
                "browser_security_secrets_harvest" => await ToolSecuritySecretsHarvest(arguments),
                "browser_security_oidc_analyze" => await ToolSecurityOidcAnalyze(arguments),
                "browser_security_oauth_flow_test" => await ToolSecurityOAuthFlowTest(arguments),
                "browser_security_graphql_analyze" => await ToolSecurityGraphqlAnalyze(arguments),
                "browser_security_verify" => await ToolSecurityVerify(arguments),
                "browser_security_verify_workflow" => await ToolSecurityVerifyWorkflow(arguments),
                "browser_security_chain_prove" => await ToolSecurityChainProve(arguments),
                "browser_repro_capture" => await ToolReproCapture(arguments),
                "browser_repro_verify" => await ToolReproVerify(arguments),
                "browser_vpx_export" => await ToolVpxExport(arguments),
                "browser_vpx_import" => await ToolVpxImport(arguments),
                "browser_vpx_clear" => ToolVpxClear(arguments),
                "browser_security_chain_analyze" => await ToolSecurityChainAnalyze(arguments),
                "browser_security_chain_patterns" => ToolSecurityChainPatterns(arguments),
                "browser_validate_html" => await ToolValidateHtml(),
                "browser_seo" => await ToolSeo(),
                "browser_check_links" => await ToolCheckLinks(arguments),
                "browser_security_xss" => await ToolSecurityXss(),
                "browser_mixed_content" => await ToolMixedContent(),
                "browser_security_cookies" => await ToolSecurityCookies(),
                "browser_security_session_id" => await ToolSecuritySessionId(arguments),
                "browser_security_reset_token" => await ToolSecurityResetToken(arguments),
                "browser_security_token_entropy" => await ToolSecurityTokenEntropy(arguments),
                "browser_security_storage" => await ToolSecurityStorage(),
                "browser_security_source_maps" => await ToolSecuritySourceMaps(),
                "browser_security_tech_stack" => await ToolSecurityTechStack(),
                "browser_saml_decode" => await ToolSamlDecode(arguments),
                "browser_saml_capture" => await ToolSamlCapture(arguments),
                "browser_saml_replay" => await ToolSamlReplay(arguments),
                "browser_structured_text" => await ToolStructuredText(),
                "browser_consistency" => await ToolConsistency(),
                "browser_third_party" => await ToolThirdParty(),
                "browser_compatibility" => await ToolCompatibility(arguments),
                "browser_audit_all" => await ToolAuditAll(arguments),
                "browser_surpriseme" => await ToolSurpriseMe(arguments),
                "browser_monkey_test" => await ToolMonkeyTest(arguments),
                "browser_monkey_trowser" => await ToolMonkeyTrowser(arguments),
                "browser_interrupter" => await ToolInterrupter(arguments),
                "browser_attack_form" => await ToolAttackForm(arguments),
                "browser_fuzz" => await ToolFuzz(arguments),
                "browser_property" => await ToolGetProperty(arguments),
                "browser_console" => await ToolConsole(arguments),
                "browser_console_clear" => ToolConsoleClear(),
                "browser_network" => await ToolNetwork(arguments),
                "browser_network_clear" => ToolNetworkClear(),
                "browser_network_har" => ToolNetworkHar(arguments),
                "browser_downloads" => ToolDownloads(),
                "browser_wait_for_download" => await ToolWaitForDownload(arguments),
                "browser_assert_download" => ToolAssertDownload(arguments),
                "browser_emulation" => await ToolEmulation(arguments),
                "browser_trace" => ToolTrace(arguments),
                "browser_clear_all" => await ToolClearAll(arguments),
                "browser_clear_session" => await ToolClearSession(arguments),
                "browser_wait" => await ToolWait(arguments),
                "browser_wait_for_final_navigation" => await ToolWaitForFinalNavigation(arguments),
                "browser_wait_for_idle" => await ToolWaitForIdle(arguments),
                "browser_assert_text" => await ToolAssertText(arguments),
                "browser_assert_element" => await ToolAssertElement(arguments),
                "browser_assert_url" => await ToolAssertUrl(arguments),
                "browser_assert_title" => await ToolAssertTitle(arguments),
                "browser_tabs" => ToolTabs(),
                "browser_new_tab" => await ToolNewTab(arguments),
                "browser_close_tab" => await ToolCloseTab(arguments),
                "browser_switch_tab" => ToolSwitchTab(arguments),
                "browser_viewport" => await ToolViewport(arguments),
                "browser_webmcp_tools" => await ToolWebMcpTools(),
                "browser_webmcp_call" => await ToolWebMcpCall(arguments),
                "browser_handle_dialog" => await ToolHandleDialog(arguments),
                "browser_dialog" => await ToolGetDialog(),
                "browser_run_script" => await ToolRunScript(arguments),
                "browser_record_start" => await ToolRecordStart(arguments),
                "browser_record_status" => await ToolRecordStatus(arguments),
                "browser_record_stop" => await ToolRecordStop(arguments),
                "browser_mock" => ToolMock(arguments),
                "browser_intercept" => ToolIntercept(arguments),
                "browser_network_throttle" => await ToolNetworkThrottle(arguments),
                "browser_wait_for_network" => await ToolWaitForNetwork(arguments),
                "browser_storage" => await ToolStorage(arguments),
                "browser_fetch" => await ToolFetch(arguments),
                "browser_fetch_batch" => await ToolFetchBatch(arguments),
                "browser_fetch_raw" => await ToolFetchRaw(arguments),
                "browser_header_overrides" => await ToolHeaderOverrides(arguments),
                "browser_ping" => ToolPing(),
                "browser_abort" => await ToolAbort(),
                "browser_orchestrate_list" => await ToolOrchestrateList(),
                "browser_orchestrate_dry_run" => await ToolOrchestrateDryRun(arguments),
                "browser_orchestrate_run" => await ToolOrchestrateRun(arguments),
                "browser_security_help" => await ToolSecurityHelp(),
                "get_test_heuristics" => ToolGetTestHeuristics(),
                "browser_scripting_help" => ToolScriptingHelp(arguments),
                "browser_inspiration" => ToolInspiration(),
                "browser_coverage" => await ToolCoverage(),
                "browser_test_data" => await ToolTestData(arguments),
                "browser_send_message" => await ToolSendMessage(arguments),
                "browser_point" => await ToolPoint(arguments),
                "browser_pointers" => await ToolPointers(arguments),
                "browser_checkpoint" => await ToolCheckpoint(arguments),
                "browser_decide" => await ToolDecide(arguments),
                "browser_decisions" => await ToolDecisions(arguments),
                "browser_journal_add" => await ToolJournalAdd(arguments),
                "browser_journal_get" => ToolJournalGet(arguments),
                "browser_journal_export" => ToolJournalExport(arguments),
                "browser_journal_import" => await ToolJournalImport(arguments),
                "browser_journal_update" => ToolJournalUpdate(arguments),
                "browser_journal_delete" => ToolJournalDelete(arguments),
                "browser_compact" => ToolCompact(arguments),
                "browser_session_memory" => ToolSessionMemory(arguments),
                "browser_ssl_list" => ToolSslList(),
                "browser_ssl_add" => ToolSslAdd(arguments),
                "browser_ssl_remove" => ToolSslRemove(arguments),
                "browser_ssl_set_active" => ToolSslSetActive(arguments),
                "browser_ssl_get_active" => ToolSslGetActive(),
                "browser_peer_register" => await ToolPeerRegister(arguments),
                "browser_peers" => await ToolPeers(),
                "browser_peer_fetch" => await ToolPeerFetch(arguments),
                "browser_peer_state" => await ToolPeerState(arguments),
                "browser_peer_navigate" => await ToolPeerNavigate(arguments),
                "browser_peer_screenshot" => await ToolPeerScreenshot(arguments),
                "browser_peer_unregister" => ToolPeerUnregister(arguments),
                "browser_race_lab_profiles" => await ToolRaceLabProfiles(arguments),
                "browser_race_lab_synchronize" => await ToolRaceLabSynchronize(arguments),
                "browser_race_lab_baseline" => await ToolRaceLabBaseline(arguments),
                "browser_race_lab_run" => await ToolRaceLabRun(arguments),
                "browser_authz_probe" => await ToolAuthzProbe(arguments),
                "browser_authz_diff" => await ToolAuthzDiff(arguments),
                "browser_authz_fuzz" => await ToolAuthzFuzz(arguments),
                "browser_authz_boundary" => await ToolAuthzBoundary(arguments),
                "browser_authz_model" => await ToolAuthzModel(arguments),
                "browser_authz_shadow" => await ToolAuthzShadow(arguments),
                "browser_authz_coverage" => await ToolAuthzCoverage(arguments),
                "browser_session_identity" => await ToolSessionIdentity(),
                "browser_identities" => ToolIdentities(),
                "browser_identity_capture" => await ToolIdentityCapture(arguments),
                "browser_identity_apply" => await ToolIdentityApply(arguments),
                "browser_identity_handoff" => await ToolIdentityHandoff(arguments),
                _ => ErrorContent($"Unknown tool: {toolName}")
            };

            return traceScope != null ? AppendRequestTrace(result, traceScope.Trace) : result;
        }
        catch (Exception ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private async Task<object> ToolsCall(JsonElement? @params)
    {
        if (@params == null)
            throw new InvalidParamsException("Missing params for tools/call");

        var p = @params.Value;
        var toolName = p.TryGetProperty("name", out var n) ? n.GetString() : null;
        if (string.IsNullOrEmpty(toolName))
            throw new InvalidParamsException("Missing 'name' in tools/call params");

        var args = p.TryGetProperty("arguments", out var a) ? a : default;
        return await ExecuteToolAsync(toolName, args);
    }

    #endregion
}
