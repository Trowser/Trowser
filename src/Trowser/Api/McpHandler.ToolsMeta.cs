using System.Text;
using System.Text.Json;
using Trowser.Security.Orchestration;

namespace Trowser.Api;

public partial class McpHandler
{
    private Task<object> ToolPing() =>
        Host == null
            ? Task.FromResult<object>(ErrorContent(
                "This tool requires the REST API server to be running."))
            : Task.FromResult<object>(TextContent(JsonSerializer.Serialize(Host.BuildPingPayload(), CompactJson)));

    private async Task<object> ToolAbort()
    {
        if (Host == null)
            return ErrorContent("This tool requires the REST API server to be running.");
        var data = await Host.BuildAbortOperationAsync();
        return TextContent(JsonSerializer.Serialize(data, CompactJson));
    }

    private Task<object> ToolOrchestrateList() =>
        RenderHostSafe(default, h => h.BuildOrchestratePlaybooksForMcpAsync);

    private Task<object> ToolOrchestrateDryRun(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildOrchestrateDryRunFromBodyAsync);

    private Task<object> ToolOrchestrateRun(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildOrchestrateRunAsync);

    private Task<object> ToolSecurityHelp() =>
        Task.FromResult<object>(TextContent(SecurityMcpHelpText));

    private const string SecurityMcpHelpText =
        """
        Trowser MCP security workflow (mode=security for full scanner pack):
        1. browser_navigate — browse key flows; use ignoreCertificateErrors on training sites with bad TLS.
        2. browser_attack_surface (spaMode:true if network log is empty) — map APIs; follow recommendedNext when sparse.
        3. Targeted scans — browser_security_xss_scan, browser_security_sqli_scan, browser_security_cors (includeAttackSurfaceUrls:true), browser_fetch for proof.
        4. browser_audit_all — rollup; browser_security_auto_scan only with scanDepth:quick and explicit maxStepSeconds (MCP caps at 55s by default).
        5. Follow nextActionItems on findings (mcp tool + args); use browser_trace_input / browser_security_verify to confirm.
        Long scans: one browser-touching tool at a time; use browser_abort to cancel; poll with browser_console / browser_network / browser_ping without blocking.
        Orchestration playbooks: browser_orchestrate_list, browser_orchestrate_dry_run, browser_orchestrate_run (REST: /api/orchestrate/*).
        browser_security = passive Security Scan overview (tech stack, CVEs, headers, CORS, XSS, cookies, storage, methods, discover); browser_security_js_libraries = Retire.js CVEs only; browser_audit_all = full page health rollup.
        """;
}
