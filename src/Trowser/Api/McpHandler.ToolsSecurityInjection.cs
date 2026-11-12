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
// These MCP tools delegate to the shared canonical builders on the parent API server (Host),
// so each tool and its matching REST endpoint run identical argument parsing and scan logic.
// Results are rendered as JSON text; safety-gate/validation failures become error content.

private Task<object> ToolSecurityPathTraversal(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityPathTraversalAsync);

private Task<object> ToolSecuritySmuggling(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySmugglingAsync);

private Task<object> ToolSecurityHostHeader(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityHostHeaderAsync);

private Task<object> ToolSecurityWafBypass(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityWafBypassAsync);

private Task<object> ToolSecuritySqliScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySqliScanAsync);

private Task<object> ToolSecuritySqliLoginSweep(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySqliLoginSweepAsync);

private Task<object> ToolSecurityNosqlScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityNosqlScanAsync);

private Task<object> ToolSecurityLdapScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityLdapScanAsync);

private Task<object> ToolSecuritySstiScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySstiScanAsync);

private Task<object> ToolSecuritySstiPolyglotScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySstiPolyglotScanAsync);

private Task<object> ToolSecuritySstiStoredScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySstiStoredScanAsync);

private Task<object> ToolSecurityPrototypePollutionScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityPrototypePollutionScanAsync);

private Task<object> ToolSecurityCstiScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCstiScanAsync);

private Task<object> ToolSecurityXssScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityXssScanAsync);

private Task<object> ToolSecurityParserProbe(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityParserProbeAsync);

private Task<object> ToolSecurityDeserializationScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityDeserializationScanAsync);

private Task<object> ToolSecurityFileUploadScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityFileUploadScanAsync);

private Task<object> ToolSecurityCmdCanary(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCmdCanaryAsync);

private Task<object> ToolSecurityXss() =>
    RenderHostSafe(default, h => h.BuildSecurityXssAsync);

private Task<object> ToolMixedContent() =>
    RenderHostSafe(default, h => h.BuildMixedContentAsync);
}
