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
private Task<object> ToolSecurityTrustedHeaderBypass(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityTrustedHeaderBypassAsync);

private Task<object> ToolSecurityDefaultCredentialCanary(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityDefaultCredentialCanaryAsync);

private Task<object> ToolSecuritySupplyChainScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySupplyChainScanAsync);

private Task<object> ToolSecurityOsvCheck(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityOsvCheckAsync);

private Task<object> ToolSecurityJsAudit(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityJsAuditAsync);

private Task<object> ToolSecurityNucleiScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityNucleiScanAsync);

private Task<object> ToolSecurityNucleiTemplates(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityNucleiTemplatesAsync);

private Task<object> ToolSecurityTlsIntrospection(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityTlsIntrospectionAsync);

private Task<object> ToolSecuritySourceMaps() =>
    RenderHostSafe(default, h => h.BuildSourceMapsAsync);
}
