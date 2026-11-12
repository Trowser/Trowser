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
private Task<object> ToolSecurityLlmRedteamScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityLlmRedteamScanAsync);

private Task<object> ToolSecurityLlmEndpointDiscover(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityLlmEndpointDiscoverAsync);

private Task<object> ToolSecurityLlmChatInteract(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityLlmChatInteractAsync);

private Task<object> ToolSecurityLlmHttpSend(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityLlmHttpSendAsync);

private Task<object> ToolSecurityLlmHttpMcpList(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityLlmHttpMcpListAsync);

private Task<object> ToolSecurityLlmSinkAssist(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityLlmSinkAssistAsync);

private Task<object> ToolSecurityLlmRedteamProbes(JsonElement args) =>
    Task.FromResult(LlmRedTeamRequestParser.FormatProbeCatalog());
}
