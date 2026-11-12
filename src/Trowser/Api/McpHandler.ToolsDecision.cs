using System.Text.Json;

namespace Trowser.Api;

/// <summary>
/// MCP tool handlers for decisions (P3). Each delegates to the shared <c>Build*Async</c> on
/// <see cref="TrowserApiServer"/> via <see cref="RenderHostSafe"/>, so the REST route and the MCP
/// tool run identical code.
/// </summary>
public partial class McpHandler
{
    /// <summary>Ask the human to make a call. Backs <c>browser_decide</c>.</summary>
    private Task<object> ToolDecide(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildDecisionAskAsync);

    /// <summary>List / get / withdraw decisions. Backs <c>browser_decisions</c>.</summary>
    private Task<object> ToolDecisions(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildDecisionsAsync);
}
