using System.Text.Json;

namespace Trowser.Api;

/// <summary>
/// MCP tool handlers for the pointer primitive (P0). Each delegates to the shared
/// <c>Build*Async</c> on <see cref="TrowserApiServer"/> via <see cref="RenderHostSafe"/>,
/// so the REST route and the MCP tool run identical code.
/// </summary>
public partial class McpHandler
{
    /// <summary>Create a pointer (agent→human). Backs <c>browser_point</c>.</summary>
    private Task<object> ToolPoint(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildPointerCreateAsync);

    /// <summary>List / get / re-resolve pointers. Backs <c>browser_pointers</c>.</summary>
    private Task<object> ToolPointers(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildPointersAsync);

    /// <summary>Create / list / get checkpoints. Backs <c>browser_checkpoint</c>.</summary>
    private Task<object> ToolCheckpoint(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildCheckpointToolAsync);
}
