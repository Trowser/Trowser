using System.Text.Json;
using Trowser;
using Trowser.Security.RaceLab;

namespace Trowser.Api;

public partial class McpHandler
{
    private Task<object> ToolRaceLabProfiles(JsonElement args)
    {
        var mode = GetString(args, "mode") ?? "list";
        return mode.ToLowerInvariant() switch
        {
            "list" => Task.FromResult<object>(TextContent(JsonSerializer.Serialize(new
            {
                profiles = RaceLabSettings.Load().Select(p => new
                {
                    p.Name,
                    builtIn = p.IsBuiltIn,
                    requestCount = p.Requests.Count
                })
            }, CompactJson))),
            "export" => RenderHostSafe(args, h => h.BuildRaceLabProfilesExportAsync),
            "import" => RenderHostSafe(args, h => h.BuildRaceLabProfilesImportAsync),
            "save" => RenderHostSafe(args, h => h.BuildRaceLabProfilesSaveAsync),
            _ => Task.FromResult<object>(ErrorContent("mode must be list, save, export, or import"))
        };
    }

    private Task<object> ToolRaceLabSynchronize(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildRaceLabSynchronizeAsync);

    private Task<object> ToolRaceLabBaseline(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildRaceLabBaselineAsync);

    private Task<object> ToolRaceLabRun(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildRaceLabRunAsync);
}
