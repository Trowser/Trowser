using System.Net;
using Trowser.Security;
using Trowser.Security.Orchestration;
using Trowser.Security.RaceLab;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    private async Task HandleGetRaceLabProfiles(HttpListenerResponse response)
    {
        var profiles = RaceLabSettings.Load();
        await WriteSuccess(response, new
        {
            profiles = profiles.Select(p => new
            {
                p.Name,
                builtIn = p.IsBuiltIn,
                requestCount = p.Requests.Count,
                parameters = SerializeRaceLabParameters(p.Parameters),
                requests = p.Requests
            })
        });
    }

    private Task HandlePostRaceLabProfiles(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildRaceLabProfilesSaveAsync);

    internal Task<object> BuildRaceLabProfilesSaveAsync(JsonBody body)
    {
        var profile = RaceLabJson.ParseProfile(body);
        if (string.IsNullOrWhiteSpace(profile.Name))
            throw new ApiCommandException(400, "Profile name is required.");

        if (profile.IsBuiltIn)
            throw new ApiCommandException(400, "Built-in presets cannot be overwritten. Save under a new name.");

        var user = RaceLabSettings.Load().Where(p => !p.IsBuiltIn).ToList();
        user.RemoveAll(p => string.Equals(p.Name, profile.Name, StringComparison.OrdinalIgnoreCase));
        user.Add(profile);
        RaceLabSettings.Save(user);

        return Task.FromResult<object>(new { saved = true, name = profile.Name });
    }

    private async Task HandleDeleteRaceLabProfile(string name, HttpListenerResponse response)
    {
        if (RaceLabSettings.IsBuiltInName(name))
        {
            await WriteError(response, 400, "Built-in Race Lab presets cannot be deleted.");
            return;
        }

        var user = RaceLabSettings.Load().Where(p => !p.IsBuiltIn).ToList();
        var removed = user.RemoveAll(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) > 0;
        if (!removed)
        {
            await WriteError(response, 404, $"Race Lab profile \"{name}\" was not found.");
            return;
        }

        RaceLabSettings.Save(user);
        await WriteSuccess(response, new { deleted = true, name });
    }

    private Task HandlePostRaceLabProfilesExport(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildRaceLabProfilesExportAsync);

    internal Task<object> BuildRaceLabProfilesExportAsync(JsonBody body)
    {
        var names = body.GetStringArray("names");
        var all = RaceLabSettings.Load();
        var selected = names is { Count: > 0 }
            ? all.Where(p => names.Contains(p.Name, StringComparer.OrdinalIgnoreCase)).ToList()
            : all.Where(p => !p.IsBuiltIn).ToList();

        if (selected.Count == 0)
            throw new ApiCommandException(400, "No profiles matched for export.");

        return Task.FromResult<object>(new
        {
            format = "trowser-race-lab-profiles",
            json = RaceLabSettings.ExportToJson(selected)
        });
    }

    private Task HandlePostRaceLabProfilesImport(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildRaceLabProfilesImportAsync);

    internal Task<object> BuildRaceLabProfilesImportAsync(JsonBody body)
    {
        var json = body.GetString("json") ?? body.GetRawJson("profilesJson");
        if (string.IsNullOrWhiteSpace(json))
            throw new ApiCommandException(400, "Field 'json' (export payload) is required.");

        var imported = RaceLabSettings.ImportFromJson(json);
        var user = RaceLabSettings.Load().Where(p => !p.IsBuiltIn).ToList();

        foreach (var p in imported.Where(p => !p.IsBuiltIn))
        {
            user.RemoveAll(x => string.Equals(x.Name, p.Name, StringComparison.OrdinalIgnoreCase));
            user.Add(p);
        }

        RaceLabSettings.Save(user);
        return Task.FromResult<object>(new { imported = imported.Count, names = imported.Select(p => p.Name).ToList() });
    }

    private Task HandlePostRaceLabSynchronize(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildRaceLabSynchronizeAsync);

    internal async Task<object> BuildRaceLabSynchronizeAsync(JsonBody body)
    {
        var profile = RaceLabJson.ParseProfile(body);
        if (profile.Requests.Count == 0)
            throw new ApiCommandException(400, "At least one request is required.");

        var sync = await _context.RunRaceLabSynchronizeAsync(
            profile,
            body.GetBool("ensurePeerOrigin", true),
            _operationCts?.Token ?? default);

        return new
        {
            message = "Latency compensation complete.",
            medianRttMs = sync.MedianRttMs,
            dispatchOffsetMs = sync.DispatchOffsetMs
        };
    }

    private Task HandlePostRaceLabBaseline(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildRaceLabBaselineAsync);

    internal async Task<object> BuildRaceLabBaselineAsync(JsonBody body)
    {
        var profile = RaceLabJson.ParseProfile(body);
        if (profile.Requests.Count == 0)
            throw new ApiCommandException(400, "At least one request is required.");

        if (profile.Requests.Any(r => !HttpMethodIsSafe(r.Method)))
        {
            var gateError = SafetyGate.RequireActive(body,
                "Race Lab baseline sends each configured request once, including state-changing methods");
            if (gateError != null)
                throw new ApiCommandException(400, gateError.Value);
        }

        var baseline = await _context.RunRaceLabBaselineAsync(profile, _operationCts?.Token ?? default);
        return new
        {
            message = "Baseline complete.",
            baseline = baseline.Select(RaceLabJson.TimelineEntryToApi).ToList()
        };
    }

    private static bool HttpMethodIsSafe(string? method) =>
        string.IsNullOrWhiteSpace(method) is false
        && (method.Equals("GET", StringComparison.OrdinalIgnoreCase)
            || method.Equals("HEAD", StringComparison.OrdinalIgnoreCase)
            || method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase));

    private Task HandlePostRaceLabRun(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildRaceLabRunAsync);

    internal async Task<object> BuildRaceLabRunAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body,
            "Race Lab sends concurrent HTTP bursts that may create duplicate resources or expose TOCTOU flaws");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var profile = RaceLabJson.ParseProfile(body);
        if (profile.Requests.Count == 0)
            throw new ApiCommandException(400, "At least one request is required.");

        var options = new RaceLabRunOptions
        {
            RunSync = body.GetBool("runSync", true),
            RunBaseline = body.GetBool("runBaseline", true),
            EnsurePeerOrigin = body.GetBool("ensurePeerOrigin", true)
        };

        var result = await _context.RunRaceLabAsync(profile, options, _operationCts?.Token ?? default);

        var includeHygiene = body.GetBool("includeHygiene", false);
        var minConfidence = body.GetString("minConfidence") ?? SecurityConfidence.Likely;
        return result.ToScanResult(profile.Name).ToApiResponse(includeHygiene, minConfidence);
    }

    private static object SerializeRaceLabParameters(RaceLabParameters p) => new
    {
        mode = p.Mode.ToString().ToLowerInvariant(),
        p.RequestsPerBatch,
        p.DelayPerRequestMs,
        p.DelayBetweenBatchesMs,
        p.TotalBatches,
        p.DurationMs,
        p.RandomizeOrder,
        p.JitterMs,
        p.TimeoutMs,
        p.IncludeBrowserCookies
    };

    internal async Task<bool> TryRouteRaceLabAsync(string path, string method, HttpListenerRequest request, HttpListenerResponse response)
    {
        switch (path)
        {
            case "/api/race-lab/profiles" when method == "GET":
                await HandleGetRaceLabProfiles(response);
                return true;
            case "/api/race-lab/profiles" when method == "POST":
                await HandlePostRaceLabProfiles(request, response);
                return true;
            case "/api/race-lab/profiles/export" when method == "POST":
                await HandlePostRaceLabProfilesExport(request, response);
                return true;
            case "/api/race-lab/profiles/import" when method == "POST":
                await HandlePostRaceLabProfilesImport(request, response);
                return true;
            case "/api/race-lab/synchronize" when method == "POST":
                await HandlePostRaceLabSynchronize(request, response);
                return true;
            case "/api/race-lab/baseline" when method == "POST":
                await HandlePostRaceLabBaseline(request, response);
                return true;
            case "/api/race-lab/run" when method == "POST":
                await HandlePostRaceLabRun(request, response);
                return true;
        }

        if (path.StartsWith("/api/race-lab/profiles/", StringComparison.OrdinalIgnoreCase) && method == "DELETE")
        {
            var name = Uri.UnescapeDataString(path["/api/race-lab/profiles/".Length..]);
            await HandleDeleteRaceLabProfile(name, response);
            return true;
        }

        return false;
    }
}
