using Trowser.Security.RaceLab;

namespace Trowser.Automation;

public partial class AutomationContext
{
    public async Task<RaceLabSyncResult> RunRaceLabSynchronizeAsync(
        RaceLabProfile profile,
        bool ensurePeerOrigin = true,
        CancellationToken ct = default)
    {
        var engine = new RaceLabEngine(this, PeerRegistry, _logColored);
        return await engine.SynchronizeAsync(profile.Requests, profile.Parameters, ensurePeerOrigin, ct);
    }

    public async Task<List<RaceLabTimelineEntry>> RunRaceLabBaselineAsync(
        RaceLabProfile profile,
        CancellationToken ct = default)
    {
        var engine = new RaceLabEngine(this, PeerRegistry, _logColored);
        return await engine.RunBaselineAsync(profile, ct);
    }

    public async Task<RaceLabRunResult> RunRaceLabAsync(
        RaceLabProfile profile,
        RaceLabRunOptions? options = null,
        CancellationToken ct = default)
    {
        options ??= new RaceLabRunOptions();
        var engine = new RaceLabEngine(this, PeerRegistry, _logColored);
        return await engine.RunFullAsync(profile, options, ct: ct);
    }
}
