using System.Collections.Concurrent;
using System.Diagnostics;

namespace Trowser.Peers;

/// <summary>Tracks child Trowser processes launched via API spawn (when GUI PeerSessionManager is absent).</summary>
internal static class PeerProcessTracker
{
    private static readonly ConcurrentDictionary<string, Process> Processes =
        new(StringComparer.OrdinalIgnoreCase);

    public static void Track(string peerName, Process process) =>
        Processes[peerName] = process;

    public static bool TryStop(string peerName, out string? error)
    {
        error = null;
        if (!Processes.TryRemove(peerName, out var process) || process == null)
            return false;

        try
        {
            if (process.HasExited)
                return true;

            process.CloseMainWindow();
            if (!process.WaitForExit(3000))
                process.Kill(entireProcessTree: true);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
