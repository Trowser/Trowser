namespace Trowser.Scripting;

/// <summary>
/// Coordinates stop and pause/resume for a running C# script.
/// Stop uses cancellation; pause blocks at automation checkpoints without cancelling.
/// </summary>
public sealed class ScriptRunControl : IDisposable
{
    private readonly CancellationTokenSource _stopCts = new();
    private readonly ManualResetEventSlim _runGate = new(initialState: true);

    public CancellationToken StopToken => _stopCts.Token;

    public bool IsPaused => !_runGate.IsSet;

    public bool IsStopped => _stopCts.IsCancellationRequested;

    public void Pause() => _runGate.Reset();

    public void Resume() => _runGate.Set();

    public void Stop()
    {
        _stopCts.Cancel();
        _runGate.Set();
    }

    /// <summary>
    /// Blocks while the script is paused. Throws when stopped.
    /// </summary>
    public async Task WaitIfRunningAsync(CancellationToken cancellationToken)
    {
        while (!_runGate.IsSet)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(50, cancellationToken).ConfigureAwait(false);
        }
    }

    public void Dispose()
    {
        Stop();
        _runGate.Dispose();
        _stopCts.Dispose();
    }
}
