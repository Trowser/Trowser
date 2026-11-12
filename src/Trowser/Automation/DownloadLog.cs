using System.IO;

namespace Trowser.Automation;

/// <summary>State of a captured browser download.</summary>
public enum DownloadState
{
    InProgress,
    Completed,
    Interrupted,
    Cancelled
}

/// <summary>
/// One download captured via WebView2 DownloadStarting.
/// Scripting property names (C#): <see cref="BytesReceived"/>, <see cref="MimeType"/>, <see cref="SuggestedFileName"/>.
/// REST JSON uses shorter aliases: <c>bytes</c>, <c>mime</c>, <c>suggestedFileName</c>.
/// </summary>
public record DownloadEntry
{
    public int Id { get; init; }
    public string Url { get; init; } = "";
    public string SuggestedFileName { get; init; } = "";
    public string Path { get; init; } = "";
    public DownloadState State { get; init; } = DownloadState.InProgress;
    public long BytesReceived { get; init; }
    public long? TotalBytes { get; init; }
    public string MimeType { get; init; } = "";
    public DateTime Timestamp { get; init; }
    public string? InterruptReason { get; init; }

    /// <summary>Alias for <see cref="BytesReceived"/> (agents often try <c>.Bytes</c>).</summary>
    public long Bytes => BytesReceived;

    /// <summary>Alias for <see cref="BytesReceived"/>.</summary>
    public long ByteCount => BytesReceived;

    /// <summary>Alias for <see cref="MimeType"/> (REST field <c>mime</c>).</summary>
    public string Mime => MimeType;

    /// <summary>Alias for <see cref="SuggestedFileName"/>.</summary>
    public string FileName => SuggestedFileName;

    public override string ToString() =>
        $"[{State}] {SuggestedFileName} ({BytesReceived} bytes) {Url}";

    /// <summary>True when the download finished successfully and the result file is present (when a path was set).</summary>
    public bool IsReady =>
        State == DownloadState.Completed &&
        (string.IsNullOrEmpty(Path) || File.Exists(Path));
}

/// <summary>Thread-safe per-tab download log (mirrors <see cref="NetworkLog"/> / <see cref="ConsoleLog"/>).</summary>
public class DownloadLog
{
    private readonly List<DownloadEntry> _entries = new();
    private readonly object _lock = new();
    private int _nextId = 1;
    private readonly List<TaskCompletionSource<DownloadEntry>> _waiters = new();

    public List<DownloadEntry> Entries
    {
        get { lock (_lock) return new List<DownloadEntry>(_entries); }
    }

    public int Count
    {
        get { lock (_lock) return _entries.Count; }
    }

    public event Action<DownloadEntry>? EntryAdded;
    public event Action<DownloadEntry>? EntryUpdated;

    internal DownloadEntry Add(DownloadEntry entry)
    {
        DownloadEntry stored;
        lock (_lock)
        {
            stored = entry with { Id = _nextId++ };
            _entries.Add(stored);
        }

        EntryAdded?.Invoke(stored);
        // Only wake waiters when the download is already terminal (rare); normally they wait for Update→Completed.
        if (IsTerminalSuccess(stored) || IsTerminalFailure(stored))
            NotifyWaiters(stored);
        return stored;
    }

    internal DownloadEntry? Update(int id, Func<DownloadEntry, DownloadEntry> mutator)
    {
        DownloadEntry? updated = null;
        lock (_lock)
        {
            for (var i = 0; i < _entries.Count; i++)
            {
                if (_entries[i].Id != id) continue;
                updated = mutator(_entries[i]);
                _entries[i] = updated;
                break;
            }
        }

        if (updated != null)
        {
            EntryUpdated?.Invoke(updated);
            if (IsTerminalSuccess(updated) || IsTerminalFailure(updated))
                NotifyWaiters(updated);
        }
        return updated;
    }

    private void NotifyWaiters(DownloadEntry entry)
    {
        List<TaskCompletionSource<DownloadEntry>> waiters;
        lock (_lock)
        {
            waiters = _waiters.ToList();
            _waiters.Clear();
        }
        foreach (var w in waiters)
            w.TrySetResult(entry);
    }

    private static bool IsTerminalSuccess(DownloadEntry e) =>
        e.State == DownloadState.Completed;

    private static bool IsTerminalFailure(DownloadEntry e) =>
        e.State is DownloadState.Interrupted or DownloadState.Cancelled;

    /// <summary>
    /// Wait until a matching download reaches <see cref="DownloadState.Completed"/>
    /// and the result file exists (when a path is set). Interrupted/cancelled downloads throw.
    /// </summary>
    public async Task<DownloadEntry> WaitForAsync(
        string? fileNameContains = null,
        int timeoutMs = 30000,
        int afterId = 0,
        CancellationToken cancellationToken = default)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(Math.Max(1, timeoutMs));

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            DownloadEntry? ready = null;
            DownloadEntry? failed = null;
            lock (_lock)
            {
                foreach (var e in _entries)
                {
                    if (e.Id <= afterId) continue;
                    if (!Matches(e, fileNameContains)) continue;
                    if (IsTerminalFailure(e))
                    {
                        failed = e;
                        break;
                    }
                    if (IsTerminalSuccess(e) && FileReady(e))
                    {
                        ready = e;
                        break;
                    }
                }
            }

            if (failed != null)
                throw new InvalidOperationException(
                    $"Download '{failed.SuggestedFileName}' ended as {failed.State}" +
                    (string.IsNullOrEmpty(failed.InterruptReason) ? "." : $": {failed.InterruptReason}"));

            if (ready != null)
                return ready;

            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
                throw new TimeoutException(
                    string.IsNullOrEmpty(fileNameContains)
                        ? $"No completed download within {timeoutMs}ms"
                        : $"No completed download matching '{fileNameContains}' within {timeoutMs}ms");

            TaskCompletionSource<DownloadEntry> tcs;
            lock (_lock)
            {
                // Re-check under lock
                foreach (var e in _entries)
                {
                    if (e.Id <= afterId) continue;
                    if (!Matches(e, fileNameContains)) continue;
                    if (IsTerminalFailure(e))
                        throw new InvalidOperationException(
                            $"Download '{e.SuggestedFileName}' ended as {e.State}" +
                            (string.IsNullOrEmpty(e.InterruptReason) ? "." : $": {e.InterruptReason}"));
                    if (IsTerminalSuccess(e) && FileReady(e))
                        return e;
                }

                tcs = new TaskCompletionSource<DownloadEntry>(TaskCreationOptions.RunContinuationsAsynchronously);
                _waiters.Add(tcs);
            }

            // Also poll: Completed can race with file flush before NotifyWaiters, and waiters
            // may be woken by an unrelated download.
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var slice = remaining > TimeSpan.FromMilliseconds(250) ? TimeSpan.FromMilliseconds(250) : remaining;
            cts.CancelAfter(slice);
            try
            {
                await using var reg = cts.Token.Register(() => tcs.TrySetCanceled(cts.Token));
                var entry = await tcs.Task.ConfigureAwait(false);
                if (!Matches(entry, fileNameContains))
                    continue;
                if (IsTerminalFailure(entry))
                    throw new InvalidOperationException(
                        $"Download '{entry.SuggestedFileName}' ended as {entry.State}" +
                        (string.IsNullOrEmpty(entry.InterruptReason) ? "." : $": {entry.InterruptReason}"));
                if (IsTerminalSuccess(entry))
                {
                    // Brief poll for on-disk file after Completed.
                    if (await WaitUntilFileReadyAsync(entry, deadline, cancellationToken).ConfigureAwait(false) is { } done)
                        return done;
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Slice timeout — loop and re-check entries / overall deadline.
            }
            finally
            {
                lock (_lock) _waiters.Remove(tcs);
            }
        }
    }

    private static bool FileReady(DownloadEntry e)
    {
        if (string.IsNullOrEmpty(e.Path)) return true;
        try { return File.Exists(e.Path); }
        catch { return false; }
    }

    private async Task<DownloadEntry?> WaitUntilFileReadyAsync(
        DownloadEntry entry, DateTime deadline, CancellationToken cancellationToken)
    {
        while (true)
        {
            // Refresh from log (bytes may update after Completed).
            DownloadEntry? current;
            lock (_lock)
                current = _entries.FirstOrDefault(e => e.Id == entry.Id) ?? entry;

            if (FileReady(current))
                return current;

            if (DateTime.UtcNow >= deadline)
                return null;

            cancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(50, cancellationToken).ConfigureAwait(false);
        }
    }

    public void Clear(bool deleteFiles = false)
    {
        List<string> paths;
        lock (_lock)
        {
            paths = deleteFiles
                ? _entries.Select(e => e.Path).Where(p => !string.IsNullOrEmpty(p)).ToList()
                : new List<string>();
            _entries.Clear();
        }

        if (!deleteFiles) return;
        foreach (var path in paths)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch { /* best-effort */ }
        }
    }

    public static bool Matches(DownloadEntry entry, string? fileNameContains)
    {
        if (string.IsNullOrEmpty(fileNameContains)) return true;
        return entry.SuggestedFileName.Contains(fileNameContains, StringComparison.OrdinalIgnoreCase)
               || Path.GetFileName(entry.Path).Contains(fileNameContains, StringComparison.OrdinalIgnoreCase);
    }
}
