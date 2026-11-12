using System.IO;

namespace Trowser;

/// <summary>
/// Deletes ephemeral WebView2 user-data folders (<c>tmp-*</c> under Sessions).
/// WebView2 child processes may keep files locked briefly after dispose.
/// </summary>
internal static class EphemeralSessionCleanup
{
    public static bool IsEphemeralFolderName(string folderName) =>
        folderName.StartsWith("tmp-", StringComparison.Ordinal);

    /// <summary>
    /// Best-effort removal of leftover <c>tmp-*</c> session directories from prior runs.
    /// </summary>
    public static void RemoveStaleFolders(string sessionsRoot, string? exceptFolder = null)
    {
        if (!Directory.Exists(sessionsRoot))
            return;

        foreach (var dir in Directory.EnumerateDirectories(sessionsRoot))
        {
            if (!IsEphemeralFolderName(Path.GetFileName(dir)))
                continue;
            if (exceptFolder != null &&
                string.Equals(dir, exceptFolder, StringComparison.OrdinalIgnoreCase))
                continue;

            if (TryDeleteDirectory(dir))
                TrowserLog.Info($"Removed stale ephemeral session folder: {dir}");
        }
    }

    public static bool TryDeleteDirectory(string path, int maxAttempts = 10, int delayMs = 300)
    {
        if (!Directory.Exists(path))
            return true;

        for (var attempt = 0; attempt < maxAttempts; attempt++)
        {
            try
            {
                Directory.Delete(path, recursive: true);
                return true;
            }
            catch (IOException) when (attempt < maxAttempts - 1)
            {
                Thread.Sleep(delayMs);
            }
            catch (UnauthorizedAccessException) when (attempt < maxAttempts - 1)
            {
                Thread.Sleep(delayMs);
            }
        }

        return false;
    }
}
