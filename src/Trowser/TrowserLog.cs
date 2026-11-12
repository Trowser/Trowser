using System.IO;

namespace Trowser;

/// <summary>
/// Simple file logger for diagnostics. Writes to %APPDATA%\Trowser\trowser.log.
/// Rotates when the file exceeds 5 MB.
/// </summary>
public static class TrowserLog
{
    private static readonly object _lock = new();
    private static readonly string _logPath;
    private const long MaxFileSize = 5 * 1024 * 1024;

    static TrowserLog()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Trowser");
        Directory.CreateDirectory(dir);
        _logPath = Path.Combine(dir, "trowser.log");
    }

    public static void Info(string message) => Write("INFO", message);
    public static void Warn(string message) => Write("WARN", message);
    public static void Error(string message) => Write("ERROR", message);
    public static void Error(string message, Exception ex) => Write("ERROR", $"{message}: {ex.Message}");

    /// <summary>Records an exception a best-effort step chose to swallow, so a skipped check is still traceable.</summary>
    public static void Swallowed(Exception ex,
        [System.Runtime.CompilerServices.CallerMemberName] string member = "",
        [System.Runtime.CompilerServices.CallerFilePath] string file = "",
        [System.Runtime.CompilerServices.CallerLineNumber] int line = 0) =>
        Write("WARN", $"Best-effort step failed in {Path.GetFileName(file)}:{line} {member}: {ex.GetType().Name}: {ex.Message}");

    private static void Write(string level, string message)
    {
        try
        {
            lock (_lock)
            {
                RotateIfNeeded();
                var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}";
                File.AppendAllText(_logPath, line + Environment.NewLine);
            }
        }
        catch { }
    }

    private static void RotateIfNeeded()
    {
        try
        {
            if (!File.Exists(_logPath)) return;
            var info = new FileInfo(_logPath);
            if (info.Length > MaxFileSize)
            {
                var backup = _logPath + ".old";
                if (File.Exists(backup)) File.Delete(backup);
                File.Move(_logPath, backup);
            }
        }
        catch { }
    }
}
