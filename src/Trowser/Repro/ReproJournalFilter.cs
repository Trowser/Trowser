using Trowser.SessionLog;

namespace Trowser.Repro;

/// <summary>Journal API calls that should not appear in bookmark replay (.trw) or narrated test steps.</summary>
public static class ReproJournalFilter
{
  private static readonly HashSet<string> HousekeepingPaths = new(StringComparer.OrdinalIgnoreCase)
  {
      "/api/bookmark-restore",
      "/api/bookmark-verify",
      "/api/bookmark-export",
      "/api/bookmark-import",
      "/api/bookmark",
      "/api/bookmarks",
      "/api/repro/verify",
      "/api/repro/capture",
      "/api/cookies/clear",
      "/api/cookies/delete",
      "/api/storage/set",
      "/api/storage/clear",
      "/api/storage/delete",
      "/api/clear-session",
      "/api/clear_session",
      "/api/execute-js",
      "/api/wait-for-final-navigation",
      "/api/wait-for-navigation",
      "/api/wait-for-idle",
      "/api/wait",
      "/api/wait-for-network",
      "/api/assert/reset",
      "/api/console/clear",
      "/api/network/clear",
      "/api/mock/clear",
      "/api/intercept/clear",
      "/api/journal",
      "/api/session-memory",
      "/api/message",
      "/api/state",
      "/api/tabs/switch",
      "/api/tabs/close",
  };

  // Calls about the session itself (bookmarks, journal, repro); never a test step, not even in narration.
  private static readonly HashSet<string> MetaPaths = new(StringComparer.OrdinalIgnoreCase)
  {
      "/api/bookmark-restore",
      "/api/bookmark-export",
      "/api/bookmark-import",
      "/api/bookmark-verify",
      "/api/bookmark",
      "/api/bookmarks",
      "/api/repro/verify",
      "/api/repro/capture",
      "/api/journal",
      "/api/session-memory",
      "/api/message",
  };

    public static bool IsHousekeepingApiPath(string? path) =>
        !string.IsNullOrWhiteSpace(path) && HousekeepingPaths.Contains(path.Trim());

    public static bool ShouldCaptureJournalAction(SessionLogger.JournalEntry entry)
    {
        if (!string.Equals(entry.Type, "action", StringComparison.OrdinalIgnoreCase))
            return false;
        if (entry.Fields == null) return false;
        if (!entry.Fields.TryGetValue("path", out var path)) return false;
        return !IsHousekeepingApiPath(path);
    }

    /// <summary>True when a journal action/error row should be narrated as a bookmark step.</summary>
    public static bool ShouldNarrateJournalAction(SessionLogger.JournalEntry entry) =>
        entry.Fields == null || !entry.Fields.TryGetValue("path", out var path)
        || string.IsNullOrWhiteSpace(path) || !MetaPaths.Contains(path.Trim());
}