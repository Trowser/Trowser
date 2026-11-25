using System.IO;
using Trowser.SessionLog;

namespace Trowser.Bookmarks;

/// <summary>Remove or copy on-disk bookmark evidence that a journal row points at.</summary>
public static class BookmarkEvidenceCleanup
{
    /// <summary>
    /// Delete the evidence files of a removed bookmark row. Only the files Trowser writes
    /// (<see cref="BookmarkFields.KnownFiles"/>) are deleted, only from a folder named after the
    /// bookmark id, and only when no remaining row still points at the same folder. The folder
    /// itself is removed only when it is then empty. Imported journals can carry arbitrary paths,
    /// so this never deletes recursively.
    /// </summary>
    public static void TryDeleteFolder(SessionLogger.JournalEntry? entry,
        IEnumerable<SessionLogger.JournalEntry>? remaining = null)
    {
        var full = OwnedFolder(entry);
        if (full == null) return;

        if (remaining != null && remaining.Any(e => e.Fields != null && BookmarkFields.HasEvidence(e.Fields)
                && SameFolder(e.Fields.GetValueOrDefault(BookmarkFields.Directory), full)))
            return;

        try
        {
            if (!Directory.Exists(full)) return;
            foreach (var name in BookmarkFields.KnownFiles)
            {
                var file = Path.Combine(full, name);
                if (File.Exists(file)) File.Delete(file);
            }
            if (!Directory.EnumerateFileSystemEntries(full).Any())
                Directory.Delete(full);
        }
        catch { /* best effort */ }
    }

    /// <summary>
    /// Give an imported bookmark row a fresh id (its id is already used by a live row) and copy
    /// its evidence into a sibling folder named after the new id, so the two rows never share files.
    /// Path fields that pointed into the old folder are rewritten; others are left as they were.
    /// </summary>
    public static void RemapId(Dictionary<string, string> fields, string newId)
    {
        var oldId = fields.GetValueOrDefault(BookmarkFields.BookmarkId) ?? "";
        fields[BookmarkFields.BookmarkId] = newId;
        if (!fields.ContainsKey(BookmarkFields.ImportedId) && !string.IsNullOrEmpty(oldId))
            fields[BookmarkFields.ImportedId] = oldId;

        var oldDir = OwnedFolder(fields, oldId);
        if (oldDir == null) return;

        var parent = Path.GetDirectoryName(oldDir);
        if (string.IsNullOrEmpty(parent)) return;
        var newDir = Path.Combine(parent, newId);
        try
        {
            if (Directory.Exists(oldDir))
            {
                Directory.CreateDirectory(newDir);
                foreach (var name in BookmarkFields.KnownFiles)
                {
                    var src = Path.Combine(oldDir, name);
                    if (File.Exists(src)) File.Copy(src, Path.Combine(newDir, name), overwrite: true);
                }
            }
        }
        catch { return; }

        fields[BookmarkFields.Directory] = newDir;
        foreach (var key in new[] { BookmarkFields.Screenshot, BookmarkFields.TrwPath, BookmarkFields.StatePath })
        {
            if (!fields.TryGetValue(key, out var path) || string.IsNullOrWhiteSpace(path)) continue;
            string fullPath;
            try { fullPath = Path.GetFullPath(path); }
            catch { continue; }
            if (SameFolder(Path.GetDirectoryName(fullPath), oldDir))
                fields[key] = Path.Combine(newDir, Path.GetFileName(fullPath));
        }
    }

    private static string? OwnedFolder(SessionLogger.JournalEntry? entry) =>
        entry?.Fields == null || !BookmarkFields.HasEvidence(entry.Fields)
            ? null
            : OwnedFolder(entry.Fields, entry.Fields.GetValueOrDefault(BookmarkFields.BookmarkId));

    /// <summary>The bookmark folder when it is a local folder whose name is the bookmark id; otherwise null.</summary>
    private static string? OwnedFolder(Dictionary<string, string> fields, string? bookmarkId)
    {
        if (string.IsNullOrWhiteSpace(bookmarkId) || !bookmarkId.StartsWith("bm-", StringComparison.Ordinal))
            return null;
        if (!fields.TryGetValue(BookmarkFields.Directory, out var dir) || string.IsNullOrWhiteSpace(dir))
            return null;
        if (Trowser.Api.ExportPathGuard.IsRemoteOrDevicePath(dir)) return null;
        try
        {
            var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dir));
            return string.Equals(Path.GetFileName(full), bookmarkId, StringComparison.OrdinalIgnoreCase) ? full : null;
        }
        catch { return null; }
    }

    private static bool SameFolder(string? a, string b)
    {
        if (string.IsNullOrWhiteSpace(a)) return false;
        try
        {
            return string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(a)),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(b)), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
