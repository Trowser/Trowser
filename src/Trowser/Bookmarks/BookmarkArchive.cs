using System.IO;
using System.IO.Compression;
using Trowser.SessionLog;

namespace Trowser.Bookmarks;

/// <summary>
/// Zip of one bookmark: <c>bookmark.json</c> (the journal bundle shape, one entry) plus the files in
/// its folder. Cookie and storage values are redacted on export, and an imported bookmark never
/// offers Go, so a zip cannot plant session state.
/// </summary>
public static class BookmarkArchive
{
    private const long MaxEntryBytes = 25L * 1024 * 1024;

    private static readonly string[] EvidenceFiles =
    [
        BookmarkFields.ScreenshotFile, BookmarkFields.TrwFile, BookmarkFields.StateFile
    ];

    /// <summary>Write <paramref name="entry"/> and its evidence to <paramref name="zipPath"/> (already validated by the caller).</summary>
    public static ExportResult Export(SessionLogger.JournalEntry entry, string zipPath)
    {
        if (!BookmarkInfo.HasBookmarkEvidence(entry))
            throw new InvalidOperationException($"Journal entry #{entry.Index} is not a bookmark.");
        var info = BookmarkInfo.FromEntry(entry);

        var fields = entry.Fields == null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(entry.Fields, StringComparer.OrdinalIgnoreCase);
        fields.Remove(BookmarkFields.Directory);

        var dir = Path.GetDirectoryName(Path.GetFullPath(zipPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var files = new List<string>();
        var stateRedacted = false;
        using (var stream = new FileStream(zipPath, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            AddFile(zip, info.Screenshot, BookmarkFields.ScreenshotFile, BookmarkFields.Screenshot, fields, files);
            AddFile(zip, info.TrwPath, BookmarkFields.TrwFile, BookmarkFields.TrwPath, fields, files);

            fields.Remove(BookmarkFields.StatePath);
            fields.Remove(BookmarkFields.StateRedacted);
            if (!string.IsNullOrEmpty(info.StatePath) && File.Exists(info.StatePath))
            {
                var snapshot = BookmarkEvidence.DeserializeState(File.ReadAllText(info.StatePath));
                var redacted = BookmarkEvidence.Redact(snapshot);
                WriteText(zip, BookmarkFields.StateFile, BookmarkEvidence.SerializeState(redacted));
                fields[BookmarkFields.StatePath] = BookmarkFields.StateFile;
                fields[BookmarkFields.StateRedacted] = "true";
                files.Add(BookmarkFields.StateFile);
                stateRedacted = true;
            }

            var copy = new SessionLogger.JournalEntry
            {
                Index = entry.Index,
                Timestamp = entry.Timestamp,
                Type = entry.Type,
                Kind = entry.Kind,
                Source = entry.Source,
                Summary = entry.Summary,
                Details = entry.Details,
                Severity = entry.Severity,
                Evidence = entry.Evidence,
                Fields = fields,
                Tags = entry.Tags,
                Url = entry.Url
            };
            WriteText(zip, BookmarkFields.EntryFile, JournalBundle.Serialize([copy], pointers: null));
            files.Add(BookmarkFields.EntryFile);
        }

        return new ExportResult(Path.GetFullPath(zipPath), info.Id, files, stateRedacted);
    }

    /// <summary>
    /// Read a bookmark zip into <paramref name="rootDirectory"/> and add its entry to the journal.
    /// Only the known file names are extracted; anything else in the zip is ignored.
    /// </summary>
    public static SessionLogger.JournalEntry Import(string zipPath, string rootDirectory, SessionLogger logger) =>
        ImportOrFind(zipPath, rootDirectory, logger, out _);

    /// <summary>
    /// Like <see cref="Import"/>, but when the same archive was already imported into this journal
    /// (same original id, timestamp, and title) the existing row is returned and
    /// <paramref name="alreadyImported"/> is true; nothing is added.
    /// </summary>
    public static SessionLogger.JournalEntry ImportOrFind(string zipPath, string rootDirectory, SessionLogger logger,
        out bool alreadyImported)
    {
        alreadyImported = false;
        using var stream = new FileStream(zipPath, FileMode.Open, FileAccess.Read);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);

        var entryJson = ReadText(zip, BookmarkFields.EntryFile)
            ?? throw new InvalidOperationException($"Not a bookmark archive: {BookmarkFields.EntryFile} is missing.");
        var bundle = JournalBundle.Deserialize(entryJson);
        var dto = bundle.Entries.FirstOrDefault(e => BookmarkFields.HasEvidence(e.Fields))
                  ?? throw new InvalidOperationException("The archive has no bookmark entry.");
        var entry = dto.ToEntry();
        var fields = entry.Fields == null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(entry.Fields, StringComparer.OrdinalIgnoreCase);

        var original = fields.GetValueOrDefault(BookmarkFields.BookmarkId);
        var originalId = fields.GetValueOrDefault(BookmarkFields.ImportedId) ?? original;
        var live = logger.GetJournal().Where(BookmarkInfo.HasBookmarkEvidence).ToList();

        var existingImport = live.FirstOrDefault(e =>
            e.Fields!.ContainsKey(BookmarkFields.Imported)
            && string.Equals(e.Fields.GetValueOrDefault(BookmarkFields.ImportedId), originalId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(e.Summary, entry.Summary, StringComparison.Ordinal)
            && Math.Abs((e.Timestamp.ToUniversalTime() - entry.Timestamp.ToUniversalTime()).TotalSeconds) < 1);
        if (existingImport != null)
        {
            alreadyImported = true;
            return existingImport;
        }

        var id = original;
        if (!BookmarkEvidence.IsValidId(id)
            || Directory.Exists(Path.Combine(rootDirectory, id!))
            || live.Any(e => string.Equals(e.Fields!.GetValueOrDefault(BookmarkFields.BookmarkId), id, StringComparison.OrdinalIgnoreCase)))
            id = BookmarkEvidence.NewId();

        var dir = Path.Combine(rootDirectory, id!);
        Directory.CreateDirectory(dir);

        fields[BookmarkFields.BookmarkId] = id!;
        if (!string.IsNullOrWhiteSpace(originalId))
            fields[BookmarkFields.ImportedId] = originalId;
        // Checkpoints and tabs belong to the exporting session; keeping them would join the wrong slice.
        fields.Remove(BookmarkFields.CheckpointId);
        fields.Remove(BookmarkFields.TabId);
        fields.Remove(BookmarkFields.StartsFrom);
        fields[BookmarkFields.BookmarkNumber] = logger.AllocateBookmarkNumber()
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        fields[BookmarkFields.Directory] = dir;
        fields[BookmarkFields.Imported] = Path.GetFileName(zipPath);
        fields.Remove(BookmarkFields.Screenshot);
        fields.Remove(BookmarkFields.TrwPath);
        fields.Remove(BookmarkFields.StatePath);
        fields.Remove(BookmarkFields.StateRedacted);

        foreach (var name in EvidenceFiles)
        {
            var zipEntry = FindEntry(zip, name);
            if (zipEntry == null) continue;
            var target = Path.Combine(dir, name);
            CopyBounded(zipEntry, target);
            switch (name)
            {
                case BookmarkFields.ScreenshotFile: fields[BookmarkFields.Screenshot] = target; break;
                case BookmarkFields.TrwFile: fields[BookmarkFields.TrwPath] = target; break;
                case BookmarkFields.StateFile:
                    fields[BookmarkFields.StatePath] = target;
                    fields[BookmarkFields.StateRedacted] = "true";
                    break;
            }
        }

        entry.Fields = fields;
        return logger.ImportEntry(entry);
    }

    private static void AddFile(ZipArchive zip, string? sourcePath, string name, string fieldKey,
        Dictionary<string, string> fields, List<string> files)
    {
        fields.Remove(fieldKey);
        if (string.IsNullOrEmpty(sourcePath) || !File.Exists(sourcePath)) return;
        zip.CreateEntryFromFile(sourcePath, name, CompressionLevel.Optimal);
        fields[fieldKey] = name;
        files.Add(name);
    }

    private static void WriteText(ZipArchive zip, string name, string text)
    {
        var e = zip.CreateEntry(name, CompressionLevel.Optimal);
        using var w = new StreamWriter(e.Open(), new System.Text.UTF8Encoding(false));
        w.Write(text);
    }

    private static ZipArchiveEntry? FindEntry(ZipArchive zip, string name) =>
        zip.Entries.FirstOrDefault(e => string.Equals(e.FullName, name, StringComparison.OrdinalIgnoreCase));

    private static string? ReadText(ZipArchive zip, string name)
    {
        var e = FindEntry(zip, name);
        if (e == null) return null;
        if (e.Length > MaxEntryBytes)
            throw new InvalidOperationException($"{name} in the archive is too large.");
        using var r = new StreamReader(e.Open());
        return r.ReadToEnd();
    }

    private static void CopyBounded(ZipArchiveEntry entry, string target)
    {
        if (entry.Length > MaxEntryBytes)
            throw new InvalidOperationException($"{entry.FullName} in the archive is too large.");
        using var input = entry.Open();
        using var output = new FileStream(target, FileMode.Create, FileAccess.Write);
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
            if (total > MaxEntryBytes)
                throw new InvalidOperationException($"{entry.FullName} in the archive is too large.");
            output.Write(buffer, 0, read);
        }
    }

    public sealed record ExportResult(string Path, string BookmarkId, List<string> Files, bool StateRedacted);
}
