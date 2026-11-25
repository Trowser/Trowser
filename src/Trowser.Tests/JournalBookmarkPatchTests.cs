using System.Text.Encodings.Web;
using System.Text.Json;
using Trowser.Api;
using Trowser.Bookmarks;
using Trowser.SessionLog;
using Xunit;

namespace Trowser.Tests;

public class JournalBookmarkPatchTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    [Fact]
    public void bookmark_patch_applies_title_and_note_separately()
    {
        var logger = new SessionLogger();
        var fields = BookmarkEvidence.BuildFields("bm-x", 1, null, [], 0, null, "/tmp", null, null, null);
        var entry = logger.LogBookmark("api", "Old title", "https://example.test/", fields, "Old details");

        using var doc = JsonDocument.Parse("""{"title":"New title","note":"New note"}""");
        var body = JsonBody.FromToolArguments(doc.RootElement);
        string? summary = null;
        string? details = null;
        var setDetails = false;
        Trowser.Api.JournalBookmarkPatch.ApplySummaryDetails(body, entry, ref summary, ref details, ref setDetails);

        Assert.Equal("New title", summary);
        Assert.Equal("New note", details);
        Assert.True(setDetails);
    }

    [Fact]
    public void bookmark_full_journal_entry_serializes_in_wrapped_response()
    {
        var logger = new SessionLogger();
        var fields = BookmarkEvidence.BuildFields("bm-y", 1, "cp", ["Step one", "Step two"], 0, null, "/tmp", null, null, null);
        logger.LogBookmark("api", "Login", "https://example.test/login", fields, "saved state");

        var entries = logger.GetJournal(type: BookmarkFields.EntryType)
            .Select(JournalProjection.ProjectEntry)
            .ToArray();
        var payload = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["data"] = new { entries, count = entries.Length, total = logger.JournalCount, view = "full" }
        };

        var json = JsonSerializer.SerializeToUtf8Bytes(payload, typeof(Dictionary<string, object?>), JsonOptions);
        using var parsed = JsonDocument.Parse(json);
        var data = parsed.RootElement.GetProperty("data");
        Assert.Equal(1, data.GetProperty("count").GetInt32());
        Assert.Equal(1, data.GetProperty("entries").GetArrayLength());
        Assert.True(data.GetProperty("entries")[0].GetProperty("fields").TryGetProperty("bookmarkId", out _));
    }
}