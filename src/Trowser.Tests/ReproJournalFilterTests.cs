using Trowser.Bookmarks;
using Trowser.Repro;
using Trowser.SessionLog;
using Xunit;

namespace Trowser.Tests;

public class ReproJournalFilterTests
{
    [Theory]
    [InlineData("/api/bookmark-restore", false)]
    [InlineData("/api/click", true)]
    [InlineData("/api/navigate", true)]
    public void ShouldCaptureJournalAction_filters_housekeeping(string path, bool expect)
    {
        var entry = new SessionLogger.JournalEntry
        {
            Type = "action",
            Fields = new Dictionary<string, string>
            {
                ["method"] = "POST",
                ["path"] = path,
                ["body"] = "{}"
            }
        };
        Assert.Equal(expect, ReproJournalFilter.ShouldCaptureJournalAction(entry));
    }
}