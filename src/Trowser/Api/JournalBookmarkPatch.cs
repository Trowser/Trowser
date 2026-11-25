using Trowser.Bookmarks;
using Trowser.SessionLog;

namespace Trowser.Api;

/// <summary>Maps PATCH / journal-update bodies onto bookmark summary/details without conflating title and note.</summary>
internal static class JournalBookmarkPatch
{
    /// <summary>
    /// For bookmarks: <c>title</c>/<c>text</c> → <paramref name="summary"/>; <c>note</c> → <paramref name="details"/>.
    /// For other entries: <c>note</c>, <c>text</c>, or <c>title</c> → <paramref name="summary"/> (legacy order).
    /// </summary>
    public static void ApplySummaryDetails(
        JsonBody body,
        SessionLogger.JournalEntry existing,
        ref string? summary,
        ref string? details,
        ref bool setDetails)
    {
        if (!BookmarkInfo.HasBookmarkEvidence(existing) && !BookmarkInfo.IsBookmark(existing))
        {
            summary = body.GetString("note") ?? body.GetString("text") ?? body.GetString("title");
            return;
        }

        var hasTitle = body.HasProperty("title") || body.HasProperty("text");
        var hasNote = body.HasProperty("note");

        if (hasTitle)
            summary = body.GetString("title") ?? body.GetString("text");

        if (hasNote && !setDetails)
        {
            details = body.GetString("note");
            setDetails = true;
            if (!hasTitle)
                summary = null;
        }
        else if (!hasTitle && !hasNote)
            summary = null;
    }
}