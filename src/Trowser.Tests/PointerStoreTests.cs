using Trowser.Pointers;
using Xunit;

namespace Trowser.Tests;

/// <summary>Unit tests for the in-memory <see cref="PointerStore"/> (P0 foundation).</summary>
public class PointerStoreTests
{
    [Fact]
    public void add_assigns_session_scoped_id_and_bumps_revision()
    {
        var store = new PointerStore();
        var r0 = store.Revision;
        var p = store.Add(new Pointer { Kind = PointerKinds.Element });
        Assert.False(string.IsNullOrEmpty(p.Id));
        Assert.Contains("-p", p.Id);
        Assert.True(store.Revision > r0);
    }

    [Fact]
    public void ids_are_unique_and_sequential()
    {
        var store = new PointerStore();
        var a = store.Add(new Pointer());
        var b = store.Add(new Pointer());
        Assert.NotEqual(a.Id, b.Id);
    }

    [Fact]
    public void get_returns_added_pointer_and_null_for_unknown()
    {
        var store = new PointerStore();
        var p = store.Add(new Pointer { Caption = "here" });
        Assert.Same(p, store.Get(p.Id));
        Assert.Null(store.Get("nope"));
        Assert.Null(store.Get(null));
    }

    [Fact]
    public void filters_by_author_kind_status()
    {
        var store = new PointerStore();
        store.Add(new Pointer { Author = PointerAuthors.Human, Kind = PointerKinds.Absence, Status = PointerStatuses.Resolved });
        store.Add(new Pointer { Author = PointerAuthors.Agent, Kind = PointerKinds.Element, Status = PointerStatuses.Stale });

        Assert.Single(store.GetAll(author: "human"));
        Assert.Single(store.GetAll(kind: PointerKinds.Element));
        Assert.Single(store.GetAll(status: PointerStatuses.Stale));
        Assert.Equal(2, store.GetAll().Count);
    }

    [Fact]
    public void remove_returns_false_for_unknown()
    {
        var store = new PointerStore();
        var p = store.Add(new Pointer());
        Assert.True(store.Remove(p.Id));
        Assert.False(store.Remove(p.Id));
        Assert.Empty(store.GetAll());
    }

    [Fact]
    public void update_status_normalizes_and_sets_rect()
    {
        var store = new PointerStore();
        var p = store.Add(new Pointer { Status = PointerStatuses.Resolved });
        var rect = new PointerRect { X = 1, Y = 2, Width = 3, Height = 4 };
        var updated = store.UpdateStatus(p.Id, "UNRESOLVABLE", rect);
        Assert.NotNull(updated);
        Assert.Equal(PointerStatuses.Unresolvable, updated!.Status);
        Assert.Same(rect, updated.Anchors.Rect);
    }

    [Fact]
    public void mark_tab_stale_only_affects_resolved_on_that_tab()
    {
        var store = new PointerStore();
        var a = store.Add(new Pointer { TabId = 0, Status = PointerStatuses.Resolved });
        var b = store.Add(new Pointer { TabId = 1, Status = PointerStatuses.Resolved });
        var c = store.Add(new Pointer { TabId = 0, Status = PointerStatuses.Unresolvable });

        store.MarkTabStale(0);

        Assert.Equal(PointerStatuses.Stale, store.Get(a.Id)!.Status);
        Assert.Equal(PointerStatuses.Resolved, store.Get(b.Id)!.Status);
        Assert.Equal(PointerStatuses.Unresolvable, store.Get(c.Id)!.Status);
    }

    [Fact]
    public void checkpoints_track_latest_and_bound_journal_index()
    {
        var store = new PointerStore();
        Assert.Null(store.LatestCheckpoint);

        var c1 = store.AddCheckpoint(journalIndex: 5, label: "first");
        var c2 = store.AddCheckpoint(journalIndex: 12, label: null, url: "https://x");

        Assert.Equal(c2.Id, store.LatestCheckpoint!.Id);
        Assert.Equal(5, store.GetCheckpoint(c1.Id)!.JournalIndex);
        Assert.Equal(2, store.GetCheckpoints().Count);
        Assert.NotEqual(c1.Id, c2.Id);
    }

    [Fact]
    public void changed_event_fires_on_mutation()
    {
        var store = new PointerStore();
        var fired = 0;
        store.Changed += () => fired++;
        store.Add(new Pointer());
        store.AddCheckpoint(0);
        Assert.Equal(2, fired);
    }
}
