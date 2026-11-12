using Trowser.Security.Orchestration;
using Xunit;

namespace Trowser.Tests.Orchestration;

public class PlaybookRunStoreTests
{
    [Fact]
    public void create_and_poll_reflects_status_and_result()
    {
        var store = new PlaybookRunStore();
        var entry = store.Create("abc123", "quick");

        entry.MarkRunning();
        entry.SetCurrentStep("attack-surface");
        entry.RecordStep(new PlaybookStepResult
        {
            Name = "attack-surface",
            Status = "ok",
            DurationMs = 10
        });
        entry.Complete(new Dictionary<string, object?> { ["playbookId"] = "quick", ["runId"] = "abc123" });

        Assert.True(store.TryGet("abc123", out var loaded));
        var poll = (Dictionary<string, object?>)loaded!.ToPollResponse();
        Assert.Equal("completed", poll["status"]);
        Assert.Equal("quick", poll["playbookId"]);
        Assert.NotNull(poll["result"]);
        var steps = Assert.IsType<List<PlaybookStepResult>>(poll["stepsExecuted"]);
        Assert.Single(steps);
    }

    [Fact]
    public void evicts_oldest_when_over_max()
    {
        var store = new PlaybookRunStore();
        for (var i = 0; i < PlaybookRunStore.MaxRuns + 2; i++)
            store.Create($"run{i:D3}", "quick");

        Assert.False(store.TryGet("run000", out _));
        Assert.True(store.TryGet($"run{PlaybookRunStore.MaxRuns + 1:D3}", out _));
    }
}
