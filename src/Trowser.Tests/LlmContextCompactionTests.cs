using Trowser.Chat;
using Trowser.SessionLog;
using Xunit;

namespace Trowser.Tests;

public class LlmContextCompactionTests
{
    [Fact]
    public void FindSafeCutIndex_skips_prompt_tool_results()
    {
        var conversation = new List<ChatMessage>
        {
            ChatMessage.System("sys"),
            ChatMessage.FromUser("hello"),
            ChatMessage.FromAssistant(null, [new ToolCall { Id = "1", Name = "browser_snapshot", ArgumentsJson = "{}" }]),
            ChatMessage.FromUser("<tool_result name=\"browser_snapshot\">\n{}\n</tool_result>"),
            ChatMessage.FromAssistant("done")
        };

        var cut = LlmContextCompaction.FindSafeCutIndex(conversation, 1);
        Assert.Equal(4, cut);
    }

    [Fact]
    public async Task ApplyPendingCompact_does_not_orphan_tool_results()
    {
        var logger = new SessionLogger();
        var memory = new SessionMemory();
        memory.QueueCompact(new PendingCompactRequest
        {
            Summary = "Test segment complete",
            KeepLastTurns = 0
        });

        var compaction = new LlmContextCompaction(logger, memory, () => Task.FromResult(new SessionMetadata()));
        var conversation = new List<ChatMessage>
        {
            ChatMessage.System("sys"),
            ChatMessage.FromUser("start"),
            ChatMessage.FromAssistant(null, [new ToolCall { Id = "1", Name = "browser_snapshot", ArgumentsJson = "{}" }]),
            ChatMessage.ToolResult("1", "browser_snapshot", "{}")
        };

        Assert.True(await compaction.ApplyPendingCompact(conversation, new LlmSettings()));

        foreach (var msg in conversation)
        {
            if (msg.Role == ChatRole.Tool)
                Assert.Fail("Compact left orphaned tool result");
            if (msg.Role == ChatRole.Assistant && msg.ToolCalls?.Count > 0)
                Assert.Fail("Compact left dangling tool_calls without results");
        }
    }

    [Fact]
    public async Task ApplyPendingCompact_includes_session_metadata_url()
    {
        var logger = new SessionLogger();
        var memory = new SessionMemory();
        memory.QueueCompact(new PendingCompactRequest
        {
            Summary = "Test",
            KeepLastTurns = 0
        });

        var compaction = new LlmContextCompaction(
            logger, memory, () => Task.FromResult(new SessionMetadata { Url = "https://example.test/" }));
        var conversation = new List<ChatMessage>
        {
            ChatMessage.System("sys"),
            ChatMessage.FromUser("hello")
        };

        Assert.True(await compaction.ApplyPendingCompact(conversation, new LlmSettings()));
        Assert.Contains(conversation, m => m.Content?.Contains("https://example.test/") == true);
    }

    [Fact]
    public async Task ApplyPendingCompact_awaits_incomplete_metadata_instead_of_blocking()
    {
        var tcs = new TaskCompletionSource<SessionMetadata>(TaskCreationOptions.RunContinuationsAsynchronously);
        var logger = new SessionLogger();
        var memory = new SessionMemory();
        memory.QueueCompact(new PendingCompactRequest
        {
            Summary = "Test",
            KeepLastTurns = 0
        });

        var compaction = new LlmContextCompaction(logger, memory, () => tcs.Task);
        var conversation = new List<ChatMessage> { ChatMessage.System("sys") };

        var compactTask = compaction.ApplyPendingCompact(conversation, new LlmSettings());
        Assert.False(compactTask.IsCompleted);

        tcs.SetResult(new SessionMetadata { Url = "https://example.test/" });
        Assert.True(await compactTask.WaitAsync(TimeSpan.FromSeconds(2)));
    }

    [Fact]
    public void Journal_evidence_round_trip()
    {
        var logger = new SessionLogger();
        var entry = logger.LogLlmNote("Finding", evidence: NoteKinds.EvidenceObserved);
        Assert.Equal(NoteKinds.EvidenceObserved, entry.Evidence);

        var index = JournalProjection.ProjectEntryIndex(entry);
        Assert.NotNull(index);
    }

    [Fact]
    public void GetJournal_view_index_shape()
    {
        var logger = new SessionLogger();
        logger.LogLlmNote("Alpha");
        logger.LogLlmNote("Beta", evidence: NoteKinds.EvidenceHypothesis);

        var index = JournalProjection.ProjectEntryIndex(logger.GetJournal().Last());
        var json = System.Text.Json.JsonSerializer.Serialize(index);
        Assert.Contains("evidence", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("summary", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("details", json, StringComparison.OrdinalIgnoreCase);
    }
}
