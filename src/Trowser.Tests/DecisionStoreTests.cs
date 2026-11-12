using Trowser.Decisions;
using Xunit;

namespace Trowser.Tests;

/// <summary>Unit tests for the in-memory <see cref="DecisionStore"/> (P3 decision handoff).</summary>
public class DecisionStoreTests
{
    private static Decision NewDecision(string lane = DecisionLanes.Steer, int timeoutMs = DecisionDefaults.TimeoutMs) =>
        new()
        {
            Question = "Ship it?",
            Lane = lane,
            TimeoutMs = timeoutMs,
            Options =
            [
                new DecisionOption { Key = "A", Label = "Ship" },
                new DecisionOption { Key = "B", Label = "Hold" }
            ]
        };

    [Fact]
    public void add_assigns_session_scoped_id_and_bumps_revision()
    {
        var store = new DecisionStore();
        var r0 = store.Revision;
        var d = store.Add(NewDecision());
        Assert.False(string.IsNullOrEmpty(d.Id));
        Assert.Contains("-d", d.Id);
        Assert.True(store.Revision > r0);
    }

    [Fact]
    public void add_derives_expiry_from_timeout_and_clamps_it()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision(timeoutMs: DecisionDefaults.MaxTimeoutMs * 10));
        Assert.Equal(DecisionDefaults.MaxTimeoutMs, d.TimeoutMs);
        Assert.True(d.ExpiresAt > d.CreatedAt);
    }

    [Fact]
    public void default_timeout_is_five_minutes()
    {
        var store = new DecisionStore();
        var d = store.Add(new Decision { Question = "?", Options = NewDecision().Options });
        Assert.Equal(300_000, d.TimeoutMs);
    }

    [Fact]
    public void answer_records_key_label_and_who_answered()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision());
        store.Answer(d.Id, "b", DecisionAnswerers.Human, "not ready");

        Assert.Equal(DecisionStatuses.Answered, d.Status);
        Assert.Equal("B", d.AnswerKey);
        Assert.Equal("Hold", d.AnswerLabel);
        Assert.Equal(DecisionAnswerers.Human, d.AnsweredBy);
        Assert.Equal("not ready", d.AnswerNote);
        Assert.NotNull(d.ResolvedAt);
    }

    [Fact]
    public void answer_is_ignored_once_resolved_so_the_record_cannot_be_rewritten()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision());
        store.Answer(d.Id, "A", DecisionAnswerers.Human);
        store.Answer(d.Id, "B", DecisionAnswerers.Human);

        Assert.Equal("A", d.AnswerKey);
    }

    [Fact]
    public void answer_with_unknown_key_leaves_the_decision_pending()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision());
        store.Answer(d.Id, "Z", DecisionAnswerers.Human);

        Assert.Equal(DecisionStatuses.Pending, d.Status);
        Assert.Null(d.AnswerKey);
    }

    [Fact]
    public void resolved_event_fires_once_per_decision()
    {
        var store = new DecisionStore();
        var resolutions = new List<Decision>();
        store.Resolved += resolutions.Add;

        var d = store.Add(NewDecision());
        store.Answer(d.Id, "A", DecisionAnswerers.Human);
        store.Answer(d.Id, "B", DecisionAnswerers.Human);

        Assert.Single(resolutions);
    }

    [Fact]
    public void cancel_marks_the_question_withdrawn_by_the_agent()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision());
        store.Cancel(d.Id, "worked it out");

        Assert.Equal(DecisionStatuses.Cancelled, d.Status);
        Assert.Equal(DecisionAnswerers.Agent, d.AnsweredBy);
        Assert.Equal("worked it out", d.AnswerNote);
    }

    [Fact]
    public void expired_decision_with_a_default_becomes_defaulted()
    {
        var store = new DecisionStore();
        var d = NewDecision(timeoutMs: DecisionDefaults.MinTimeoutMs);
        d.DefaultKey = "B";
        store.Add(d);
        d.ExpiresAt = DateTime.Now.AddSeconds(-1);

        Assert.Equal(1, store.ApplyDueDefaults());
        Assert.Equal(DecisionStatuses.Defaulted, d.Status);
        Assert.Equal("B", d.AnswerKey);
        Assert.Equal(DecisionAnswerers.Default, d.AnsweredBy);
    }

    [Fact]
    public void expired_decision_without_a_default_expires_with_no_answer()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision());
        d.ExpiresAt = DateTime.Now.AddSeconds(-1);

        store.ApplyDueDefaults();
        Assert.Equal(DecisionStatuses.Expired, d.Status);
        Assert.Null(d.AnswerKey);
    }

    [Fact]
    public void reads_apply_due_defaults_so_the_record_is_honest_whenever_anyone_looks()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision());
        d.DefaultKey = "A";
        d.ExpiresAt = DateTime.Now.AddSeconds(-1);

        Assert.Equal(DecisionStatuses.Defaulted, store.Get(d.Id)!.Status);
    }

    [Fact]
    public async Task gate_wait_returns_when_a_human_answers()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision(DecisionLanes.Gate));

        var waiting = store.WaitForResolutionAsync(d.Id);
        store.Answer(d.Id, "A", DecisionAnswerers.Human);

        var resolved = await waiting.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(DecisionStatuses.Answered, resolved.Status);
        Assert.Equal("A", resolved.AnswerKey);
    }

    [Fact]
    public async Task gate_wait_returns_the_default_when_the_timeout_fires()
    {
        var store = new DecisionStore();
        var d = NewDecision(DecisionLanes.Gate, timeoutMs: DecisionDefaults.MinTimeoutMs);
        d.DefaultKey = "B";
        d.CreatedAt = DateTime.Now.AddMilliseconds(-(DecisionDefaults.MinTimeoutMs + 500));
        store.Add(d);

        var resolved = await store.WaitForResolutionAsync(d.Id).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(DecisionStatuses.Defaulted, resolved.Status);
        Assert.Equal("B", resolved.AnswerKey);
    }

    [Fact]
    public async Task gate_wait_returns_immediately_for_an_already_resolved_decision()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision(DecisionLanes.Gate));
        store.Answer(d.Id, "A", DecisionAnswerers.Human);

        var resolved = await store.WaitForResolutionAsync(d.Id).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("A", resolved.AnswerKey);
    }

    [Fact]
    public async Task gate_wait_unblocks_when_the_agent_withdraws_the_question()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision(DecisionLanes.Gate));

        var waiting = store.WaitForResolutionAsync(d.Id);
        store.Cancel(d.Id, "never mind");

        var resolved = await waiting.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(DecisionStatuses.Cancelled, resolved.Status);
    }

    [Fact]
    public void other_answer_stores_custom_text_when_allowed()
    {
        var store = new DecisionStore();
        var d = NewDecision();
        d.AllowOther = true;
        d.OtherKey = "C";
        store.Add(d);

        store.Answer(d.Id, "C", DecisionAnswerers.Human, "Try the staging URL instead");

        Assert.True(d.IsOtherAnswer);
        Assert.Equal("C", d.AnswerKey);
        Assert.Equal("Try the staging URL instead", d.AnswerLabel);
        Assert.Equal("Try the staging URL instead", d.AnswerNote);
    }

    [Fact]
    public void other_answer_accepts_legacy_other_alias()
    {
        var store = new DecisionStore();
        var d = NewDecision();
        d.AllowOther = true;
        d.OtherKey = "C";
        store.Add(d);

        store.Answer(d.Id, DecisionOption.OtherAlias, DecisionAnswerers.Human, "Custom path");

        Assert.True(d.IsOtherAnswer);
        Assert.Equal("C", d.AnswerKey);
        Assert.Equal("Custom path", d.AnswerLabel);
    }

    [Fact]
    public void other_answer_is_ignored_when_not_allowed_or_empty()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision());

        store.Answer(d.Id, DecisionOption.OtherAlias, DecisionAnswerers.Human, "custom");
        Assert.Equal(DecisionStatuses.Pending, d.Status);

        d.AllowOther = true;
        d.OtherKey = "C";
        store.Answer(d.Id, "C", DecisionAnswerers.Human, "   ");
        Assert.Equal(DecisionStatuses.Pending, d.Status);
    }

    [Fact]
    public async Task steer_grace_waits_for_human_answer()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision(DecisionLanes.Steer));

        var graceTask = store.WaitForSteerGraceAsync(d.Id, 5000);

        await Task.Delay(100);
        store.Answer(d.Id, "A", DecisionAnswerers.Human);

        var result = await graceTask;
        Assert.Equal(DecisionStatuses.Answered, result.Status);
        Assert.Equal("A", result.AnswerKey);
    }

    [Fact]
    public async Task steer_grace_returns_pending_when_no_answer()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision(DecisionLanes.Steer));

        var result = await store.WaitForSteerGraceAsync(d.Id, 50);
        Assert.Equal(DecisionStatuses.Pending, result.Status);
    }

    [Fact]
    public async Task steer_grace_zero_returns_immediately()
    {
        var store = new DecisionStore();
        var d = store.Add(NewDecision(DecisionLanes.Steer));

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await store.WaitForSteerGraceAsync(d.Id, 0);
        sw.Stop();

        // Generous bound: shared CI runners stall; the point is "did not wait for a grace period".
        Assert.True(sw.ElapsedMilliseconds < 1000);
        Assert.Equal(DecisionStatuses.Pending, result.Status);
    }

    [Fact]
    public void filters_by_status_and_lane()
    {
        var store = new DecisionStore();
        var gate = store.Add(NewDecision(DecisionLanes.Gate));
        store.Add(NewDecision(DecisionLanes.Review));
        store.Answer(gate.Id, "A", DecisionAnswerers.Human);

        Assert.Single(store.GetAll(lane: DecisionLanes.Gate));
        Assert.Single(store.GetAll(status: DecisionStatuses.Answered));
        Assert.Single(store.GetAll(status: DecisionStatuses.Pending));
        Assert.Equal(2, store.GetAll().Count);
    }

    [Fact]
    public void has_pending_tracks_whether_anything_still_needs_the_human()
    {
        var store = new DecisionStore();
        Assert.False(store.HasPending);
        var d = store.Add(NewDecision());
        Assert.True(store.HasPending);
        store.Answer(d.Id, "A", DecisionAnswerers.Human);
        Assert.False(store.HasPending);
    }

    [Fact]
    public void has_attention_pending_excludes_review_lane()
    {
        var store = new DecisionStore();
        Assert.False(store.HasAttentionPending);

        store.Add(NewDecision(DecisionLanes.Review));
        Assert.True(store.HasPending);
        Assert.False(store.HasAttentionPending);
        Assert.Empty(store.GetAttentionPending());

        var gate = store.Add(NewDecision(DecisionLanes.Gate));
        Assert.True(store.HasAttentionPending);
        Assert.Single(store.GetAttentionPending());

        var steer = store.Add(NewDecision(DecisionLanes.Steer));
        Assert.Equal(2, store.GetAttentionPending().Count);

        store.Answer(gate.Id, "A", DecisionAnswerers.Human);
        Assert.True(store.HasAttentionPending);
        store.Answer(steer.Id, "B", DecisionAnswerers.Human);
        Assert.False(store.HasAttentionPending);
        Assert.True(store.HasPending); // review still pending
    }

    [Fact]
    public void lane_and_status_normalization_falls_back_to_the_safe_value()
    {
        Assert.Equal(DecisionLanes.Steer, DecisionLanes.Normalize(null));
        Assert.Equal(DecisionLanes.Steer, DecisionLanes.Normalize("nonsense"));
        Assert.Equal(DecisionLanes.Gate, DecisionLanes.Normalize(" GATE "));
        Assert.Equal(DecisionStatuses.Pending, DecisionStatuses.Normalize("nonsense"));
        Assert.Equal(DecisionUrgencies.Normal, DecisionUrgencies.Normalize(null));
        Assert.Equal(DecisionUrgencies.High, DecisionUrgencies.Normalize("High"));
    }

    [Fact]
    public void option_keys_are_letters_in_order()
    {
        Assert.Equal("A", DecisionOption.KeyAt(0));
        Assert.Equal("D", DecisionOption.KeyAt(3));
        Assert.Equal("F", DecisionOption.KeyAt(5));
    }

    [Fact]
    public void plain_text_includes_lane_question_options_and_footer()
    {
        var d = NewDecision(DecisionLanes.Gate);
        d.Recommendation = "A";
        d.Options[0].Detail = "Looks good";
        d.Status = DecisionStatuses.Answered;
        d.AnswerKey = "A";
        d.AnsweredBy = DecisionAnswerers.Human;

        var text = DecisionCardCopy.PlainText(d);

        Assert.Contains("WAITING ON YOU", text);
        Assert.Contains("Ship it?", text);
        Assert.Contains("A  Ship   recommended", text);
        Assert.Contains("Looks good", text);
        Assert.Contains("You chose A) Ship.", text);
    }
}
