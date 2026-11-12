using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Trowser.Decisions;

namespace Trowser;

/// <summary>
/// P3 wiring for decisions (agent → human). A new question opens the AI Assistant with an A/B/C/D
/// card and asks for attention via the taskbar, chat badge, and status bar. Attention chrome stays
/// until the question is answered, defaulted, expired, or cancelled — looking at the window alone
/// does not clear it. Every resolution is journalled here so the record cannot depend on which
/// path resolved it.
/// </summary>
public partial class MainWindow
{
    private DispatcherTimer? _decisionSweepTimer;
    private bool _decisionAttentionActive;
    private bool _decisionAttentionUrgent;
    private string? _decisionAttentionQuestion;
    private string? _statusBeforeDecision;
    private Brush? _statusBarBrushBeforeDecision;
    private Storyboard? _chatAttentionPulse;
    private static readonly Brush StatusBarDefaultBrush = new SolidColorBrush(Color.FromRgb(0x00, 0x7A, 0xCC));
    private static readonly Brush StatusBarWaitingBrush = new SolidColorBrush(Color.FromRgb(0xF5, 0xA6, 0x23));
    private static readonly Brush StatusBarUrgentBrush = new SolidColorBrush(Color.FromRgb(0xC7, 0x2E, 0x2E));
    private static readonly Brush ChatAttentionBrush = new SolidColorBrush(Color.FromRgb(0xF5, 0xA6, 0x23));
    private static readonly Brush ChatAttentionBorderBrush = new SolidColorBrush(Color.FromRgb(0xD9, 0x6D, 0x1A));
    private static readonly Brush ChatIdleBrush = new SolidColorBrush(Color.FromRgb(0x2D, 0x2D, 0x30));
    private static readonly Brush ChatIdleBorderBrush = new SolidColorBrush(Color.FromRgb(0x3F, 0x3F, 0x46));

    private const string WaitingOnYouTitlePrefix = "Waiting on you — ";
    private const string DefaultChatTooltip = "AI Assistant (Ctrl+L)";

    private void WireDecisions()
    {
        _decisionStore.Asked += OnDecisionAsked;
        _decisionStore.Resolved += OnDecisionResolved;
        Activated += OnWindowActivatedForDecisionAttention;
        Deactivated += OnWindowDeactivatedForDecisionAttention;
    }

    // Fires from the API/MCP thread that created the decision — marshal to the UI thread.
    private void OnDecisionAsked(Decision decision) => Dispatcher.BeginInvoke(() =>
    {
        try
        {
            IsChatPanelVisible = true;
            ChatPanelControl.ShowDecision(
                decision,
                () => _decisionStore.Get(decision.Id),
                (key, note) => _decisionStore.Answer(decision.Id, key, DecisionAnswerers.Human, note));

            // Review never interrupts: it is a record, not a request.
            if (decision.Lane != DecisionLanes.Review)
                ApplyDecisionAttentionChrome(flash: true);
            else if (_decisionStore.HasAttentionPending)
                ApplyDecisionAttentionChrome(flash: false);

            StartDecisionSweep();
        }
        catch (Exception ex) { TrowserLog.Warn($"Decision card failed: {ex.Message}"); }
    });

    private void OnDecisionResolved(Decision decision) => Dispatcher.BeginInvoke(() =>
    {
        try
        {
            _sessionLogger.LogDecisionResolved(
                decision.Question, decision.Id, decision.Status,
                decision.AnswerKey, decision.AnswerLabel, decision.AnsweredBy, decision.AnswerNote,
                decision.IsOtherAnswer);
        }
        catch (Exception ex) { TrowserLog.Warn($"Decision journal log failed: {ex.Message}"); }

        if (_decisionStore.HasAttentionPending)
        {
            ApplyDecisionAttentionChrome(flash: false);
            return;
        }

        ClearDecisionAttentionChrome();

        if (!_decisionStore.HasPending)
            StopDecisionSweep();
    });

    private void OnWindowActivatedForDecisionAttention(object? sender, EventArgs e)
    {
        // Stop the flash while the user is in Trowser — overlay / badge / status stay until answered.
        if (_decisionAttentionActive)
            AttentionNotifier.StopFlashOnly(this);
    }

    private void OnWindowDeactivatedForDecisionAttention(object? sender, EventArgs e)
    {
        // Left without answering — make the taskbar shout again.
        if (_decisionAttentionActive)
            AttentionNotifier.Reflash(this, _decisionAttentionUrgent);
    }

    /// <summary>
    /// Apply (or refresh) all "waiting on you" chrome from the current attention-pending set.
    /// Overlay, progress bar, chat badge, status bar colour, and title prefix stay until clear.
    /// </summary>
    private void ApplyDecisionAttentionChrome(bool flash)
    {
        var pending = _decisionStore.GetAttentionPending();
        if (pending.Count == 0)
        {
            ClearDecisionAttentionChrome();
            return;
        }

        var urgent = pending.Any(d => d.Urgency == DecisionUrgencies.High);
        var question = pending[0].Question;
        _decisionAttentionUrgent = urgent;
        _decisionAttentionQuestion = question;

        if (!_decisionAttentionActive)
        {
            _statusBeforeDecision = StatusText.Text;
            _statusBarBrushBeforeDecision = StatusBarBorder.Background;
            _decisionAttentionActive = true;
        }

        if (flash)
            AttentionNotifier.RequestAttention(this, urgent, question);
        else
            AttentionNotifier.ApplyOverlay(this, urgent, question);

        StatusBarBorder.Background = urgent ? StatusBarUrgentBrush : StatusBarWaitingBrush;
        StatusText.Text = "Waiting on you — AI Assistant";

        UpdateChatAttentionBadge(pending.Count, question);
        RefreshWindowTitle();
    }

    private void ClearDecisionAttentionChrome()
    {
        if (!_decisionAttentionActive && !_decisionStore.HasAttentionPending)
        {
            // Still clear UI bits if a race left badge visible.
            UpdateChatAttentionBadge(0, null);
            AttentionNotifier.ClearAttention(this);
            return;
        }

        _decisionAttentionActive = false;
        _decisionAttentionUrgent = false;
        _decisionAttentionQuestion = null;

        AttentionNotifier.ClearAttention(this);
        UpdateChatAttentionBadge(0, null);

        StatusBarBorder.Background = _statusBarBrushBeforeDecision ?? StatusBarDefaultBrush;
        if (!string.IsNullOrEmpty(_statusBeforeDecision) &&
            StatusText.Text.StartsWith("Waiting on you", StringComparison.Ordinal))
        {
            StatusText.Text = _statusBeforeDecision;
        }
        else if (StatusText.Text.StartsWith("Waiting on you", StringComparison.Ordinal) ||
                 StatusText.Text.Contains("decision (AI Assistant", StringComparison.Ordinal))
        {
            StatusText.Text = "Ready";
        }

        _statusBeforeDecision = null;
        _statusBarBrushBeforeDecision = null;
        RefreshWindowTitle();
    }

    private void UpdateChatAttentionBadge(int count, string? question)
    {
        if (count <= 0)
        {
            ChatAttentionBadge.Visibility = Visibility.Collapsed;
            ChatToggleButton.Background = ChatIdleBrush;
            ChatToggleButton.BorderBrush = ChatIdleBorderBrush;
            ChatToggleButton.ToolTip = DefaultChatTooltip;
            StopChatAttentionPulse();
            return;
        }

        ChatAttentionBadge.Visibility = Visibility.Visible;
        ChatAttentionBadgeCount.Text = count > 99 ? "99+" : count.ToString();
        ChatToggleButton.Background = ChatAttentionBrush;
        ChatToggleButton.BorderBrush = ChatAttentionBorderBrush;
        ChatToggleButton.Foreground = Brushes.White;
        ChatToggleButton.ToolTip = string.IsNullOrWhiteSpace(question)
            ? "Waiting on you — open AI Assistant"
            : $"Waiting on you — {question}";
        StartChatAttentionPulse();
    }

    private void StartChatAttentionPulse()
    {
        if (_chatAttentionPulse != null) return;

        var anim = new DoubleAnimation
        {
            From = 1.0,
            To = 0.55,
            Duration = TimeSpan.FromMilliseconds(750),
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        };
        _chatAttentionPulse = new Storyboard();
        Storyboard.SetTarget(anim, ChatToggleButton);
        Storyboard.SetTargetProperty(anim, new PropertyPath(UIElement.OpacityProperty));
        _chatAttentionPulse.Children.Add(anim);
        _chatAttentionPulse.Begin();
    }

    private void StopChatAttentionPulse()
    {
        _chatAttentionPulse?.Stop();
        _chatAttentionPulse = null;
        ChatToggleButton.Opacity = 1.0;
        ChatToggleButton.Foreground = new SolidColorBrush(Color.FromRgb(0xCC, 0xCC, 0xCC));
    }

    /// <summary>
    /// Set the window title from page chrome, prefixing "Waiting on you — " while a decision needs
    /// attention so alt-tab / taskbar stay honest after tab title changes.
    /// </summary>
    private void SetWindowTitleFromPage(string? pageTitle)
    {
        var baseTitle = string.IsNullOrEmpty(pageTitle) ? "Trowser" : $"{pageTitle} - Trowser";
        Title = _decisionAttentionActive ? WaitingOnYouTitlePrefix + baseTitle : baseTitle;
    }

    private void RefreshWindowTitle()
    {
        var pageTitle = _automationContext?.ActiveTab?.Title;
        SetWindowTitleFromPage(string.IsNullOrEmpty(pageTitle) ? null : pageTitle);
    }

    /// <summary>
    /// One-second sweep that applies timeouts to questions nobody is waiting on. A gate-lane ask has
    /// its own waiter, but a steer or review question would otherwise sit "pending" on screen long
    /// past its default — and an expiry that only happens when someone looks is not a record.
    /// </summary>
    private void StartDecisionSweep()
    {
        if (_decisionSweepTimer != null) return;
        _decisionSweepTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _decisionSweepTimer.Tick += (_, _) =>
        {
            _decisionStore.ApplyDueDefaults();
            if (!_decisionStore.HasPending) StopDecisionSweep();
        };
        _decisionSweepTimer.Start();
    }

    private void StopDecisionSweep()
    {
        _decisionSweepTimer?.Stop();
        _decisionSweepTimer = null;
    }
}
