using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Trowser.Api;
using Trowser.Decisions;

namespace Trowser.Chat;

/// <summary>
/// WPF UserControl providing the LLM chat interface.
/// Shows conversation messages, handles user input, streams responses,
/// and displays tool call activity in real-time.
/// </summary>
public class ChatPanel : Border
{
    private readonly StackPanel _messageContainer;
    private readonly ScrollViewer _scrollViewer;
    private readonly TextBox _inputBox;
    private readonly Button _sendButton;
    private readonly Button _stopButton;
    private readonly TextBlock _statusText;
    private readonly StackPanel _emptyState;
    private readonly TextBlock _modelLabel;
    private readonly TextBlock _contextMeter;
    private string? _resolvedModel;

    private LlmClient? _llmClient;
    private LlmToolExecutor? _toolExecutor;
    private McpHandler? _mcpHandler;
    private List<ChatMessage>? _conversation;
    private readonly List<ChatTranscriptItem> _transcript = new();
    private CancellationTokenSource? _cts;
    private TextBox? _currentStreamBlock;
    private Border? _currentStreamBubble;
    private StackPanel? _streamContent;
    private RichTextBox? _streamMarkdownView;
    private string _streamedMarkdown = "";
    private string _streamCompleteMarkdown = "";
    private bool _isProcessing;

    /// <summary>
    /// Raised when the user clicks a quicktest link. The string is the logical name under
    /// <c>Trowser.Resources.Quicktests</c> (e.g. <c>SiteHealth</c> or <c>Usability.ResponsiveAccessibility</c>).
    /// The host window should load and run it in the Script Console.
    /// </summary>
    public event Action<string>? QuicktestRequested;

    /// <summary>
    /// Raised when the user selects "Show as HTML" from a message context menu.
    /// The string is the generated HTML content to display in a new browser tab.
    /// </summary>
    public event Action<string>? ShowAsHtmlRequested;

    /// <summary>
    /// Raised when the user asks to close the chat panel via the header "x" button
    /// while already on the empty start page. The host window should hide the panel.
    /// </summary>
    public event Action? CloseRequested;

    /// <summary>
    /// Raised when the user clicks the unconfigured header prompt to open LLM Settings.
    /// </summary>
    public event Action? ConfigureRequested;

    private bool _configurePromptActive;

    private static readonly Brush BgDark = Bc("#1E1E1E");
    private static readonly Brush BgMedium = Bc("#252526");
    private static readonly Brush BgPanel = Bc("#2D2D30");
    private static readonly Brush BgUserBubble = Bc("#0E639C");
    private static readonly Brush BgAssistantBubble = Bc("#2D2D30");
    private static readonly Brush BgToolBubble = Bc("#1A3A2A");
    private static readonly Brush BorderColor = Bc("#3F3F46");
    private static readonly Brush FgNormal = Bc("#CCCCCC");
    private static readonly Brush FgDim = Bc("#888888");
    private static readonly Brush FgGreen = Bc("#4EC9B0");
    private static readonly Brush FgBlue = Bc("#569CD6");

    public ChatPanel()
    {
        Background = BgDark;
        BorderBrush = BorderColor;
        BorderThickness = new Thickness(1, 0, 0, 0);

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(36) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        // Header
        var header = new Border
        {
            Background = BgPanel,
            BorderBrush = BorderColor,
            BorderThickness = new Thickness(0, 0, 0, 1)
        };
        var headerPanel = new DockPanel { Margin = new Thickness(10, 0, 6, 0) };

        var titleBlock = new TextBlock
        {
            Text = "AI Assistant",
            Foreground = FgNormal,
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center
        };
        headerPanel.Children.Add(titleBlock);

        var headerRight = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };
        DockPanel.SetDock(headerRight, Dock.Right);

        _modelLabel = new TextBlock
        {
            Text = "",
            Foreground = FgDim,
            FontSize = 10,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0)
        };
        _modelLabel.MouseLeftButtonUp += (_, _) =>
        {
            if (_configurePromptActive)
                ConfigureRequested?.Invoke();
        };
        headerRight.Children.Add(_modelLabel);

        _contextMeter = new TextBlock
        {
            Text = "",
            Foreground = FgDim,
            FontSize = 10,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0),
            ToolTip = "Context usage, close and prompt again for new tests"
        };
        headerRight.Children.Add(_contextMeter);

        var clearButton = CreateHeaderButton("\u2715", "Clear chat / close panel");
        clearButton.Click += (_, _) => CloseOrClear();
        headerRight.Children.Add(clearButton);

        headerPanel.Children.Add(headerRight);
        header.Child = headerPanel;
        Grid.SetRow(header, 0);
        rootGrid.Children.Add(header);

        // Message area
        _messageContainer = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };

        _emptyState = CreateEmptyState();
        _messageContainer.Children.Add(_emptyState);

        _scrollViewer = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Background = BgDark,
            Padding = new Thickness(0)
        };
        _scrollViewer.Content = _messageContainer;
        _scrollViewer.ContextMenu = CreateSessionContextMenu();
        Grid.SetRow(_scrollViewer, 1);
        rootGrid.Children.Add(_scrollViewer);

        // Input area
        var inputArea = new Border
        {
            Background = BgMedium,
            BorderBrush = BorderColor,
            BorderThickness = new Thickness(0, 1, 0, 0),
            Padding = new Thickness(8, 8, 8, 8)
        };

        var inputGrid = new Grid();
        inputGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        inputGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var inputRow = new DockPanel();

        _sendButton = new Button
        {
            Content = "\u27A4",
            Width = 36,
            Height = 36,
            FontSize = 16,
            Background = Bc("#0E639C"),
            Foreground = Brushes.White,
            BorderBrush = Bc("#3F3F46"),
            BorderThickness = new Thickness(1),
            Cursor = Cursors.Hand,
            ToolTip = "Send message (Enter)",
            VerticalAlignment = VerticalAlignment.Bottom
        };
        _sendButton.Click += (_, _) => _ = SendMessageAsync();
        DockPanel.SetDock(_sendButton, Dock.Right);
        inputRow.Children.Add(_sendButton);

        _stopButton = new Button
        {
            Content = "\u25A0",
            Width = 36,
            Height = 36,
            FontSize = 14,
            Background = Bc("#C72E2E"),
            Foreground = Brushes.White,
            BorderBrush = Bc("#3F3F46"),
            BorderThickness = new Thickness(1),
            Cursor = Cursors.Hand,
            ToolTip = "Stop generation",
            VerticalAlignment = VerticalAlignment.Bottom,
            Visibility = Visibility.Collapsed
        };
        _stopButton.Click += (_, _) => StopGeneration();
        DockPanel.SetDock(_stopButton, Dock.Right);
        inputRow.Children.Add(_stopButton);

        _inputBox = new TextBox
        {
            Background = BgDark,
            Foreground = FgNormal,
            CaretBrush = FgNormal,
            BorderBrush = BorderColor,
            BorderThickness = new Thickness(1),
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            MinHeight = 36,
            MaxHeight = 120,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Padding = new Thickness(8, 8.5, 8, 8.5),
            Margin = new Thickness(0, 0, 6, 0),
            VerticalAlignment = VerticalAlignment.Bottom
        };
        _inputBox.PreviewKeyDown += InputBox_PreviewKeyDown;
        inputRow.Children.Add(_inputBox);

        Grid.SetRow(inputRow, 0);
        inputGrid.Children.Add(inputRow);

        _statusText = new TextBlock
        {
            Text = "",
            Foreground = FgDim,
            FontSize = 11,
            Margin = new Thickness(2, 4, 0, 0),
            Visibility = Visibility.Collapsed
        };
        Grid.SetRow(_statusText, 1);
        inputGrid.Children.Add(_statusText);

        inputArea.Child = inputGrid;
        Grid.SetRow(inputArea, 2);
        rootGrid.Children.Add(inputArea);

        Child = rootGrid;
    }

    /// <summary>
    /// Initialize the chat panel with a connected McpHandler for tool execution.
    /// </summary>
    public void Initialize(McpHandler mcpHandler, LlmSettings settings, LlmContextCompaction? compaction = null)
    {
        _mcpHandler = mcpHandler;
        _toolExecutor = new LlmToolExecutor(mcpHandler) { ConfirmAsync = ConfirmToolCallAsync };
        _llmClient = new LlmClient(settings, _toolExecutor, compaction);

        _llmClient.OnTextDelta += text => Dispatcher.Invoke(() => AppendStreamText(text));
        _llmClient.OnToolCallStarted += name => Dispatcher.Invoke(() => ShowToolCallStarted(name));
        _llmClient.OnToolCallCompleted += (name, result) => Dispatcher.Invoke(() => ShowToolCallCompleted(name, result));
        _llmClient.OnResponseComplete += () => Dispatcher.Invoke(OnResponseComplete);
        _llmClient.OnError += error => Dispatcher.Invoke(() => ShowError(error));
        _llmClient.OnStatus += text => Dispatcher.Invoke(() => SetStatus(text));
        _llmClient.OnResolvedModel += model => Dispatcher.Invoke(() =>
        {
            _resolvedModel = model;
            UpdateModelLabel(_llmClient.Settings);
        });
        _llmClient.OnCompactApplied += info => Dispatcher.Invoke(() => ShowCompactSeparator(info));

        UpdateModelLabel(settings);
        _conversation = _llmClient.CreateConversation();
    }

    /// <summary>
    /// Places text into the chat input box and focuses it without sending. Used to "paste"
    /// a captured request (with its headers) into the chat so the user can add a question
    /// and review before submitting it to the LLM.
    /// </summary>
    public void PrefillInput(string text)
    {
        var existing = _inputBox.Text;
        _inputBox.Text = string.IsNullOrWhiteSpace(existing)
            ? text
            : existing.TrimEnd() + "\n\n" + text;
        _inputBox.CaretIndex = _inputBox.Text.Length;
        _inputBox.Focus();
        Dispatcher.InvokeAsync(() => _inputBox.ScrollToEnd(), DispatcherPriority.Background);
    }

    /// <summary>
    /// Opens a "strange moment" prompt and leaves the caret at the end so the tester can edit before
    /// sending. The tester's own words now arrive inside <paramref name="actionTrail"/> (under
    /// "Over to you:", built by MainWindow), so there is no separate "What I noticed:" field to fill.
    /// Keeps other prefilled text (e.g. Send to Chat) above it.
    /// <paramref name="actionTrail"/> is a visible, editable handoff note (pointer, recent GUI actions,
    /// errors, and the tester's message) — never silent capture.
    /// </summary>
    public void PrefillStrangeMoment(string? actionTrail = null)
    {
        const string header = "Might be a bug here — help me figure it out.";
        var body = header;
        if (!string.IsNullOrWhiteSpace(actionTrail))
            body += "\n\n" + actionTrail.Trim();

        var existing = _inputBox.Text.Trim();
        if (string.IsNullOrEmpty(existing) || existing.StartsWith(header, StringComparison.Ordinal))
        {
            _inputBox.Text = body;
        }
        else
        {
            _inputBox.Text = existing + "\n\n" + body;
        }

        _inputBox.CaretIndex = _inputBox.Text.Length;
        _inputBox.Focus();
        Dispatcher.InvokeAsync(() => _inputBox.ScrollToEnd(), DispatcherPriority.Background);
    }

    /// <summary>
    /// Prefills investigation text and leaves the caret after <c>Tester notes:</c>
    /// so the tester can add a sentence before sending.
    /// </summary>
    public void PrefillWithTesterNotes(string bodyBeforeNotes)
    {
        const string header = "Look at this Security Shadow finding from a security perspective.";
        const string label = "Tester notes:";
        var body = bodyBeforeNotes.TrimEnd() + "\n\n" + label + " ";

        var existing = _inputBox.Text.Trim();
        if (string.IsNullOrEmpty(existing) || existing.StartsWith(header, StringComparison.Ordinal))
            _inputBox.Text = body;
        else
            _inputBox.Text = existing + "\n\n" + body;

        _inputBox.CaretIndex = _inputBox.Text.Length;
        _inputBox.Focus();
        Dispatcher.InvokeAsync(() => _inputBox.ScrollToEnd(), DispatcherPriority.Background);
    }

    public void UpdateSettings(LlmSettings settings)
    {
        if (_mcpHandler != null)
            _mcpHandler.Mode = settings.Mode;
        if (_llmClient != null)
        {
            _llmClient.Settings = settings;
            _llmClient.ClearCachedPrompts();
            if (_conversation != null)
                _llmClient.RefreshConversationSystemPrompt(_conversation);
        }
        _resolvedModel = null;
        UpdateModelLabel(settings);
    }

    private void UpdateModelLabel(LlmSettings settings)
    {
        if (!settings.IsConfigured)
        {
            _configurePromptActive = true;
            _modelLabel.Text = "Click here to configure";
            _modelLabel.Foreground = FgBlue;
            _modelLabel.TextDecorations = TextDecorations.Underline;
            _modelLabel.Cursor = Cursors.Hand;
            _modelLabel.ToolTip = "Open LLM Settings to set your LLM provider and API key.";
            return;
        }

        _configurePromptActive = false;
        _modelLabel.Foreground = FgDim;
        _modelLabel.TextDecorations = null;
        _modelLabel.Cursor = Cursors.Arrow;

        var configured = settings.Model;
        var displayModel = !string.IsNullOrWhiteSpace(_resolvedModel) ? _resolvedModel! : configured;

        var providerTag = settings.Provider switch
        {
            LlmProvider.OpenRouter => "OpenRouter",
            LlmProvider.Anthropic => "Anthropic",
            LlmProvider.GitHubCopilot => "Copilot",
            _ when LlmSettings.IsLocalEndpoint(settings.Endpoint) => "Local",
            _ => null
        };

        _modelLabel.Text = providerTag == null ? displayModel : $"{displayModel} · {providerTag}";

        var tipParts = new List<string>();
        if (!string.IsNullOrWhiteSpace(_resolvedModel) &&
            !string.Equals(_resolvedModel, configured, StringComparison.OrdinalIgnoreCase))
        {
            tipParts.Add($"Configured as {configured}; last response used {_resolvedModel}.");
        }
        if (settings.GetEnvironmentApiKeySource() is { } env)
            tipParts.Add($"Using {env} from environment (API key field empty).");
        _modelLabel.ToolTip = tipParts.Count > 0 ? string.Join(" ", tipParts) : null;
    }

    #region Message Sending

    private async Task SendMessageAsync()
    {
        if (_isProcessing) return;
        var text = _inputBox.Text.Trim();
        if (string.IsNullOrEmpty(text)) return;
        if (_llmClient == null || _conversation == null)
        {
            ShowError("Chat not initialized. Configure LLM settings first.");
            return;
        }
        if (!_llmClient.Settings.IsConfigured)
        {
            ShowError(_llmClient.Settings.RequiresApiKey
                ? "LLM not configured. Open LLM Settings (\u22EF menu) and set provider, model, and API key (or an env var)."
                : "LLM not configured. Open LLM Settings (\u22EF menu) to set your endpoint and model.");
            return;
        }

        _inputBox.Text = "";
        _emptyState.Visibility = Visibility.Collapsed;

        AddUserBubble(text);
        _transcript.Add(ChatTranscriptItem.User(text));
        _conversation.Add(ChatMessage.FromUser(text));

        _isProcessing = true;
        _sendButton.Visibility = Visibility.Collapsed;
        _stopButton.Visibility = Visibility.Visible;
        _inputBox.IsEnabled = false;
        SetStatus("Thinking...");

        _cts = new CancellationTokenSource();
        ResetStreamState();

        try
        {
            await _llmClient.SendAsync(_conversation, _cts.Token);
            UpdateContextMeter();
        }
        catch (OperationCanceledException)
        {
            AppendStreamText("\n[Stopped]");
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
        finally
        {
            OnResponseComplete();
        }
    }

    private void StopGeneration()
    {
        _cts?.Cancel();
    }

    private void OnResponseComplete()
    {
        FinalizeCurrentStreamBubble();
        _isProcessing = false;
        _sendButton.Visibility = Visibility.Visible;
        _stopButton.Visibility = Visibility.Collapsed;
        _inputBox.IsEnabled = true;
        SetStatus("");
        UpdateContextMeter();
        _inputBox.Focus();
    }

    private async Task ManualCompactAsync()
    {
        if (_llmClient == null || _conversation == null || _isProcessing) return;
        var tokens = _llmClient.EstimateConversationTokens(_conversation);
        if (tokens < 100)
        {
            SetStatus("Nothing much to compact yet.");
            return;
        }

        _isProcessing = true;
        SetStatus("Compacting...");
        try
        {
            if (!await _llmClient.ManualCompact(_conversation))
                SetStatus("Compact did not change the conversation.");
            else
                SetStatus("");
            UpdateContextMeter();
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
            SetStatus("");
        }
        finally
        {
            _isProcessing = false;
        }
    }

    private void UpdateContextMeter()
    {
        if (_llmClient == null || _conversation == null)
        {
            _contextMeter.Text = "";
            return;
        }

        var tokens = _llmClient.EstimateConversationTokens(_conversation);
        var budget = _llmClient.Settings.ContextBudgetTokens;
        if (budget <= 0)
        {
            _contextMeter.Text = $"~{tokens:N0} tok";
            return;
        }

        var pct = Math.Min(100, tokens * 100 / budget);
        _contextMeter.Text = $"~{pct}% ctx";
        _contextMeter.Foreground = pct >= _llmClient.Settings.CompactForcePercent
            ? Bc("#F44747")
            : pct >= _llmClient.Settings.CompactWarnPercent
                ? Bc("#DCDCAA")
                : FgDim;
    }

    private void ShowCompactSeparator(CompactAppliedInfo info)
    {
        var label = info.Deterministic ? "Auto-compact" : "Context compacted";
        var text = $"{label}: {info.MessagesBefore} msgs → {info.MessagesAfter}, " +
                   $"~{info.TokensBefore:N0} → ~{info.TokensAfter:N0} tokens";
        _transcript.Add(ChatTranscriptItem.Compact(text, info.Summary));
        var bubble = new Border
        {
            Background = Bc("#2A2A1E"),
            BorderBrush = Bc("#5A5A30"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(10, 8, 10, 8),
            Margin = new Thickness(16, 8, 16, 8),
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = FgGreen,
            FontSize = 11,
            FontWeight = FontWeights.SemiBold
        });
        if (!string.IsNullOrWhiteSpace(info.Summary))
        {
            panel.Children.Add(new TextBlock
            {
                Text = info.Summary,
                Foreground = FgDim,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0)
            });
        }
        bubble.Child = panel;
        _messageContainer.Children.Add(bubble);
        ScrollToBottom();
        UpdateContextMeter();
    }

    #endregion

    #region Message Bubbles

    private void AddUserBubble(string text)
    {
        var bubble = new Border
        {
            Background = BgUserBubble,
            CornerRadius = new CornerRadius(12, 12, 2, 12),
            Padding = new Thickness(12, 8, 12, 8),
            Margin = new Thickness(48, 6, 10, 2),
            HorizontalAlignment = HorizontalAlignment.Right,
            MaxWidth = 500
        };
        bubble.Child = CreateSelectableText(text, Brushes.White);
        _messageContainer.Children.Add(bubble);
        ScrollToBottom();
    }

    private void EnsureAssistantBubble()
    {
        if (_currentStreamBlock != null) return;

        var bubble = new Border
        {
            Background = BgAssistantBubble,
            CornerRadius = new CornerRadius(12, 12, 12, 2),
            Padding = new Thickness(12, 8, 12, 8),
            Margin = new Thickness(10, 6, 48, 2),
            HorizontalAlignment = HorizontalAlignment.Left,
            MaxWidth = 500
        };
        _streamContent = new StackPanel();
        _currentStreamBlock = CreateSelectableText("", FgNormal, copyWhole: () => _streamedMarkdown);
        _streamContent.Children.Add(_currentStreamBlock);
        _currentStreamBubble = bubble;
        bubble.Child = _streamContent;
        _messageContainer.Children.Add(bubble);
    }

    private void AppendStreamText(string text)
    {
        EnsureAssistantBubble();
        _streamedMarkdown += text;
        if (text.IndexOf('\n') < 0)
        {
            _currentStreamBlock!.Text += text;
            _currentStreamBlock.Visibility = Visibility.Visible;
            ScrollToBottom();
            return;
        }

        RefreshStreamSplit();
        ScrollToBottom();
    }

    /// <summary>
    /// Promote finished Markdown (closed fences, earlier paragraphs) for rendering
    /// while the model is still writing the tail.
    /// </summary>
    private void RefreshStreamSplit()
    {
        var (complete, remainder) = MarkdownHelper.SplitCompleteAndRemainder(_streamedMarkdown);
        if (!string.Equals(complete, _streamCompleteMarkdown, StringComparison.Ordinal))
        {
            _streamCompleteMarkdown = complete;
            if (string.IsNullOrWhiteSpace(complete))
            {
                if (_streamMarkdownView != null)
                    _streamMarkdownView.Visibility = Visibility.Collapsed;
            }
            else if (_streamMarkdownView == null)
            {
                _streamMarkdownView = CreateMarkdownView(complete, FgNormal, copyWhole: () => _streamedMarkdown);
                _streamMarkdownView.Margin = new Thickness(0, 0, 0, 6);
                _streamContent!.Children.Insert(0, _streamMarkdownView);
            }
            else
            {
                _streamMarkdownView.Document = MarkdownHelper.ToFlowDocument(complete, FgNormal);
                AttachMarkdownInteractions(_streamMarkdownView, () => _streamedMarkdown);
                _streamMarkdownView.Visibility = Visibility.Visible;
            }
        }

        _currentStreamBlock!.Text = remainder;
        _currentStreamBlock.Visibility = string.IsNullOrEmpty(remainder)
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    /// <summary>
    /// After streaming finishes (or before a tool call), replace plain text with rendered Markdown.
    /// </summary>
    private void FinalizeCurrentStreamBubble()
    {
        if (_currentStreamBubble == null)
        {
            ResetStreamState();
            return;
        }

        var markdown = _streamedMarkdown;
        if (string.IsNullOrWhiteSpace(markdown) && _currentStreamBlock != null)
            markdown = _currentStreamBlock.Text;

        if (!string.IsNullOrWhiteSpace(markdown))
        {
            _currentStreamBubble.Child = CreateMarkdownView(markdown, FgNormal);
            _transcript.Add(ChatTranscriptItem.Assistant(markdown));
        }

        ResetStreamState();
    }

    private void ResetStreamState()
    {
        _streamedMarkdown = "";
        _streamCompleteMarkdown = "";
        _streamMarkdownView = null;
        _streamContent = null;
        _currentStreamBlock = null;
        _currentStreamBubble = null;
    }

    private void ShowToolCallStarted(string toolName)
    {
        FinalizeCurrentStreamBubble();
        SetStatus($"Running {toolName}...");

        var display = FormatToolName(toolName);
        var panel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(10, 3, 10, 1)
        };
        var icon = new TextBlock
        {
            Text = "\u2699",
            Foreground = FgGreen,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 6, 0)
        };
        panel.Children.Add(icon);
        var nameBlock = new TextBlock
        {
            Text = display,
            Foreground = FgDim,
            FontSize = 11,
            FontFamily = new FontFamily("Cascadia Code, Consolas, Courier New"),
            VerticalAlignment = VerticalAlignment.Center
        };
        panel.Children.Add(nameBlock);
        _messageContainer.Children.Add(panel);
        _transcript.Add(ChatTranscriptItem.Tool(toolName));
        ScrollToBottom();
    }

    private void ShowToolCallCompleted(string toolName, string result)
    {
        SetStatus("Thinking...");
        if (!LooksLikeToolError(result))
            return;

        var snippet = TruncateToolError(result);
        _transcript.Add(ChatTranscriptItem.ToolError(snippet));
        var line = CreateSelectableText(snippet, Bc("#F48771"), 11);
        line.Margin = new Thickness(28, 0, 10, 4);
        _messageContainer.Children.Add(line);
        ScrollToBottom();
    }

    internal static bool LooksLikeToolError(string result)
    {
        if (string.IsNullOrWhiteSpace(result))
            return false;

        var t = result.TrimStart();
        if (t.StartsWith("Error:", StringComparison.OrdinalIgnoreCase))
            return true;
        if (t.Contains("timed out after", StringComparison.OrdinalIgnoreCase))
            return true;
        if (t.Contains("JavaScript error:", StringComparison.OrdinalIgnoreCase))
            return true;
        if (!t.StartsWith('{'))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(t);
            return doc.RootElement.TryGetProperty("error", out var err) &&
                   err.ValueKind == JsonValueKind.String &&
                   !string.IsNullOrWhiteSpace(err.GetString());
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string TruncateToolError(string result)
    {
        var text = result.Trim();
        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.TryGetProperty("error", out var err) &&
                err.ValueKind == JsonValueKind.String)
            {
                var msg = err.GetString();
                if (!string.IsNullOrWhiteSpace(msg))
                    text = msg.Trim();
            }
        }
        catch (JsonException)
        {
            /* keep raw */
        }

        const int max = 220;
        if (text.Length <= max)
            return text;
        return text[..max] + "\u2026";
    }

    private readonly HashSet<string> _sessionApprovedTools = new(StringComparer.Ordinal);
    private readonly HashSet<string> _sessionApprovedSafetyModes = new(StringComparer.OrdinalIgnoreCase);
    private bool _sessionApproveAllNameBased;

    /// <summary>
    /// Modal approval for flagged tool calls. Uses separate dialogs and persisted settings for
    /// by-name tools (user/session safety) vs active/aggressive safetyMode (server safety).
    /// </summary>
    private Task<bool> ConfirmToolCallAsync(string toolName, string argumentsJson, string reason)
    {
        // Path-triggered approvals depend on the arguments, so only tools that are dangerous
        // by name (or a fixed safety mode) can be approved for the whole chat session.
        var nameOnly = ChatToolApproval.IsNameOnlyReason(toolName, reason);
        if (nameOnly && ShouldAutoApproveNameBased(toolName))
            return Task.FromResult(true);

        if (ChatToolApproval.TryParseSafetyModeReason(reason, out var safetyMode)
            && ShouldAutoApproveSafetyMode(safetyMode))
            return Task.FromResult(true);

        return Dispatcher.InvokeAsync(() =>
        {
            var args = argumentsJson.Length > 1200 ? argumentsJson[..1200] + "\u2026" : argumentsJson;
            var owner = Window.GetWindow(this);
            var dialog = new Window
            {
                Title = "Allow assistant action?",
                Owner = owner,
                WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen,
                SizeToContent = SizeToContent.Height,
                Width = 560,
                ResizeMode = ResizeMode.NoResize,
                ShowInTaskbar = false
            };
            bool allowed = false;
            var panel = new StackPanel { Margin = new Thickness(14) };
            panel.Children.Add(new TextBlock
            {
                Text = $"The assistant wants to call {toolName}, which {reason}.\n\n" +
                       "Page content can steer the assistant. Only allow this if you asked for it.",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            });
            panel.Children.Add(new TextBox
            {
                Text = args,
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                MaxHeight = 220,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                FontFamily = new FontFamily("Consolas"),
                Margin = new Thickness(0, 0, 0, 12)
            });
            CheckBox? disableFuturePrompts = null;
            var isSafetyModeReason = ChatToolApproval.TryParseSafetyModeReason(reason, out var dialogSafetyMode);
            if (isSafetyModeReason && _llmClient?.Settings.ConfirmActiveSafetyProbes != false)
            {
                disableFuturePrompts = new CheckBox
                {
                    Content = "Don't ask again for active/aggressive security probes (change in LLM Settings)",
                    Margin = new Thickness(0, 0, 0, 12)
                };
                panel.Children.Add(disableFuturePrompts);
            }
            else if (nameOnly && _llmClient?.Settings.ConfirmSensitiveAssistantActions != false)
            {
                disableFuturePrompts = new CheckBox
                {
                    Content = "Don't ask again for script, fetch, and similar sensitive tools (change in LLM Settings)",
                    Margin = new Thickness(0, 0, 0, 12)
                };
                panel.Children.Add(disableFuturePrompts);
            }

            void OnAllowed()
            {
                allowed = true;
                if (disableFuturePrompts?.IsChecked == true && _llmClient != null)
                {
                    if (isSafetyModeReason)
                        _llmClient.Settings.ConfirmActiveSafetyProbes = false;
                    else
                        _llmClient.Settings.ConfirmSensitiveAssistantActions = false;
                    _llmClient.Settings.Save();
                }
            }

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            Button Make(string text, Action onClick, bool isDefault = false, bool isCancel = false)
            {
                var b = new Button
                {
                    Content = text, Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(6, 0, 0, 0),
                    IsDefault = isDefault, IsCancel = isCancel
                };
                b.Click += (_, _) => { onClick(); dialog.Close(); };
                return b;
            }
            buttons.Children.Add(Make("Allow once", OnAllowed));
            if (nameOnly)
            {
                buttons.Children.Add(Make("Allow all for this chat", () =>
                {
                    OnAllowed();
                    _sessionApproveAllNameBased = true;
                }));
                buttons.Children.Add(Make($"Allow {toolName} for this chat", () =>
                {
                    OnAllowed();
                    _sessionApprovedTools.Add(toolName);
                }));
            }
            else if (isSafetyModeReason)
            {
                buttons.Children.Add(Make($"Allow {dialogSafetyMode} probes for this chat", () =>
                {
                    OnAllowed();
                    _sessionApprovedSafetyModes.Add(dialogSafetyMode);
                }));
            }
            buttons.Children.Add(Make("Deny", () => allowed = false, isDefault: true, isCancel: true));
            panel.Children.Add(buttons);
            dialog.Content = panel;
            dialog.ShowDialog();
            return allowed;
        }).Task;
    }

    private bool ShouldAutoApproveNameBased(string toolName)
    {
        if (_llmClient?.Settings.ConfirmSensitiveAssistantActions == false)
            return true;
        if (_sessionApproveAllNameBased)
            return true;
        return _sessionApprovedTools.Contains(toolName);
    }

    private bool ShouldAutoApproveSafetyMode(string safetyMode)
    {
        if (_llmClient?.Settings.ConfirmActiveSafetyProbes == false)
            return true;
        return _sessionApprovedSafetyModes.Contains(safetyMode);
    }

    private void ShowError(string message)
    {
        FinalizeCurrentStreamBubble();
        var bubble = new Border
        {
            Background = Bc("#3D1F1F"),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12, 8, 12, 8),
            Margin = new Thickness(10, 6, 10, 2),
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        bubble.Child = CreateSelectableText("\u26A0 " + message, Bc("#F48771"), 12);
        _messageContainer.Children.Add(bubble);
        _transcript.Add(ChatTranscriptItem.Error(message));
        ScrollToBottom();
    }

    #endregion

    #region Decisions

    /// <summary>
    /// Render an agent-to-human decision as a card in the conversation: the question, its options as
    /// A/B/C/D buttons, and — once it resolves — what was chosen and by whom. The card polls
    /// <paramref name="refresh"/> once a second so a decision resolved elsewhere (the REST answer
    /// route, a timeout default, or the agent withdrawing it) stops asking for an answer it no longer
    /// needs. <paramref name="onAnswer"/> receives the option key and, for the lettered Other option,
    /// the custom text the tester typed.
    /// </summary>
    public void ShowDecision(Decision decision, Func<Decision?> refresh, Action<string, string?> onAnswer)
    {
        FinalizeCurrentStreamBubble();
        _emptyState.Visibility = Visibility.Collapsed;

        var accent = decision.Lane switch
        {
            DecisionLanes.Gate => Bc("#F5A623"),
            DecisionLanes.Review => FgDim,
            _ => FgBlue
        };

        var card = new Border
        {
            Background = BgAssistantBubble,
            BorderBrush = accent,
            BorderThickness = new Thickness(3, 0, 0, 0),
            CornerRadius = new CornerRadius(2, 8, 8, 2),
            Padding = new Thickness(12, 10, 12, 10),
            Margin = new Thickness(10, 8, 16, 4),
            HorizontalAlignment = HorizontalAlignment.Stretch
        };

        var body = new StackPanel();

        body.Children.Add(new TextBlock
        {
            Text = DecisionCardCopy.LaneHeader(decision),
            Foreground = accent,
            FontSize = 10,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 6)
        });

        body.Children.Add(new TextBlock
        {
            Text = decision.Question,
            Foreground = FgNormal,
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 8)
        });

        var pointerLine = DecisionCardCopy.PointerLine(decision);
        if (!string.IsNullOrEmpty(pointerLine))
        {
            body.Children.Add(new TextBlock
            {
                Text = pointerLine,
                Foreground = FgDim,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            });
        }

        var optionPanel = new StackPanel();
        foreach (var option in decision.Options)
            optionPanel.Children.Add(CreateDecisionOptionButton(decision, option, onAnswer));
        if (decision.AllowOther)
            AddOtherAnswerControls(decision, optionPanel, onAnswer);
        body.Children.Add(optionPanel);

        var footer = new TextBlock
        {
            Foreground = FgDim,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0)
        };
        body.Children.Add(footer);

        card.Child = body;
        card.ContextMenu = CreateCopyContextMenu(() =>
            DecisionCardCopy.PlainText(refresh() ?? decision));
        _messageContainer.Children.Add(card);
        _transcript.Add(ChatTranscriptItem.FromDecision(decision));
        ScrollToBottom();

        StartDecisionCardTimer(decision, refresh, optionPanel, footer);
    }

    private Border CreateDecisionOptionButton(Decision decision, DecisionOption option, Action<string, string?> onAnswer)
    {
        var recommended = string.Equals(option.Key, decision.Recommendation, StringComparison.OrdinalIgnoreCase);

        var content = new StackPanel();
        var line = new TextBlock
        {
            Foreground = recommended ? FgGreen : FgBlue,
            FontSize = 12,
            FontFamily = new FontFamily("Segoe UI"),
            TextWrapping = TextWrapping.Wrap
        };
        line.Inlines.Add(new Run($"{option.Key}  ") { FontWeight = FontWeights.Bold });
        line.Inlines.Add(new Run(option.Label));
        if (recommended)
            line.Inlines.Add(new Run("   recommended") { Foreground = FgDim, FontSize = 10 });
        content.Children.Add(line);

        if (!string.IsNullOrWhiteSpace(option.Detail))
        {
            content.Children.Add(new TextBlock
            {
                Text = option.Detail,
                Foreground = FgDim,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 0, 0)
            });
        }

        return CreateChipButton(content, FgBlue, () => onAnswer(option.Key, null));
    }

    private void AddOtherAnswerControls(Decision decision, StackPanel optionPanel, Action<string, string?> onAnswer)
    {
        var otherKey = decision.OtherKey ?? DecisionOption.KeyAt(decision.Options.Count);
        var otherPanel = new StackPanel { Visibility = Visibility.Collapsed, Margin = new Thickness(0, 4, 0, 0) };

        var input = new TextBox
        {
            Background = BgDark,
            Foreground = FgNormal,
            CaretBrush = FgNormal,
            BorderBrush = BorderColor,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            FontFamily = new FontFamily("Segoe UI"),
            Padding = new Thickness(8, 6, 8, 6),
            Margin = new Thickness(0, 0, 0, 4),
            MinHeight = 32
        };

        void SubmitOther()
        {
            var text = input.Text.Trim();
            if (string.IsNullOrEmpty(text)) return;
            onAnswer(otherKey, text);
        }

        input.PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.None)
            {
                e.Handled = true;
                SubmitOther();
            }
        };

        var submitRow = new StackPanel { Orientation = Orientation.Horizontal };
        submitRow.Children.Add(CreateChipButton("Send answer", FgGreen, SubmitOther));

        otherPanel.Children.Add(input);
        otherPanel.Children.Add(submitRow);

        var content = new StackPanel();
        var line = new TextBlock
        {
            Foreground = FgBlue,
            FontSize = 12,
            FontFamily = new FontFamily("Segoe UI"),
            TextWrapping = TextWrapping.Wrap
        };
        line.Inlines.Add(new Run($"{otherKey}  ") { FontWeight = FontWeights.Bold });
        line.Inlines.Add(new Run("Other…"));
        content.Children.Add(line);

        var otherBtn = CreateChipButton(content, FgBlue, () =>
        {
            otherPanel.Visibility = Visibility.Visible;
            input.Focus();
        });
        optionPanel.Children.Add(otherBtn);
        optionPanel.Children.Add(otherPanel);
    }

    /// <summary>
    /// Drive the card's countdown and swap the buttons for a verdict once the decision resolves.
    /// Polling the store beats subscribing because the card must also reflect resolutions it did not
    /// cause — a timeout, or an answer posted over REST.
    /// </summary>
    private void StartDecisionCardTimer(Decision decision, Func<Decision?> refresh, Panel optionPanel, TextBlock footer)
    {
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };

        void Render()
        {
            var current = refresh() ?? decision;
            var nextFooter = DecisionCardCopy.Footer(current);
            if (footer.Text != nextFooter)
                footer.Text = nextFooter;

            if (current.Status == DecisionStatuses.Pending)
                return;

            timer.Stop();
            optionPanel.Visibility = Visibility.Collapsed;
            footer.Foreground = current.Status switch
            {
                DecisionStatuses.Answered => FgGreen,
                DecisionStatuses.Defaulted or DecisionStatuses.Expired => Bc("#DCDCAA"),
                _ => FgDim
            };
        }

        timer.Tick += (_, _) => Render();
        // Stop the timer with the panel so a closed session does not keep ticking cards alive.
        Unloaded += (_, _) => timer.Stop();
        Render();
        if (decision.Status == DecisionStatuses.Pending)
            timer.Start();
    }

    #endregion

    #region UI Helpers

    /// <summary>
    /// Creates a read-only TextBox styled to look like a TextBlock, but with selectable/copyable text.
    /// Right-click Copy takes the whole message (or the selection, if there is one).
    /// </summary>
    private TextBox CreateSelectableText(string text, Brush foreground, double fontSize = 13, Func<string>? copyWhole = null)
    {
        var tb = new TextBox
        {
            Text = text,
            Foreground = foreground,
            FontSize = fontSize,
            FontFamily = new FontFamily("Segoe UI"),
            TextWrapping = TextWrapping.Wrap,
            IsReadOnly = true,
            BorderThickness = new Thickness(0),
            Background = Brushes.Transparent,
            Padding = new Thickness(0),
            Cursor = Cursors.IBeam,
            IsTabStop = false
        };
        tb.ContextMenu = CreateMessageContextMenu(
            copyText: () => tb.SelectionLength > 0
                ? tb.SelectedText
                : copyWhole?.Invoke() ?? tb.Text,
            selectAll: () => tb.SelectAll());
        return tb;
    }

    /// <summary>
    /// Read-only RichTextBox with Markdown rendered as a FlowDocument.
    /// </summary>
    private RichTextBox CreateMarkdownView(string markdown, Brush foreground, double fontSize = 13, Func<string>? copyWhole = null)
    {
        Func<string> whole = copyWhole ?? (() => markdown);
        var rtb = new RichTextBox
        {
            Document = MarkdownHelper.ToFlowDocument(markdown, foreground, fontSize),
            Foreground = foreground,
            FontSize = fontSize,
            FontFamily = new FontFamily("Segoe UI"),
            IsReadOnly = true,
            IsDocumentEnabled = true,
            BorderThickness = new Thickness(0),
            Background = Brushes.Transparent,
            Padding = new Thickness(0),
            Margin = new Thickness(0),
            Cursor = Cursors.IBeam,
            IsTabStop = false,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
            CaretBrush = Brushes.Transparent
        };
        rtb.ContextMenu = CreateMessageContextMenu(
            copyText: () => rtb.Selection.IsEmpty ? whole() : rtb.Selection.Text,
            selectAll: () => rtb.SelectAll());
        AttachMarkdownInteractions(rtb, whole);
        return rtb;
    }

    private void AttachMarkdownInteractions(RichTextBox rtb, Func<string> fullMarkdown)
    {
        MarkdownHelper.ForEachCodeBox(rtb.Document, codeBox =>
        {
            codeBox.ContextMenu = CreateMessageContextMenu(
                copyText: () => codeBox.SelectionLength > 0 ? codeBox.SelectedText : fullMarkdown(),
                selectAll: () => codeBox.SelectAll());
        });
    }

    private ContextMenu CreateMessageContextMenu(Func<string?> copyText, Action selectAll)
    {
        var menu = new ContextMenu();
        var copyItem = new MenuItem { Header = "Copy", InputGestureText = "Ctrl+C" };
        copyItem.Click += (_, _) => CopyToClipboard(copyText());
        menu.Items.Add(copyItem);
        var selectAllItem = new MenuItem { Header = "Select All", InputGestureText = "Ctrl+A" };
        selectAllItem.Click += (_, _) => selectAll();
        menu.Items.Add(selectAllItem);
        menu.Items.Add(new Separator());
        AddSessionMenuItems(menu);
        return menu;
    }

    private static void CopyToClipboard(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return;
        try
        {
            Clipboard.SetText(text);
        }
        catch
        {
            /* clipboard locked by another process */
        }
    }

    private ContextMenu CreateSessionContextMenu()
    {
        var menu = new ContextMenu();
        AddSessionMenuItems(menu);
        return menu;
    }

    /// <summary>Copy plus session actions (Compact, Show as HTML) for non-markdown blocks such as decision cards.</summary>
    private ContextMenu CreateCopyContextMenu(Func<string?> copyText)
    {
        var menu = new ContextMenu();
        var copyItem = new MenuItem { Header = "Copy", InputGestureText = "Ctrl+C" };
        copyItem.Click += (_, _) => CopyToClipboard(copyText());
        menu.Items.Add(copyItem);
        menu.Items.Add(new Separator());
        AddSessionMenuItems(menu);
        return menu;
    }

    private void AddSessionMenuItems(ContextMenu menu)
    {
        var compactItem = new MenuItem { Header = "Compact" };
        compactItem.Click += (_, _) => _ = ManualCompactAsync();
        menu.Items.Add(compactItem);
        var htmlItem = new MenuItem { Header = "Show as HTML" };
        htmlItem.Click += (_, _) => RequestShowAsHtml();
        menu.Items.Add(htmlItem);
    }

    private void RequestShowAsHtml() =>
        ShowAsHtmlRequested?.Invoke(GenerateConversationHtml());

    /// <summary>
    /// Header "x" behavior: if a conversation is in progress, go back to the empty
    /// start page (clearing it). If already on the start page, close the panel.
    /// </summary>
    private void CloseOrClear()
    {
        if (_emptyState.Visibility == Visibility.Visible)
        {
            CloseRequested?.Invoke();
            return;
        }

        if (_isProcessing)
            StopGeneration();
        ClearChat();
    }

    private void ClearChat()
    {
        _messageContainer.Children.Clear();
        _transcript.Clear();
        _messageContainer.Children.Add(_emptyState);
        _emptyState.Visibility = Visibility.Visible;
        ResetStreamState();
        if (_llmClient != null)
        {
            // Ensure mode/prompt from latest settings are used for the new conversation.
            if (_mcpHandler != null)
                _mcpHandler.Mode = _llmClient.Settings.Mode;
            _llmClient.ClearCachedPrompts();
            _conversation = _llmClient.CreateConversation();
            _sessionApprovedTools.Clear();
            _sessionApproveAllNameBased = false;
        }
        else
        {
            _conversation = null;
        }
    }

    private void SetStatus(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            _statusText.Visibility = Visibility.Collapsed;
            _statusText.Text = "";
        }
        else
        {
            _statusText.Text = text;
            _statusText.Visibility = Visibility.Visible;
        }
    }

    private void ScrollToBottom()
    {
        Dispatcher.InvokeAsync(() => _scrollViewer.ScrollToEnd(), DispatcherPriority.Background);
    }

    private void InputBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.None)
        {
            e.Handled = true;
            _ = SendMessageAsync();
        }
    }

    private StackPanel CreateEmptyState()
    {
        var panel = new StackPanel
        {
            VerticalAlignment = VerticalAlignment.Top,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Margin = new Thickness(20, 30, 20, 20)
        };

        var disclaimer = new TextBlock
        {
            FontStyle = FontStyles.Italic,
            Foreground = FgDim,
            FontSize = 12,
            HorizontalAlignment = HorizontalAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            TextAlignment = TextAlignment.Center,
            Margin = new Thickness(0, 0, 0, 24)
        };
        disclaimer.Inlines.Add(new Run("You") { FontWeight = FontWeights.SemiBold });
        disclaimer.Inlines.Add(" are responsible for the results, and how it is reported");
        panel.Children.Add(disclaimer);

        // --- Links to quicktests with code ---
        panel.Children.Add(CreateSectionHeader("\u26A1 Fast testing with code"));

        var quicktests = new (string label, string quicktestName)[]
        {
            ("Site health check", "SiteHealth"),
            ("Accessibility audit", "Usability.ResponsiveAccessibility"),
            ("Security scan", "Security.1 SecurityScan"),
            ("Robustness (request fuzzer)", "Reliability.RequestFuzzer"),
            ("Backward compatibility warning", "Compliance.BrowserCompatibilityScan"),
        };

        foreach (var (label, quicktestName) in quicktests)
        {
            panel.Children.Add(CreateQuicktestLink(label, quicktestName));
        }

        // --- LLM testing section ---
        panel.Children.Add(CreateSectionHeader("\U0001F916 AI assisted testing", topMargin: 20));

        string[] suggestions =
        [
            "\U0001F4A1  what should I test?",
            "\U0001F41B  check this page quickly for major bugs",
            "\U0001F50D  give me some candidates for deeper testing",
            "\u26A1  create some useful C# scripts for me",
            "\U0001F4D6  understand this page and test if it does what it's supposed to"
        ];

        foreach (var suggestion in suggestions)
        {
            panel.Children.Add(CreateSuggestionButton(suggestion));
        }

        return panel;
    }

    private static TextBlock CreateSectionHeader(string text, double topMargin = 0)
    {
        return new TextBlock
        {
            Text = text,
            Foreground = FgNormal,
            FontSize = 13,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, topMargin, 0, 8)
        };
    }

    private Border CreateQuicktestLink(string label, string quicktestName) =>
        CreateChipButton("\u25B6  " + label, FgGreen, () => QuicktestRequested?.Invoke(quicktestName));

    private Border CreateSuggestionButton(string suggestion) =>
        CreateChipButton(suggestion, FgBlue, () =>
        {
            var cleanText = suggestion[(suggestion.IndexOf(' ') + 1)..].Trim();
            _inputBox.Text = cleanText;
            _ = SendMessageAsync();
        });

    /// <summary>
    /// The panel's one clickable-row shape, shared by quicktest links, start-page suggestions and
    /// decision options. <paramref name="content"/> takes a string or any element, so an option
    /// button can stack its label and consequence on two lines.
    /// </summary>
    private static Border CreateChipButton(object content, Brush foreground, Action onClick)
    {
        var btn = new Border
        {
            Background = BgPanel,
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(12, 8, 12, 8),
            Margin = new Thickness(0, 2, 0, 2),
            Cursor = Cursors.Hand,
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        btn.Child = content as UIElement ?? new TextBlock
        {
            Text = content as string ?? content.ToString(),
            Foreground = foreground,
            FontSize = 12,
            FontFamily = new FontFamily("Segoe UI"),
            TextWrapping = TextWrapping.Wrap
        };
        btn.MouseEnter += (_, _) => btn.Background = Bc("#3E3E42");
        btn.MouseLeave += (_, _) => btn.Background = BgPanel;
        btn.MouseLeftButtonDown += (_, _) => onClick();
        return btn;
    }

    private string GenerateConversationHtml()
    {
        var model = _llmClient?.Settings?.Model ?? "";
        return ChatSessionHtml.Generate(_transcript, model, DateTime.Now);
    }

    private static string FormatToolName(string toolName) =>
        ChatSessionHtml.FormatToolName(toolName);

    private static Button CreateHeaderButton(string content, string tooltip, double? width = 28)
    {
        var btn = new Button
        {
            Content = content,
            Height = 24,
            FontSize = 12,
            Background = Brushes.Transparent,
            Foreground = FgDim,
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
            ToolTip = tooltip,
            VerticalAlignment = VerticalAlignment.Center,
            Padding = new Thickness(width == null ? 6 : 0, 0, width == null ? 6 : 0, 0)
        };
        if (width != null)
            btn.Width = width.Value;
        return btn;
    }

    private static SolidColorBrush Bc(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }

    #endregion
}
