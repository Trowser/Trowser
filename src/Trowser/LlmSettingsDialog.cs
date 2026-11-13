using System.Diagnostics;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Trowser.Api;
using Trowser.Chat;

namespace Trowser;

/// <summary>
/// LLM Settings dialog: built-in AI Assistant provider, model, prompts, and MCP client config copy.
/// Dark-themed to match the Trowser UI.
/// </summary>
public class LlmSettingsDialog : Window
{
    private readonly ComboBox _mcpClientCombo;
    private readonly ComboBox _providerCombo;
    private readonly TextBox _endpointTextBox;
    private readonly TextBlock _endpointHint;
    private readonly StackPanel _githubHostPanel;
    private readonly TextBox _githubHostTextBox;
    private readonly PasswordBox _apiKeyBox;
    private readonly ComboBox _modelCombo;
    private readonly TextBlock _modelHint;
    private readonly TextBox _temperatureTextBox;
    private readonly TextBox _maxTokensTextBox;
    private readonly RadioButton _modeChat;
    private readonly RadioButton _modeFull;
    private readonly RadioButton _modeEconomical;
    private readonly CheckBox _streamResponsesCheckBox;
    private readonly CheckBox _confirmSensitiveActionsCheckBox;
    private readonly CheckBox _confirmActiveSafetyProbesCheckBox;
    private readonly TextBlock _llmStatusText;
    private readonly TextBlock _apiKeyHint;
    private readonly Dictionary<string, LlmProviderProfile> _providerProfiles;
    private readonly Dictionary<string, List<string>> _modelsByCacheKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _selectedModelByCacheKey = new(StringComparer.OrdinalIgnoreCase);
    private int _previousProviderIndex;
    private string? _previousModelCacheKey;
    private string? _systemPromptChat;
    private string? _systemPromptFull;
    private string? _systemPromptEconomical;
    private CancellationTokenSource? _setupCts;

    private readonly bool _proxyEnabled;
    private readonly string _proxyUrl;
    private int _apiPort;
    private readonly string _apiKey;
    private readonly Func<int?> _ensureApiRunning;
    private readonly int _contextBudgetTokens;
    private readonly bool _autoCompactEnabled;
    private readonly int _compactWarnPercent;
    private readonly int _compactForcePercent;
    private readonly int _compactKeepLastTurns;

    public LlmSettings GetLlmSettings()
    {
        var provider = IndexToProvider(_providerCombo.SelectedIndex);
        CaptureUiIntoProfile(_providerCombo.SelectedIndex);

        var settings = new LlmSettings
        {
            Provider = provider,
            Endpoint = _endpointTextBox.Text.Trim(),
            GitHubHost = _githubHostTextBox.Text.Trim(),
            ApiKey = _apiKeyBox.Password,
            Model = GetModelText().Trim(),
            Temperature = double.TryParse(_temperatureTextBox.Text.Trim(), out var t) ? Math.Clamp(t, 0, 2) : 0.3,
            MaxTokens = int.TryParse(_maxTokensTextBox.Text.Trim(), out var m) && m > 0 ? m : null,
            Mode = _modeEconomical.IsChecked == true ? InteractionMode.Economical
                 : _modeFull.IsChecked == true ? InteractionMode.Full
                 : InteractionMode.Chat,
            StreamResponses = _streamResponsesCheckBox.IsChecked == true,
            StreamResponsesUserSet = true,
            ConfirmSensitiveAssistantActions = _confirmSensitiveActionsCheckBox.IsChecked != false,
            ConfirmActiveSafetyProbes = _confirmActiveSafetyProbesCheckBox.IsChecked != false,
            Providers = LlmSettings.CloneProfiles(_providerProfiles),
            ProxyEnabled = _proxyEnabled,
            ProxyUrl = _proxyUrl,
            ContextBudgetTokens = _contextBudgetTokens,
            AutoCompactEnabled = _autoCompactEnabled,
            CompactWarnPercent = _compactWarnPercent,
            CompactForcePercent = _compactForcePercent,
            CompactKeepLastTurns = _compactKeepLastTurns,
            SystemPromptChat = _systemPromptChat,
            SystemPromptFull = _systemPromptFull,
            SystemPromptEconomical = _systemPromptEconomical
        };
        settings.CaptureActiveToProfile();
        settings.EnsureProviderProfiles();
        return settings;
    }

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");

    public LlmSettingsDialog(Window owner, LlmSettings llmSettings, int apiPort, string? apiKey, Func<int?> ensureApiRunning)
    {
        Owner = owner;
        Title = "LLM Settings";
        Width = 560;
        Height = 820;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        Background = BgMedium;

        _proxyEnabled = llmSettings.ProxyEnabled;
        _proxyUrl = llmSettings.ProxyUrl;
        _apiPort = apiPort;
        _apiKey = apiKey ?? "";
        _ensureApiRunning = ensureApiRunning;
        _contextBudgetTokens = llmSettings.ContextBudgetTokens;
        _autoCompactEnabled = llmSettings.AutoCompactEnabled;
        _compactWarnPercent = llmSettings.CompactWarnPercent;
        _compactForcePercent = llmSettings.CompactForcePercent;
        _compactKeepLastTurns = llmSettings.CompactKeepLastTurns;

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var scrollViewer = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Padding = new Thickness(0)
        };

        var rootStack = new StackPanel { Margin = new Thickness(24, 20, 24, 12) };

        _systemPromptChat = llmSettings.SystemPromptChat;
        _systemPromptFull = llmSettings.SystemPromptFull;
        _systemPromptEconomical = llmSettings.SystemPromptEconomical;

        // Two sections, both always shown and usable together: built-in Chat (API key) first,
        // external agent (MCP) below.
        var chatStack = new StackPanel();
        var agentStack = new StackPanel();
        AddSectionHeader(rootStack, "Built-in Chat — uses an API key");
        rootStack.Children.Add(chatStack);
        AddSectionHeader(rootStack, "External agent — Claude Code, Cursor, OpenCode…", topMargin: 24);
        rootStack.Children.Add(agentStack);

        AddLabel(chatStack, "Interaction Mode");
        var modeHint = new TextBlock
        {
            Text = "Choose your style of assistant, and change in Prompt... for fruther customization.",
            Foreground = FgDim,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 6)
        };
        chatStack.Children.Add(modeHint);
        var modeRow = new Grid { Margin = new Thickness(0, 0, 0, 4) };
        modeRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        modeRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var modeStack = new StackPanel();
        _modeEconomical = new RadioButton
        {
            Content = "Economical \u2014 everyday live testing (default)",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 2, 0, 2),
            GroupName = "InteractionMode",
            IsChecked = llmSettings.Mode == InteractionMode.Economical
        };
        modeStack.Children.Add(_modeEconomical);
        _modeChat = new RadioButton
        {
            Content = "Chat \u2014 testing advisor, observes and guides",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 2, 0, 2),
            GroupName = "InteractionMode",
            IsChecked = llmSettings.Mode == InteractionMode.Chat
        };
        modeStack.Children.Add(_modeChat);
        _modeFull = new RadioButton
        {
            Content = "Full \u2014 security testing and specialist tools",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 2, 0, 2),
            GroupName = "InteractionMode",
            IsChecked = llmSettings.Mode == InteractionMode.Full
        };
        modeStack.Children.Add(_modeFull);
        Grid.SetColumn(modeStack, 0);
        modeRow.Children.Add(modeStack);

        var promptBtn = new Button
        {
            Content = "Prompt\u2026",
            Width = 90,
            Height = 28,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 0, 0, 0),
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand,
            ToolTip = "Edit the system prompt for each interaction mode"
        };
        promptBtn.Click += (_, _) =>
        {
            var selectedMode = _modeEconomical.IsChecked == true ? InteractionMode.Economical
                : _modeFull.IsChecked == true ? InteractionMode.Full
                : InteractionMode.Chat;
            var working = new LlmSettings
            {
                SystemPromptChat = _systemPromptChat,
                SystemPromptFull = _systemPromptFull,
                SystemPromptEconomical = _systemPromptEconomical
            };
            var promptDialog = new PromptDialog(this, working, selectedMode);
            if (promptDialog.ShowDialog() == true)
            {
                _systemPromptChat = promptDialog.SystemPromptChat;
                _systemPromptFull = promptDialog.SystemPromptFull;
                _systemPromptEconomical = promptDialog.SystemPromptEconomical;
                _modeChat.IsChecked = promptDialog.SelectedMode == InteractionMode.Chat;
                _modeFull.IsChecked = promptDialog.SelectedMode == InteractionMode.Full;
                _modeEconomical.IsChecked = promptDialog.SelectedMode == InteractionMode.Economical;
            }
        };
        Grid.SetColumn(promptBtn, 1);
        modeRow.Children.Add(promptBtn);
        chatStack.Children.Add(modeRow);

        AddLabel(chatStack, "Provider");
        _providerCombo = new ComboBox
        {
            Width = 420,
            Height = 30,
            HorizontalAlignment = HorizontalAlignment.Left,
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            FontSize = 13,
        };
        DarkComboBoxHelper.ApplyDarkStyle(_providerCombo);
        _providerCombo.Items.Add(DarkComboBoxHelper.CreateItem("OpenRouter \u2014 free router by default (recommended)"));
        _providerCombo.Items.Add(DarkComboBoxHelper.CreateItem("OpenAI-compatible (OpenAI, Ollama, LM Studio, vLLM, Azure\u2026)"));
        _providerCombo.Items.Add(DarkComboBoxHelper.CreateItem("Anthropic (Claude)"));
        _providerCombo.Items.Add(DarkComboBoxHelper.CreateItem("GitHub Copilot (via gh CLI)"));
        _providerCombo.SelectedIndex = ProviderToIndex(llmSettings.Provider);
        _previousProviderIndex = _providerCombo.SelectedIndex;

        _providerProfiles = LlmSettings.CloneProfiles(llmSettings.Providers);
        OverlayActiveProfile(llmSettings);

        _providerCombo.SelectionChanged += ProviderCombo_SelectionChanged;
        chatStack.Children.Add(_providerCombo);

        var presetRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(0, 8, 0, 2)
        };
        var ollamaBtn = CreateSmallButton("Use Ollama");
        ollamaBtn.ToolTip = "Point at local Ollama (http://localhost:11434/v1). No API key required.";
        ollamaBtn.Click += (_, _) => ApplyOllamaPreset();
        presetRow.Children.Add(ollamaBtn);

        var testBtn = CreateSmallButton("Test connection");
        testBtn.Margin = new Thickness(8, 0, 0, 0);
        testBtn.ToolTip = "Verify endpoint, credentials, and model.";
        testBtn.Click += (_, _) => _ = RunConnectionTestAsync();
        presetRow.Children.Add(testBtn);

        var fetchBtn = CreateSmallButton("Fetch models");
        fetchBtn.Margin = new Thickness(8, 0, 0, 0);
        fetchBtn.ToolTip = "Load model ids from the provider (OpenRouter, OpenAI-compatible, Ollama, GitHub Copilot).";
        fetchBtn.Click += (_, _) => _ = RunFetchModelsAsync();
        presetRow.Children.Add(fetchBtn);
        chatStack.Children.Add(presetRow);

        _llmStatusText = new TextBlock
        {
            Text = "",
            Foreground = FgDim,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 4, 0, 4),
            Visibility = Visibility.Collapsed
        };
        chatStack.Children.Add(_llmStatusText);

        AddLabel(chatStack, "API Endpoint");
        _endpointTextBox = CreateTextBox(llmSettings.Endpoint);
        _endpointTextBox.TextChanged += (_, _) =>
        {
            RefreshApiKeyHint();
            UpdateConfiguredStatus();
        };
        chatStack.Children.Add(_endpointTextBox);
        _endpointHint = new TextBlock
        {
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 2, 0, 0),
            TextWrapping = TextWrapping.Wrap
        };
        chatStack.Children.Add(_endpointHint);

        _githubHostPanel = new StackPanel();
        AddLabel(_githubHostPanel, "GitHub host (Copilot)");
        _githubHostTextBox = CreateTextBox(llmSettings.GitHubHost ?? "");
        _githubHostTextBox.TextChanged += (_, _) =>
        {
            RefreshApiKeyHint();
            UpdateConfiguredStatus();
        };
        _githubHostPanel.Children.Add(_githubHostTextBox);
        AddHint(_githubHostPanel, "Leave empty to auto-detect from Copilot CLI / gh. Example: company.ghe.com");
        chatStack.Children.Add(_githubHostPanel);

        AddLabel(chatStack, "API Key");
        _apiKeyBox = new PasswordBox
        {
            Password = llmSettings.ApiKey,
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 4, 8, 4),
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            Height = 30
        };
        _apiKeyBox.PasswordChanged += (_, _) =>
        {
            RefreshApiKeyHint();
            UpdateConfiguredStatus();
        };
        chatStack.Children.Add(_apiKeyBox);
        _apiKeyHint = new TextBlock
        {
            Foreground = FgDim,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 2, 0, 0)
        };
        chatStack.Children.Add(_apiKeyHint);

        AddLabel(chatStack, "Model");
        _modelCombo = new ComboBox
        {
            IsEditable = true,
            Height = 30,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            FontSize = 13,
            StaysOpenOnEdit = true
        };
        DarkComboBoxHelper.ApplyDarkEditableStyle(_modelCombo);
        SeedDefaultModels(llmSettings);
        _previousModelCacheKey = ModelCacheKey(llmSettings.Provider, llmSettings.Endpoint);
        ApplyModelListForCacheKey(_previousModelCacheKey, llmSettings.Model);
        _modelCombo.AddHandler(System.Windows.Controls.Primitives.TextBoxBase.TextChangedEvent,
            new TextChangedEventHandler((_, _) => UpdateConfiguredStatus()));
        chatStack.Children.Add(_modelCombo);
        _modelHint = new TextBlock
        {
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 2, 0, 0),
            TextWrapping = TextWrapping.Wrap
        };
        chatStack.Children.Add(_modelHint);
        RefreshCopilotFields();

        var advancedRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };

        var tempStack = new StackPanel { Margin = new Thickness(0, 0, 20, 0) };
        AddLabel(tempStack, "Temperature");
        _temperatureTextBox = CreateTextBox(llmSettings.Temperature.ToString("F1"), 80);
        tempStack.Children.Add(_temperatureTextBox);
        AddHint(tempStack, "Sent to the model (0 = focused, higher = more random).");
        advancedRow.Children.Add(tempStack);

        var tokStack = new StackPanel();
        AddLabel(tokStack, "Max Tokens (optional)");
        _maxTokensTextBox = CreateTextBox(llmSettings.MaxTokens?.ToString() ?? "", 120);
        tokStack.Children.Add(_maxTokensTextBox);
        AddHint(tokStack, "Leave empty for provider default. Caps reply length.");
        advancedRow.Children.Add(tokStack);

        chatStack.Children.Add(advancedRow);

        _streamResponsesCheckBox = new CheckBox
        {
            Content = "Stream responses (show output incrementally)",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 10, 0, 2),
            IsChecked = llmSettings.StreamResponses
        };
        chatStack.Children.Add(_streamResponsesCheckBox);
        AddHint(chatStack, "Show tokens as they arrive. When off, each assistant step appears all at once — it does not stop tool calls or extra turns. Only turn on if you want continuous messaging and token usage / proxy noise is not a problem.");

        _confirmSensitiveActionsCheckBox = new CheckBox
        {
            Content = "Confirm sensitive assistant actions before they run",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 10, 0, 2),
            IsChecked = llmSettings.ConfirmSensitiveAssistantActions
        };
        chatStack.Children.Add(_confirmSensitiveActionsCheckBox);
        AddHint(chatStack,
            "When enabled, Chat asks before tools that run script, fetch with cookies, change mocks, and similar. " +
            "Page content can steer the assistant — keep this on on untrusted sites. Local file paths still ask when off.");

        _confirmActiveSafetyProbesCheckBox = new CheckBox
        {
            Content = "Confirm active/aggressive security probes before they run",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 10, 0, 2),
            IsChecked = llmSettings.ConfirmActiveSafetyProbes
        };
        chatStack.Children.Add(_confirmActiveSafetyProbesCheckBox);
        AddHint(chatStack,
            "When enabled, Chat asks before security tools run in active or aggressive safety mode (they can change server state). " +
            "Local file paths still ask when off.");

        RefreshApiKeyHint();
        UpdateConfiguredStatus();

        // ─── External agent: pick agent + mode; Claude Code also gets a task and Start ───
        AddLabel(agentStack, "Agent");
        var agentRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
        _mcpClientCombo = new ComboBox
        {
            Height = 28,
            Width = 180,
            HorizontalAlignment = HorizontalAlignment.Left,
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            FontSize = 12
        };
        foreach (var (_, displayName) in McpClientConfig.Clients)
            _mcpClientCombo.Items.Add(DarkComboBoxHelper.CreateItem(displayName));
        _mcpClientCombo.SelectedIndex = McpClientConfig.Clients
            .Select((c, i) => (c.Kind, i))
            .First(x => x.Kind == McpClientConfig.ClientKind.ClaudeCode).i;
        DarkComboBoxHelper.ApplyDarkStyle(_mcpClientCombo);
        agentRow.Children.Add(_mcpClientCombo);

        agentRow.Children.Add(new TextBlock
        {
            Text = "Mode",
            Foreground = FgText,
            FontSize = 12,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(16, 0, 8, 0)
        });
        var mcpModeCombo = new ComboBox
        {
            Height = 28,
            Width = 110,
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            FontSize = 12,
            ToolTip = "Core: everyday testing tools. Security: adds security testing tools."
        };
        mcpModeCombo.Items.Add(DarkComboBoxHelper.CreateItem("Core"));
        mcpModeCombo.Items.Add(DarkComboBoxHelper.CreateItem("Security"));
        mcpModeCombo.SelectedIndex = 0;
        DarkComboBoxHelper.ApplyDarkStyle(mcpModeCombo);
        agentRow.Children.Add(mcpModeCombo);
        agentStack.Children.Add(agentRow);
        AddHint(agentStack, "Copy MCP config: paste into the agent's MCP config. Enable Keep API key in Settings if you want a stable key. Prefer user-level mcp.json over committing secrets.");
        ExternalMcpMode SelectedMcpMode() =>
            mcpModeCombo.SelectedIndex == 1 ? ExternalMcpMode.Security : ExternalMcpMode.Core;

        // Claude Code only: task + Start (registers Trowser and opens a session with a starter prompt).
        var claudePanel = new StackPanel();
        AddLabel(claudePanel, "Task");
        var claudeRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
        var starterCombo = new ComboBox
        {
            Height = 28,
            Width = 180,
            HorizontalAlignment = HorizontalAlignment.Left,
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            FontSize = 12
        };
        foreach (var starter in McpClientConfig.ClaudeStarters)
            starterCombo.Items.Add(DarkComboBoxHelper.CreateItem(starter.Name));
        starterCombo.SelectedIndex = 0;
        DarkComboBoxHelper.ApplyDarkStyle(starterCombo);
        claudeRow.Children.Add(starterCombo);

        var claudeStartBtn = new Button
        {
            Content = "Start Claude Code",
            Height = 30,
            Padding = new Thickness(10, 0, 10, 0),
            Margin = new Thickness(8, 0, 0, 0),
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 11,
            Cursor = Cursors.Hand,
            ToolTip = "Open a terminal, register Trowser with Claude Code, and start a session with this task. Needs the claude CLI on PATH."
        };
        claudeStartBtn.Click += (_, _) =>
        {
            // Starts the REST API if it is off; returns the live port, or null if it could not start.
            var port = _ensureApiRunning();
            if (port == null)
            {
                claudeStartBtn.Content = "API failed";
                return;
            }
            _apiPort = port.Value;
            var starter = McpClientConfig.ClaudeStarters[starterCombo.SelectedIndex] with { Mode = SelectedMcpMode() };
            var command = McpClientConfig.BuildClaudeCodeLaunch(_apiPort, starter, _apiKey);
            try
            {
                Process.Start(new ProcessStartInfo("powershell.exe")
                {
                    ArgumentList = { "-NoExit", "-Command", command },
                    UseShellExecute = true
                });
                claudeStartBtn.Content = "Started";
            }
            catch
            {
                claudeStartBtn.Content = "Failed";
            }
        };
        // Each task suggests its mode (Security check → Security); the Mode combo can still override it.
        starterCombo.SelectionChanged += (_, _) =>
        {
            claudeStartBtn.Content = "Start Claude Code";
            mcpModeCombo.SelectedIndex =
                McpClientConfig.ClaudeStarters[starterCombo.SelectedIndex].Mode == ExternalMcpMode.Security ? 1 : 0;
        };
        claudeRow.Children.Add(claudeStartBtn);
        claudePanel.Children.Add(claudeRow);
        AddHint(claudePanel, "Uses your Claude subscription through Claude Code, not an API key. Needs the claude CLI installed and signed in. Registers Trowser as 'trowser' at user scope.");
        agentStack.Children.Add(claudePanel);

        var mcpCopyBtn = new Button
        {
            Content = "Copy MCP config",
            Height = 30,
            Padding = new Thickness(10, 0, 10, 0),
            Margin = new Thickness(8, 0, 0, 0),
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 11,
            Cursor = Cursors.Hand,
            ToolTip = "Copy MCP JSON for the selected agent and mode (includes URL and API key)"
        };
        mcpCopyBtn.Click += (_, _) =>
        {
            var kind = McpClientConfig.Clients[_mcpClientCombo.SelectedIndex].Kind;
            var json = McpClientConfig.Build(kind, _apiPort, SelectedMcpMode(), _apiKey);
            try
            {
                Clipboard.SetText(json);
                mcpCopyBtn.Content = "Copied";
            }
            catch
            {
                mcpCopyBtn.Content = "Failed";
            }
        };
        void ResetAgentButtons()
        {
            mcpCopyBtn.Content = "Copy MCP config";
            claudePanel.Visibility = McpClientConfig.Clients[_mcpClientCombo.SelectedIndex].Kind == McpClientConfig.ClientKind.ClaudeCode
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
        _mcpClientCombo.SelectionChanged += (_, _) => ResetAgentButtons();
        mcpModeCombo.SelectionChanged += (_, _) => mcpCopyBtn.Content = "Copy MCP config";
        ResetAgentButtons();
        agentRow.Children.Add(mcpCopyBtn);

        scrollViewer.Content = rootStack;
        Grid.SetRow(scrollViewer, 0);
        rootGrid.Children.Add(scrollViewer);

        // Buttons
        var buttonPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(24, 12, 24, 16)
        };

        var okButton = CreateButton("OK", true);
        okButton.Click += (_, _) => { DialogResult = true; };

        var cancelButton = CreateButton("Cancel", false);
        cancelButton.Click += (_, _) => { DialogResult = false; };
        cancelButton.Margin = new Thickness(8, 0, 0, 0);

        buttonPanel.Children.Add(okButton);
        buttonPanel.Children.Add(cancelButton);
        Grid.SetRow(buttonPanel, 1);
        rootGrid.Children.Add(buttonPanel);

        Content = rootGrid;

        Loaded += (_, _) =>
        {
            // Focus the already-selected Interaction Mode radio so the dialog opens at the top
            // without changing the user's previous choice (WPF Focus does not check a RadioButton).
            var selectedMode = _modeEconomical.IsChecked == true ? _modeEconomical
                : _modeFull.IsChecked == true ? _modeFull
                : _modeChat;
            selectedMode.Focus();
            scrollViewer.ScrollToHome();
        };
    }

    private void ProviderCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_endpointTextBox == null || _modelCombo == null) return;

        var newIndex = _providerCombo.SelectedIndex;

        CaptureUiIntoProfile(_previousProviderIndex);
        RememberCurrentModelSelection();

        _previousProviderIndex = newIndex;
        ApplyProfileToUi(newIndex);

        RefreshApiKeyHint();
        RefreshCopilotFields();
        UpdateConfiguredStatus();
    }

    private void OverlayActiveProfile(LlmSettings settings)
    {
        var profile = GetProfile(ProviderToIndex(settings.Provider));
        if (!string.IsNullOrWhiteSpace(settings.Endpoint))
            profile.Endpoint = settings.Endpoint;
        profile.ApiKey = settings.ApiKey ?? "";
        if (!string.IsNullOrWhiteSpace(settings.Model))
            profile.Model = settings.Model;
        if (!string.IsNullOrWhiteSpace(settings.GitHubHost))
            profile.GitHubHost = settings.GitHubHost;
    }

    private void CaptureUiIntoProfile(int comboIndex)
    {
        if (_endpointTextBox == null || _apiKeyBox == null)
            return;

        var profile = GetProfile(comboIndex);
        profile.Endpoint = _endpointTextBox.Text.Trim();
        profile.ApiKey = _apiKeyBox.Password;
        profile.Model = GetModelText().Trim();
        if (_githubHostTextBox != null)
            profile.GitHubHost = _githubHostTextBox.Text.Trim();
    }

    private void ApplyProfileToUi(int comboIndex)
    {
        var provider = IndexToProvider(comboIndex);
        var profile = GetProfile(comboIndex);

        var endpoint = string.IsNullOrWhiteSpace(profile.Endpoint)
            ? LlmSettings.DefaultEndpoint(provider)
            : profile.Endpoint;
        _endpointTextBox.Text = endpoint;

        if (_githubHostTextBox != null)
            _githubHostTextBox.Text = profile.GitHubHost ?? "";

        _apiKeyBox.Password = profile.ApiKey ?? "";

        var cacheKey = ModelCacheKey(provider, endpoint);
        var preferred = !string.IsNullOrWhiteSpace(profile.Model)
            ? profile.Model
            : _selectedModelByCacheKey.GetValueOrDefault(cacheKey)
              ?? LlmSettings.DefaultModel(provider);
        ApplyModelListForCacheKey(cacheKey, preferred);
        _previousModelCacheKey = cacheKey;
    }

    private LlmProviderProfile GetProfile(int comboIndex)
    {
        var provider = IndexToProvider(comboIndex);
        var key = LlmSettings.ProviderKey(provider);
        if (!_providerProfiles.TryGetValue(key, out var profile) || profile == null)
        {
            profile = LlmSettings.CreateDefaultProfile(provider);
            _providerProfiles[key] = profile;
        }

        return profile;
    }

    private void RefreshCopilotFields()
    {
        if (_githubHostPanel == null || _endpointHint == null || _modelHint == null)
            return;

        var copilot = IndexToProvider(_providerCombo.SelectedIndex) == LlmProvider.GitHubCopilot;
        _githubHostPanel.Visibility = copilot ? Visibility.Visible : Visibility.Collapsed;
        _endpointHint.Text = copilot
            ? "Copilot chat URL is taken from GitHub after login (endpoints.api). Leave the default unless you use a proxy."
            : "OpenRouter / OpenAI / Ollama presets fill this automatically.";
        _modelHint.Text = copilot
            ? "Use Copilot ids such as claude-sonnet-5 (not Anthropic date stamps). Click Fetch models to list what your license allows."
            : "Default openrouter/free lets OpenRouter pick a free model (tool-capable when needed). Or pick a specific slug / use Fetch models.";
    }

    private void ApplyOllamaPreset()
    {
        RememberCurrentModelSelection();

        // OpenAI-compatible + local endpoint; no key required.
        _providerCombo.SelectedIndex = ProviderToIndex(LlmProvider.OpenAiCompatible);
        _endpointTextBox.Text = LlmSettings.OllamaEndpoint;

        var cacheKey = ModelCacheKey(LlmProvider.OpenAiCompatible, LlmSettings.OllamaEndpoint);
        var preferred = _selectedModelByCacheKey.GetValueOrDefault(cacheKey)
                        ?? LlmSettings.DefaultOllamaModel;
        ApplyModelListForCacheKey(cacheKey, preferred);
        _previousModelCacheKey = cacheKey;

        RefreshApiKeyHint();
        UpdateConfiguredStatus();
        SetLlmStatus("Ollama preset applied. Start Ollama, then Fetch models or Test connection.", ok: true);
    }

    private async Task RunConnectionTestAsync()
    {
        _setupCts?.Cancel();
        _setupCts = new CancellationTokenSource();
        var ct = _setupCts.Token;

        SetLlmStatus("Testing connection\u2026", ok: null);
        var settings = SnapshotWorkingLlmSettings();
        var result = await LlmSetupService.TestConnectionAsync(settings, ct);
        if (ct.IsCancellationRequested) return;
        SetLlmStatus(result.Message, result.Ok);
        if (!result.Ok)
            UpdateConfiguredStatus(settings);
    }

    private async Task RunFetchModelsAsync()
    {
        _setupCts?.Cancel();
        _setupCts = new CancellationTokenSource();
        var ct = _setupCts.Token;

        SetLlmStatus("Fetching models\u2026", ok: null);
        var settings = SnapshotWorkingLlmSettings();
        var result = await LlmSetupService.ListModelsAsync(settings, ct);
        if (ct.IsCancellationRequested) return;

        if (!result.Ok)
        {
            SetLlmStatus(result.Message, ok: false);
            return;
        }

        var cacheKey = ModelCacheKey(settings.Provider, settings.Endpoint);
        var models = result.Models.Take(400).ToList();
        _modelsByCacheKey[cacheKey] = models;

        var current = GetModelText();
        var preferred = !string.IsNullOrWhiteSpace(current) &&
                        models.Any(m => m.Equals(current, StringComparison.OrdinalIgnoreCase))
            ? current
            : models.Count > 0 ? models[0] : current;

        ApplyModelListForCacheKey(cacheKey, preferred);
        _previousModelCacheKey = cacheKey;
        _selectedModelByCacheKey[cacheKey] = GetModelText();

        SetLlmStatus(result.Message, ok: true);
        UpdateConfiguredStatus();
    }

    private void RememberCurrentModelSelection()
    {
        if (_modelCombo == null) return;
        var key = _previousModelCacheKey ?? ModelCacheKey(
            IndexToProvider(_previousProviderIndex),
            _endpointTextBox?.Text ?? "");
        var model = GetModelText();
        if (!string.IsNullOrWhiteSpace(model))
            _selectedModelByCacheKey[key] = model;

        // Keep whatever is currently in the dropdown for that provider.
        if (_modelCombo.Items.Count > 0)
        {
            var items = new List<string>();
            foreach (var item in _modelCombo.Items)
            {
                var text = (item as ComboBoxItem)?.Content?.ToString() ?? item?.ToString();
                if (!string.IsNullOrWhiteSpace(text))
                    items.Add(text);
            }
            if (items.Count > 0)
                _modelsByCacheKey[key] = items;
        }
    }

    private void SeedDefaultModels(LlmSettings settings)
    {
        void Seed(string key, params string[] models) =>
            _modelsByCacheKey[key] = models.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        Seed("openRouter",
            LlmSettings.DefaultOpenRouterModel,
            "openai/gpt-4o-mini",
            "openai/gpt-4o",
            "anthropic/claude-sonnet-4",
            "google/gemini-2.5-flash",
            "meta-llama/llama-3.3-70b-instruct:free");

        Seed("openAiCompatible",
            LlmSettings.DefaultOpenAiModel,
            "gpt-4o-mini",
            "o4-mini",
            "gpt-4.1");

        Seed("ollama:" + LlmSettings.OllamaEndpoint.TrimEnd('/').ToLowerInvariant(),
            LlmSettings.DefaultOllamaModel,
            "llama3",
            "mistral",
            "qwen2.5",
            "deepseek-r1");

        Seed("anthropic",
            LlmSettings.DefaultAnthropicModel,
            "claude-opus-4-20250514",
            "claude-3-5-haiku-20241022");

        Seed("gitHubCopilot", LlmSettings.DefaultCopilotModels);

        foreach (var kv in _providerProfiles)
        {
            if (!LlmSettings.TryParseProviderKey(kv.Key, out var provider))
                continue;
            var profile = kv.Value;
            if (profile == null || string.IsNullOrWhiteSpace(profile.Model))
                continue;
            var key = ModelCacheKey(provider, profile.Endpoint);
            _selectedModelByCacheKey[key] = profile.Model;
        }

        var initialKey = ModelCacheKey(settings.Provider, settings.Endpoint);
        if (!string.IsNullOrWhiteSpace(settings.Model))
            _selectedModelByCacheKey[initialKey] = settings.Model;
    }

    private string ModelCacheKey(LlmProvider provider, string endpoint)
    {
        if (provider == LlmProvider.OpenAiCompatible &&
            LlmSettings.IsLocalEndpoint(endpoint))
        {
            var normalized = endpoint.Trim().TrimEnd('/').ToLowerInvariant();
            return "ollama:" + normalized;
        }

        return provider switch
        {
            LlmProvider.OpenRouter => "openRouter",
            LlmProvider.Anthropic => "anthropic",
            LlmProvider.GitHubCopilot => "gitHubCopilot",
            _ => "openAiCompatible"
        };
    }

    private void ApplyModelListForCacheKey(string cacheKey, string? preferredModel)
    {
        if (!_modelsByCacheKey.TryGetValue(cacheKey, out var models) || models.Count == 0)
        {
            models = new List<string>();
            if (!string.IsNullOrWhiteSpace(preferredModel))
                models.Add(preferredModel);
            _modelsByCacheKey[cacheKey] = models;
        }

        var selected = preferredModel;
        if (string.IsNullOrWhiteSpace(selected))
            selected = _selectedModelByCacheKey.GetValueOrDefault(cacheKey);
        if (string.IsNullOrWhiteSpace(selected) && models.Count > 0)
            selected = models[0];

        if (!string.IsNullOrWhiteSpace(selected) &&
            !models.Any(m => m.Equals(selected, StringComparison.OrdinalIgnoreCase)))
        {
            models = new List<string>(models) { selected };
            _modelsByCacheKey[cacheKey] = models;
        }

        _modelCombo.Items.Clear();
        foreach (var id in models)
            _modelCombo.Items.Add(DarkComboBoxHelper.CreateItem(id));

        _modelCombo.Text = selected ?? "";
        if (!string.IsNullOrWhiteSpace(selected))
            _selectedModelByCacheKey[cacheKey] = selected;
    }

    private LlmSettings SnapshotWorkingLlmSettings()
    {
        return new LlmSettings
        {
            Provider = IndexToProvider(_providerCombo.SelectedIndex),
            Endpoint = _endpointTextBox.Text.Trim(),
            GitHubHost = _githubHostTextBox.Text.Trim(),
            ApiKey = _apiKeyBox.Password,
            Model = GetModelText().Trim()
        };
    }

    private void RefreshApiKeyHint()
    {
        if (_apiKeyHint == null) return;

        var settings = SnapshotWorkingLlmSettings();
        if (settings.Provider == LlmProvider.GitHubCopilot)
        {
            _apiKeyHint.Text =
                "Optional: leave empty to use Copilot CLI (browser login) or `gh auth token`. " +
                "Env: COPILOT_GITHUB_TOKEN / GH_TOKEN / GITHUB_TOKEN. Classic PATs (ghp_) are not supported.";
            return;
        }

        if (!settings.RequiresApiKey)
        {
            _apiKeyHint.Text = "Local endpoint detected — API key optional.";
            return;
        }

        if (!string.IsNullOrWhiteSpace(_apiKeyBox.Password))
        {
            _apiKeyHint.Text = settings.UsesOpenRouter
                ? "Key stored in settings. Get keys at openrouter.ai/keys."
                : "Key stored in settings (plain text in %APPDATA%\\Trowser\\settings.json).";
            return;
        }

        var envName = settings.GetEnvironmentApiKeySource();
        if (envName != null)
        {
            _apiKeyHint.Text = $"Using {envName} from the environment (not saved to settings.json).";
            return;
        }

        _apiKeyHint.Text = settings.Provider switch
        {
            LlmProvider.OpenRouter => "Required. Paste an OpenRouter key, or set OPENROUTER_API_KEY. openrouter.ai/keys",
            LlmProvider.Anthropic => "Required. Paste an Anthropic key, or set ANTHROPIC_API_KEY.",
            _ => "Required for cloud endpoints. Paste a key, or set OPENAI_API_KEY."
        };
    }

    private void UpdateConfiguredStatus(LlmSettings? settings = null)
    {
        settings ??= SnapshotWorkingLlmSettings();

        var busy = _llmStatusText.Visibility == Visibility.Visible &&
                   (_llmStatusText.Text.StartsWith("Testing", StringComparison.Ordinal) ||
                    _llmStatusText.Text.StartsWith("Fetching", StringComparison.Ordinal));
        if (busy)
            return;

        if (settings.IsConfigured)
        {
            SetLlmStatus("Ready — Chat can send requests with this configuration.", ok: true);
        }
        else
        {
            var reason = string.IsNullOrWhiteSpace(settings.Model)
                ? "Not ready: set a model."
                : settings.RequiresApiKey && string.IsNullOrWhiteSpace(settings.GetEffectiveApiKey())
                    ? "Not ready: API key missing (settings or environment)."
                    : "Not ready: set endpoint and model.";
            SetLlmStatus(reason, ok: false);
        }
    }

    private void SetLlmStatus(string message, bool? ok)
    {
        _llmStatusText.Text = message;
        _llmStatusText.Visibility = string.IsNullOrEmpty(message) ? Visibility.Collapsed : Visibility.Visible;
        _llmStatusText.Foreground = ok switch
        {
            true => Bc("#4EC9B0"),
            false => Bc("#F48771"),
            null => FgDim
        };
    }

    private string GetModelText() =>
        _modelCombo?.Text?.Trim() ?? "";

    private static LlmProvider IndexToProvider(int index) => index switch
    {
        0 => LlmProvider.OpenRouter,
        2 => LlmProvider.Anthropic,
        3 => LlmProvider.GitHubCopilot,
        _ => LlmProvider.OpenAiCompatible
    };

    private static int ProviderToIndex(LlmProvider provider) => provider switch
    {
        LlmProvider.OpenRouter => 0,
        LlmProvider.Anthropic => 2,
        LlmProvider.GitHubCopilot => 3,
        _ => 1
    };

    private Button CreateSmallButton(string content)
    {
        return new Button
        {
            Content = content,
            Height = 28,
            Padding = new Thickness(10, 0, 10, 0),
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center
        };
    }

    #region UI Helpers

    private static void AddSectionHeader(StackPanel parent, string text, double topMargin = 0)
    {
        var header = new TextBlock
        {
            Text = text,
            Foreground = Bc("#569CD6"),
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, topMargin, 0, 10)
        };
        parent.Children.Add(header);
    }

    private static void AddLabel(Panel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = Brushes.White,
            FontSize = 12,
            Margin = new Thickness(0, 6, 0, 4)
        });
    }

    private static void AddHint(StackPanel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 2, 0, 0),
            TextWrapping = TextWrapping.Wrap
        });
    }

    private static TextBox CreateTextBox(string value, double width = double.NaN)
    {
        var tb = new TextBox
        {
            Text = value,
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 4, 8, 4),
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            Height = 30
        };
        if (!double.IsNaN(width))
        {
            tb.Width = width;
            tb.HorizontalAlignment = HorizontalAlignment.Left;
        }
        return tb;
    }

    private static Button CreateButton(string text, bool isDefault)
    {
        return new Button
        {
            Content = text,
            Width = 90,
            Height = 28,
            IsDefault = isDefault,
            IsCancel = !isDefault,
            Background = isDefault ? Bc("#0E639C") : Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand
        };
    }

    private static SolidColorBrush Bc(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }

    #endregion
}
