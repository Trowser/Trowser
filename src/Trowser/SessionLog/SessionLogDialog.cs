using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;

namespace Trowser.SessionLog;

/// <summary>
/// Dark-themed settings dialog for the session log feature.
/// Allows the user to pick a log file, toggle categories, and generate HTML reports.
/// </summary>
public class SessionLogDialog : Window
{
    private static readonly SolidColorBrush BgDark = Freeze("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Freeze("#2D2D30");
    private static readonly SolidColorBrush FgText = Freeze("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Freeze("#888888");
    private static readonly SolidColorBrush BorderClr = Freeze("#3F3F46");
    private static readonly SolidColorBrush AccentGreen = Freeze("#4EC9B0");
    private static readonly SolidColorBrush AccentOrange = Freeze("#EF9552");
    private static readonly SolidColorBrush AccentBlue = Freeze("#007ACC");

    private readonly TextBox _filePathBox;
    private readonly CheckBox _chkBrowserActions;
    private readonly CheckBox _chkNotes;
    private readonly CheckBox _chkScriptOutput;
    private readonly CheckBox _chkScreenshots;
    private readonly CheckBox _chkMessages;
    private readonly CheckBox _chkApiUsage;
    private readonly CheckBox _chkLlmNotes;
    private readonly CheckBox _chkRecordings;
    private readonly Button _toggleButton;

    private readonly SessionLogger _logger;
    private readonly SessionLogSettings _settings;
    private readonly Action _onStateChanged;
    private readonly Func<string?>? _getCurrentUrl;

    public SessionLogDialog(Window owner, SessionLogger logger, SessionLogSettings settings,
        Action onStateChanged, Func<string?>? getCurrentUrl = null)
    {
        _logger = logger;
        _settings = settings;
        _onStateChanged = onStateChanged;
        _getCurrentUrl = getCurrentUrl;

        Owner = owner;
        Title = "Session Log";
        Width = 520;
        Height = 500;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        Background = BgMedium;
        ShowInTaskbar = false;

        var root = new StackPanel { Margin = new Thickness(24, 20, 24, 20) };

        // --- Title ---
        root.Children.Add(new TextBlock
        {
            Text = "Session Log Settings",
            Foreground = FgText,
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 16)
        });

        // --- Log file path ---
        root.Children.Add(Label("Log file (.md):"));
        var fileRow = new DockPanel { Margin = new Thickness(0, 0, 0, 12) };

        var browseBtn = StyledButton("Browse...", 80);
        browseBtn.Click += BrowseButton_Click;
        DockPanel.SetDock(browseBtn, Dock.Right);
        fileRow.Children.Add(browseBtn);

        _filePathBox = new TextBox
        {
            Text = settings.LogFilePath ?? "",
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(6, 4, 6, 4),
            FontSize = 12,
            Margin = new Thickness(0, 0, 8, 0),
            VerticalContentAlignment = VerticalAlignment.Center
        };
        fileRow.Children.Add(_filePathBox);
        root.Children.Add(fileRow);

        // --- Category toggles ---
        root.Children.Add(Label("Log categories:"));
        var checkPanel = new StackPanel { Margin = new Thickness(0, 0, 0, 16) };

        _chkBrowserActions = StyledCheckBox("Browser actions (clicks, navigations, typing…)", settings.LogBrowserActions);
        _chkNotes = StyledCheckBox("Tester notes (Ctrl+Shift+T)", settings.LogNotes);
        _chkScriptOutput = StyledCheckBox("Script console output", settings.LogScriptOutput);
        _chkScreenshots = StyledCheckBox("Screenshots (Ctrl+Shift+S), requires logging turned on", settings.LogScreenshots);
        _chkMessages = StyledCheckBox("Messages (api/message)", settings.LogMessages);
        _chkApiUsage = StyledCheckBox("API usage (REST API commands from LLM)", settings.LogApiUsage);
        _chkLlmNotes = StyledCheckBox("LLM notes (api/journal)", settings.LogLlmNotes);
        _chkRecordings = StyledCheckBox("Recordings in textual format", settings.LogRecordings);

        checkPanel.Children.Add(_chkBrowserActions);
        checkPanel.Children.Add(_chkNotes);
        checkPanel.Children.Add(_chkScriptOutput);
        checkPanel.Children.Add(_chkScreenshots);
        checkPanel.Children.Add(_chkMessages);
        checkPanel.Children.Add(_chkApiUsage);
        checkPanel.Children.Add(_chkLlmNotes);
        checkPanel.Children.Add(_chkRecordings);
        root.Children.Add(checkPanel);

        // --- Buttons row ---
        var btnRow = new DockPanel { Margin = new Thickness(0, 8, 0, 0) };

        _toggleButton = StyledButton(_logger.IsLogging ? "⏹ Stop Logging" : "▶ Start Logging", 150);
        _toggleButton.Background = _logger.IsLogging ? Freeze("#C72E2E") : AccentGreen;
        _toggleButton.Foreground = Freeze("#FFFFFF");
        _toggleButton.Click += ToggleLogging_Click;
        btnRow.Children.Add(_toggleButton);

        var htmlBtn = StyledButton("Chronological Report", 150);
        htmlBtn.Click += HtmlReport_Click;
        DockPanel.SetDock(htmlBtn, Dock.Right);
        btnRow.Children.Add(htmlBtn);

        root.Children.Add(btnRow);

        // --- Status ---
        var statusText = _logger.IsLogging
            ? $"Logging to: {Path.GetFileName(_logger.FilePath)}"
            : "Not logging";
        var status = new TextBlock
        {
            Text = statusText,
            Foreground = _logger.IsLogging ? AccentGreen : FgDim,
            FontSize = 11,
            Margin = new Thickness(0, 16, 0, 0)
        };
        root.Children.Add(status);

        Content = root;

        Closing += (_, _) => SaveSettings();
    }

    private void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Filter = "Markdown Files (*.md)|*.md|All Files (*.*)|*.*",
            DefaultExt = ".md",
            Title = "Choose Session Log File",
            OverwritePrompt = false
        };

        if (!string.IsNullOrEmpty(_filePathBox.Text))
        {
            try
            {
                dialog.InitialDirectory = Path.GetDirectoryName(Path.GetFullPath(_filePathBox.Text));
                dialog.FileName = Path.GetFileName(_filePathBox.Text);
            }
            catch { /* ignore bad paths */ }
        }

        if (dialog.ShowDialog() == true)
            _filePathBox.Text = dialog.FileName;
    }

    private void ToggleLogging_Click(object sender, RoutedEventArgs e)
    {
        if (_logger.IsLogging)
        {
            _logger.Stop();
            _settings.LoggingEnabled = false;
        }
        else
        {
            var filePath = _filePathBox.Text.Trim();
            if (string.IsNullOrEmpty(filePath))
            {
                MessageBox.Show(this, "Please select a log file first.", "Session Log",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _settings.LoggingEnabled = true;
            SaveSettings();
            _logger.Settings = _settings;

            try
            {
                string? currentUrl = _getCurrentUrl?.Invoke();
                _logger.Start(filePath, currentUrl);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Failed to start logging:\n{ex.Message}", "Session Log",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
        }

        _toggleButton.Content = _logger.IsLogging ? "⏹ Stop Logging" : "▶ Start Logging";
        _toggleButton.Background = _logger.IsLogging ? Freeze("#C72E2E") : AccentGreen;
        _onStateChanged();
        Close();
    }

    private void HtmlReport_Click(object sender, RoutedEventArgs e)
    {
        var mdPath = _filePathBox.Text.Trim();
        if (string.IsNullOrEmpty(mdPath) || !File.Exists(mdPath))
        {
            MessageBox.Show(this, "No log file found. Start logging first or select an existing file.",
                "Session Log", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "HTML Files (*.html)|*.html|All Files (*.*)|*.*",
            DefaultExt = ".html",
            Title = "Save HTML Report",
            FileName = Path.GetFileNameWithoutExtension(mdPath) + ".html"
        };

        try
        {
            dialog.InitialDirectory = Path.GetDirectoryName(Path.GetFullPath(mdPath));
        }
        catch { }

        if (dialog.ShowDialog() != true) return;

        try
        {
            _logger.Flush();
            HtmlReportGenerator.Generate(mdPath, dialog.FileName);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Failed to generate report:\n{ex.Message}", "Session Log",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SaveSettings()
    {
        _settings.LogFilePath = _filePathBox.Text.Trim();
        _settings.LogBrowserActions = _chkBrowserActions.IsChecked == true;
        _settings.LogNotes = _chkNotes.IsChecked == true;
        _settings.LogScriptOutput = _chkScriptOutput.IsChecked == true;
        _settings.LogScreenshots = _chkScreenshots.IsChecked == true;
        _settings.LogMessages = _chkMessages.IsChecked == true;
        _settings.LogApiUsage = _chkApiUsage.IsChecked == true;
        _settings.LogLlmNotes = _chkLlmNotes.IsChecked == true;
        _settings.LogRecordings = _chkRecordings.IsChecked == true;
        _settings.Save();
    }

    // --- UI helpers ---

    private static TextBlock Label(string text) => new()
    {
        Text = text,
        Foreground = FgText,
        FontSize = 12,
        Margin = new Thickness(0, 0, 0, 4)
    };

    private static CheckBox StyledCheckBox(string text, bool isChecked) => new()
    {
        Content = text,
        IsChecked = isChecked,
        Foreground = FgText,
        FontSize = 12,
        Margin = new Thickness(0, 3, 0, 3)
    };

    private static Button StyledButton(string text, double width)
    {
        var btn = new Button
        {
            Content = text,
            Width = width,
            Height = 28,
            FontSize = 12,
            Background = Freeze("#3E3E42"),
            Foreground = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Cursor = Cursors.Hand
        };
        return btn;
    }

    private static SolidColorBrush Freeze(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}
