using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Trowser.Security;

namespace Trowser;

/// <summary>
/// SSL Manager dialog for managing client certificates.
/// Supports browsing for .pfx/.p12 files, entering passwords, setting aliases,
/// and switching the active certificate.
/// </summary>
public class SslManagerDialog : Window
{
    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentBlue = Bc("#569CD6");
    private static readonly SolidColorBrush ActiveGreen = Bc("#4EC9B0");
    private static readonly SolidColorBrush ExpiredRed = Bc("#F44747");

    private readonly SslManager _sslManager;
    private readonly ListBox _certListBox;
    private readonly TextBox _filePathTextBox;
    private readonly PasswordBox _passwordBox;
    private readonly TextBox _aliasTextBox;
    private readonly TextBlock _statusText;

    public SslManagerDialog(Window owner, SslManager sslManager)
    {
        _sslManager = sslManager;

        Owner = owner;
        Title = "SSL Manager";
        Width = 580;
        Height = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        Background = BgMedium;

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var scrollViewer = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Padding = new Thickness(0)
        };

        var rootStack = new StackPanel { Margin = new Thickness(24, 20, 24, 12) };

        // ─── Section: Loaded Certificates ───
        AddSectionHeader(rootStack, "Client Certificates");
        AddHint(rootStack, "Manage PKCS#12 (.pfx / .p12) client certificates for mutual TLS authentication.");

        _certListBox = new ListBox
        {
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Height = 160,
            Margin = new Thickness(0, 8, 0, 0),
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 12
        };
        rootStack.Children.Add(_certListBox);

        // Certificate action buttons
        var certBtnRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(0, 6, 0, 0)
        };

        var setActiveBtn = CreateSmallButton("Set Active");
        setActiveBtn.Click += SetActive_Click;
        certBtnRow.Children.Add(setActiveBtn);

        var clearActiveBtn = CreateSmallButton("Clear Active");
        clearActiveBtn.Margin = new Thickness(6, 0, 0, 0);
        clearActiveBtn.Click += ClearActive_Click;
        certBtnRow.Children.Add(clearActiveBtn);

        var removeBtn = CreateSmallButton("Remove");
        removeBtn.Margin = new Thickness(6, 0, 0, 0);
        removeBtn.Click += Remove_Click;
        certBtnRow.Children.Add(removeBtn);

        rootStack.Children.Add(certBtnRow);

        // ─── Section: Add Certificate ───
        AddSectionHeader(rootStack, "Add Certificate", topMargin: 20);

        // File path with browse button
        AddLabel(rootStack, "Certificate File (.pfx / .p12)");
        var fileRow = new StackPanel { Orientation = Orientation.Horizontal };
        _filePathTextBox = new TextBox
        {
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 4, 8, 4),
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            Height = 30,
            Width = 380,
            IsReadOnly = true
        };
        fileRow.Children.Add(_filePathTextBox);

        var browseBtn = CreateSmallButton("Browse…");
        browseBtn.Margin = new Thickness(6, 0, 0, 0);
        browseBtn.Width = 80;
        browseBtn.Click += Browse_Click;
        fileRow.Children.Add(browseBtn);
        rootStack.Children.Add(fileRow);

        // Password
        AddLabel(rootStack, "Password");
        _passwordBox = new PasswordBox
        {
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 4, 8, 4),
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            Height = 30
        };
        rootStack.Children.Add(_passwordBox);

        // Alias
        AddLabel(rootStack, "Alias (optional — defaults to filename)");
        _aliasTextBox = new TextBox
        {
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
        rootStack.Children.Add(_aliasTextBox);
        AddHint(rootStack, "Use alias to refer to this certificate in API/MCP/scripting: SslSetActive(\"my-alias\")");

        // Add button
        var addBtn = new Button
        {
            Content = "Add Certificate",
            Width = 140,
            Height = 30,
            HorizontalAlignment = HorizontalAlignment.Left,
            Background = Bc("#0E639C"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand,
            Margin = new Thickness(0, 10, 0, 0)
        };
        addBtn.Click += Add_Click;
        rootStack.Children.Add(addBtn);

        // Status
        _statusText = new TextBlock
        {
            Foreground = FgDim,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0)
        };
        rootStack.Children.Add(_statusText);

        scrollViewer.Content = rootStack;
        Grid.SetRow(scrollViewer, 0);
        rootGrid.Children.Add(scrollViewer);

        // Close button
        var buttonPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(24, 12, 24, 16)
        };

        var closeBtn = new Button
        {
            Content = "Close",
            Width = 90,
            Height = 28,
            IsCancel = true,
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand
        };
        closeBtn.Click += (_, _) => { DialogResult = true; };
        buttonPanel.Children.Add(closeBtn);

        Grid.SetRow(buttonPanel, 1);
        rootGrid.Children.Add(buttonPanel);

        Content = rootGrid;

        RefreshCertList();
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select Client Certificate",
            Filter = "PKCS#12 files (*.pfx;*.p12)|*.pfx;*.p12|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog(this) == true)
        {
            _filePathTextBox.Text = dialog.FileName;
            _passwordBox.Focus();

            if (string.IsNullOrWhiteSpace(_aliasTextBox.Text))
                _aliasTextBox.Text = Path.GetFileNameWithoutExtension(dialog.FileName);
        }
    }

    private void Add_Click(object sender, RoutedEventArgs e)
    {
        var filePath = _filePathTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(filePath))
        {
            SetStatus("Select a certificate file first.", isError: true);
            return;
        }

        try
        {
            var alias = _aliasTextBox.Text.Trim();
            var info = _sslManager.AddCertificate(filePath, _passwordBox.Password,
                string.IsNullOrWhiteSpace(alias) ? null : alias);

            SetStatus($"Added certificate '{info.Alias}' (expires {info.NotAfter:yyyy-MM-dd}).");
            _filePathTextBox.Text = "";
            _passwordBox.Clear();
            _aliasTextBox.Text = "";
            RefreshCertList();
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, isError: true);
        }
    }

    private void SetActive_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedAlias();
        if (selected == null)
        {
            SetStatus("Select a certificate from the list.", isError: true);
            return;
        }

        try
        {
            _sslManager.SetActive(selected);
            SetStatus($"Active certificate set to '{selected}'.");
            RefreshCertList();
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, isError: true);
        }
    }

    private void ClearActive_Click(object sender, RoutedEventArgs e)
    {
        _sslManager.SetActive(null);
        SetStatus("Active certificate cleared.");
        RefreshCertList();
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedAlias();
        if (selected == null)
        {
            SetStatus("Select a certificate from the list.", isError: true);
            return;
        }

        if (_sslManager.RemoveCertificate(selected))
        {
            SetStatus($"Certificate '{selected}' removed.");
            RefreshCertList();
        }
        else
        {
            SetStatus($"Certificate '{selected}' not found.", isError: true);
        }
    }

    private string? GetSelectedAlias()
    {
        if (_certListBox.SelectedItem is not ListBoxItem item) return null;
        return item.Tag as string;
    }

    private void RefreshCertList()
    {
        _certListBox.Items.Clear();
        var certs = _sslManager.ListCertificates();

        if (certs.Count == 0)
        {
            var emptyItem = new ListBoxItem
            {
                Content = "No certificates loaded",
                Foreground = FgDim,
                IsEnabled = false,
                FontStyle = FontStyles.Italic
            };
            _certListBox.Items.Add(emptyItem);
            return;
        }

        foreach (var cert in certs)
        {
            var stack = new StackPanel { Orientation = Orientation.Vertical, Margin = new Thickness(2) };

            // First line: alias + active badge
            var titleRow = new StackPanel { Orientation = Orientation.Horizontal };
            titleRow.Children.Add(new TextBlock
            {
                Text = cert.Alias,
                Foreground = cert.IsActive ? ActiveGreen : FgText,
                FontWeight = cert.IsActive ? FontWeights.Bold : FontWeights.Normal,
                FontSize = 13
            });
            if (cert.IsActive)
            {
                titleRow.Children.Add(new TextBlock
                {
                    Text = " ● ACTIVE",
                    Foreground = ActiveGreen,
                    FontSize = 10,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(6, 0, 0, 0)
                });
            }
            if (cert.IsExpired)
            {
                titleRow.Children.Add(new TextBlock
                {
                    Text = " ⚠ EXPIRED",
                    Foreground = ExpiredRed,
                    FontSize = 10,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(6, 0, 0, 0)
                });
            }
            stack.Children.Add(titleRow);

            // Second line: subject + expiry
            stack.Children.Add(new TextBlock
            {
                Text = $"{cert.Subject}  |  Expires: {cert.NotAfter:yyyy-MM-dd}  |  {cert.OriginalFileName}",
                Foreground = FgDim,
                FontSize = 10,
                TextTrimming = TextTrimming.CharacterEllipsis
            });

            var item = new ListBoxItem
            {
                Content = stack,
                Tag = cert.Alias,
                Background = Brushes.Transparent,
                Foreground = FgText,
                Padding = new Thickness(4, 2, 4, 2)
            };
            _certListBox.Items.Add(item);
        }
    }

    private void SetStatus(string text, bool isError = false)
    {
        _statusText.Text = text;
        _statusText.Foreground = isError ? ExpiredRed : ActiveGreen;
    }

    #region UI Helpers

    private static void AddSectionHeader(StackPanel parent, string text, double topMargin = 0)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = AccentBlue,
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, topMargin, 0, 10)
        });
    }

    private static void AddLabel(StackPanel parent, string text)
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
            Foreground = Bc("#888888"),
            FontSize = 10,
            Margin = new Thickness(0, 2, 0, 0),
            TextWrapping = TextWrapping.Wrap
        });
    }

    private static Button CreateSmallButton(string text)
    {
        return new Button
        {
            Content = text,
            Width = 90,
            Height = 26,
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 11,
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
