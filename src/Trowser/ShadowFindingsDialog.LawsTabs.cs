using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Trowser.Laws;
using Trowser.Security;

namespace Trowser;

public partial class ShadowFindingsDialog
{
    private StackPanel? _lawsList;
    private StackPanel? _proposalsList;
    private TabControl? _mainTabs;

    public event Action<string>? OpenLawInEditorRequested;
    public event Action<string>? LawCodeEditRequested;
    public event Action<string, bool>? LawCopiedToUser;
    public event Action<string>? UserLawDeleted;
    public event Action? ShadowConfigPersistRequested;

    private void BuildLawsAndProposalsTabs(TabControl tabs)
    {
        _mainTabs = tabs;

        var lawsTab = new TabItem { Header = "Laws" };
        var lawsScroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1)
        };
        _lawsList = new StackPanel();
        lawsScroll.Content = _lawsList;
        lawsTab.Content = lawsScroll;

        var proposalsTab = new TabItem { Header = "Proposals" };
        var propScroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1)
        };
        _proposalsList = new StackPanel();
        propScroll.Content = _proposalsList;
        proposalsTab.Content = propScroll;

        tabs.Items.Add(lawsTab);
        tabs.Items.Add(proposalsTab);

        tabs.SelectionChanged += (_, _) =>
        {
            if (tabs.SelectedIndex == 1)
                RefreshLawsTab();
            else if (tabs.SelectedIndex == 2)
                RefreshProposalsTab();
        };
    }

    private CheckBox CreateLawCheckBox(string content, bool isChecked, bool isEnabled = true)
    {
        return new CheckBox
        {
            Content = content,
            IsChecked = isChecked,
            IsEnabled = isEnabled,
            Foreground = FgText,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0)
        };
    }

    private static string FormatLawSourceTitle(string sourceFile)
    {
        if (sourceFile.StartsWith("embedded:", StringComparison.OrdinalIgnoreCase))
            return Path.GetFileName(sourceFile["embedded:".Length..]);
        return Path.GetFileName(sourceFile);
    }

    private static string FormatLawSourceSubtitle(string sourceFile)
    {
        if (sourceFile.StartsWith("embedded:", StringComparison.OrdinalIgnoreCase))
            return "Trowser embedded (read-only)";
        return sourceFile;
    }

    private void RefreshLawsTab()
    {
        if (_lawsList == null || _laws == null)
            return;

        _lawsList.Children.Clear();
        var laws = _laws.Loader.Diagnostics;
        if (laws.Count > 0)
        {
            _lawsList.Children.Add(new TextBlock
            {
                Text = "Compile diagnostics",
                Foreground = Bc("#CCA700"),
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(8, 8, 8, 4)
            });
            foreach (var d in laws)
            {
                _lawsList.Children.Add(new TextBlock
                {
                    Text = $"{d.SourceFile}: {d.Message}",
                    Foreground = FgDim,
                    FontSize = 10,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(8, 0, 8, 4)
                });
            }
        }

        _lawsList.Children.Add(new TextBlock
        {
            Text = "Choose Law files to run in Shadow for this session. Uncheck a file to skip all of its Laws on every site. "
                   + "Use the checkbox beside each Law to mute it without turning the file off.",
            Foreground = FgDim,
            FontSize = 10,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(10, 8, 10, 8)
        });

        var knownSources = _laws.GetLoadedLawSources();
        var bySource = _laws.Registry.All
            .Where(l => !string.IsNullOrEmpty(l.SourceFile) && !LawService.IsEphemeralScriptSource(l.SourceFile))
            .GroupBy(l => ShadowConfig.NormalizeLawSourceKey(l.SourceFile) ?? l.SourceFile!, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.Key.StartsWith("embedded:", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase);

        foreach (var group in bySource)
        {
            var sourceKey = group.First().SourceFile!;
            var fileActive = _shadow.Config.IsLawSourceActive(sourceKey);

            var fileBlock = new Border
            {
                Background = BgItem,
                BorderBrush = BorderClr,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 8, 10, 8),
                Margin = new Thickness(0, 0, 0, 1)
            };
            var fileStack = new StackPanel();

            var fileHeader = new Grid { Margin = new Thickness(0, 0, 0, 6) };
            fileHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            fileHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            fileHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var fileCheck = CreateLawCheckBox("", fileActive);
            fileCheck.ToolTip = "Use this Law file in Shadow for the current session";
            fileCheck.Checked += (_, _) =>
            {
                _shadow.Config.SetLawSourceActive(sourceKey, true, knownSources);
                ShadowConfigPersistRequested?.Invoke();
                RefreshLawsTab();
            };
            fileCheck.Unchecked += (_, _) =>
            {
                _shadow.Config.SetLawSourceActive(sourceKey, false, knownSources);
                ShadowConfigPersistRequested?.Invoke();
                RefreshLawsTab();
            };
            Grid.SetColumn(fileCheck, 0);
            fileHeader.Children.Add(fileCheck);

            var fileTitles = new StackPanel { Margin = new Thickness(0, 0, 8, 0) };
            fileTitles.Children.Add(new TextBlock
            {
                Text = FormatLawSourceTitle(sourceKey),
                Foreground = FgText,
                FontWeight = FontWeights.SemiBold,
                FontSize = 12
            });
            fileTitles.Children.Add(new TextBlock
            {
                Text = FormatLawSourceSubtitle(sourceKey),
                Foreground = FgDim,
                FontSize = 9,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 0, 0)
            });
            Grid.SetColumn(fileTitles, 1);
            fileHeader.Children.Add(fileTitles);

            var fileButtons = new StackPanel { Orientation = Orientation.Horizontal };
            var openBtn = CreateButton("Open", false);
            openBtn.FontSize = 10;
            openBtn.Height = 22;
            openBtn.Margin = new Thickness(0, 0, 6, 0);
            openBtn.Click += (_, _) => OpenLawInEditorRequested?.Invoke(sourceKey);
            fileButtons.Children.Add(openBtn);

            if (sourceKey.StartsWith("embedded:", StringComparison.OrdinalIgnoreCase))
            {
                var copyBtn = CreateButton("Copy to my Laws", false);
                copyBtn.FontSize = 10;
                copyBtn.Height = 22;
                copyBtn.Click += async (_, _) =>
                {
                    var (path, createdNew) = await _laws.CopyEmbeddedLawToUserAsync(sourceKey);
                    if (path != null)
                        LawCopiedToUser?.Invoke(path, createdNew);
                    RefreshLawsTab();
                };
                fileButtons.Children.Add(copyBtn);
            }
            else if (LawService.IsUserLawSource(sourceKey))
            {
                var deleteBtn = CreateButton("Delete file", false);
                deleteBtn.FontSize = 10;
                deleteBtn.Height = 22;
                deleteBtn.Click += async (_, _) =>
                {
                    var confirm = MessageBox.Show(
                        Owner,
                        $"Delete this Law file and unload its definitions?\n\n{sourceKey}",
                        "Delete user Law",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);
                    if (confirm != MessageBoxResult.Yes)
                        return;

                    if (await _laws.DeleteUserLawFileAsync(sourceKey))
                    {
                        UserLawDeleted?.Invoke(sourceKey);
                        RefreshLawsTab();
                    }
                };
                fileButtons.Children.Add(deleteBtn);
            }

            Grid.SetColumn(fileButtons, 2);
            fileHeader.Children.Add(fileButtons);
            fileStack.Children.Add(fileHeader);

            foreach (var law in group.OrderBy(l => l.Name, StringComparer.OrdinalIgnoreCase))
            {
                var muted = _shadow.Config.DisabledLaws.Contains(law.Id);
                var verdict = law.LastVerdict?.ToString() ?? "not exercised";
                var lawRow = new Grid { Margin = new Thickness(20, 0, 0, 6) };
                lawRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                lawRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                var lawCheck = CreateLawCheckBox("", !muted, fileActive);
                lawCheck.ToolTip = fileActive
                    ? "Include this Law when Shadow runs"
                    : "Enable the Law file above to use this Law";
                var lawId = law.Id;
                lawCheck.Checked += (_, _) =>
                {
                    _shadow.Config.DisabledLaws.Remove(lawId);
                    ShadowConfigPersistRequested?.Invoke();
                    RefreshLawsTab();
                };
                lawCheck.Unchecked += (_, _) =>
                {
                    _shadow.Config.DisabledLaws.Add(lawId);
                    ShadowConfigPersistRequested?.Invoke();
                    RefreshLawsTab();
                };
                Grid.SetColumn(lawCheck, 0);
                lawRow.Children.Add(lawCheck);

                var lawText = new StackPanel { Opacity = fileActive ? 1.0 : 0.55 };
                lawText.Children.Add(new TextBlock
                {
                    Text = law.Name,
                    Foreground = FgText,
                    FontWeight = FontWeights.SemiBold,
                    FontSize = 11
                });
                lawText.Children.Add(new TextBlock
                {
                    Text = $"{law.Trigger} · {verdict} · pass {law.PassCount} · fail {law.FailCount}",
                    Foreground = FgDim,
                    FontSize = 10,
                    Margin = new Thickness(0, 2, 0, 0)
                });
                Grid.SetColumn(lawText, 1);
                lawRow.Children.Add(lawText);
                fileStack.Children.Add(lawRow);
            }

            fileBlock.Child = fileStack;
            _lawsList.Children.Add(fileBlock);
        }

        if (_laws.Registry.All.Count(l => !LawService.IsEphemeralScriptSource(l.SourceFile)) == 0)
        {
            _lawsList.Children.Add(new TextBlock
            {
                Text = "No Laws loaded yet. Embedded Laws load in the background after startup.",
                Foreground = FgDim,
                FontStyle = FontStyles.Italic,
                Margin = new Thickness(10)
            });
        }
    }

    private void RefreshProposalsTab()
    {
        if (_proposalsList == null || _laws == null)
            return;

        _proposalsList.Children.Clear();
        foreach (var p in _laws.Proposals.Proposals)
        {
            var row = new Border
            {
                Background = BgItem,
                BorderBrush = BorderClr,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 8, 10, 8)
            };
            var stack = new StackPanel();
            stack.Children.Add(new TextBlock
            {
                Text = p.Title,
                Foreground = FgText,
                FontWeight = FontWeights.SemiBold,
                FontSize = 12
            });
            stack.Children.Add(new TextBlock
            {
                Text = $"{p.Source} · {p.Kind ?? "proposal"} · {p.Observations} samples · {p.Counterexamples} counterexamples",
                Foreground = FgDim,
                FontSize = 10,
                Margin = new Thickness(0, 2, 0, 4)
            });
            if (!string.IsNullOrWhiteSpace(p.Rationale))
            {
                stack.Children.Add(new TextBlock
                {
                    Text = p.Rationale,
                    Foreground = FgText,
                    FontSize = 10,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 0, 0, 4)
                });
            }
            foreach (var ev in p.Evidence.Take(2))
            {
                stack.Children.Add(new TextBlock
                {
                    Text = "• " + ev,
                    Foreground = FgDim,
                    FontSize = 10,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 0, 0, 2)
                });
            }

            var buttons = new StackPanel { Orientation = Orientation.Horizontal };
            var acceptBtn = CreateButton("Accept", true);
            acceptBtn.FontSize = 10;
            acceptBtn.Height = 22;
            acceptBtn.Margin = new Thickness(0, 0, 6, 0);
            var proposal = p;
            acceptBtn.Click += async (_, _) =>
            {
                var accepted = _laws.Proposals.Accept(proposal.Id);
                if (accepted != null)
                    await _laws.AppendProposalToUserLawsAsync(accepted);
                RefreshProposalsTab();
                RefreshLawsTab();
            };
            buttons.Children.Add(acceptBtn);

            var rejectBtn = CreateButton("Reject", false);
            rejectBtn.FontSize = 10;
            rejectBtn.Height = 22;
            rejectBtn.Click += (_, _) =>
            {
                _laws.Proposals.Reject(proposal.Id);
                RefreshProposalsTab();
            };
            buttons.Children.Add(rejectBtn);

            var editBtn = CreateButton("Edit", false);
            editBtn.FontSize = 10;
            editBtn.Height = 22;
            editBtn.Margin = new Thickness(6, 0, 0, 0);
            editBtn.Click += (_, _) => LawCodeEditRequested?.Invoke(proposal.Code);
            buttons.Children.Add(editBtn);

            var refineBtn = CreateButton("Refine (AI)", false);
            refineBtn.FontSize = 10;
            refineBtn.Height = 22;
            refineBtn.Margin = new Thickness(6, 0, 0, 0);
            refineBtn.Click += async (_, _) =>
            {
                refineBtn.IsEnabled = false;
                try
                {
                    var notes = $"{proposal.Observations} observations, {proposal.Counterexamples} counterexamples, host {proposal.Host}";
                    var (ok, code, _) = await _laws.CreateAuthor().RefineMinedProposalAsync(proposal.Code, notes);
                    LawCodeEditRequested?.Invoke(code);
                }
                finally
                {
                    refineBtn.IsEnabled = true;
                }
            };
            buttons.Children.Add(refineBtn);

            stack.Children.Add(buttons);
            row.Child = stack;
            _proposalsList.Children.Add(row);
        }

        if (_laws.Proposals.Proposals.Count == 0)
        {
            _proposalsList.Children.Add(new TextBlock
            {
                Text = "No proposals. Enable Laws mining in Experimental settings — mined invariants become Laws here (Accept / Edit / Refine), not from duplicate Shadow findings.",
                Foreground = FgDim,
                FontStyle = FontStyles.Italic,
                Margin = new Thickness(10)
            });
        }
    }
}
