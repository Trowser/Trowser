using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace Trowser;

/// <summary>
/// Address-bar typed-URL completion (dropdown + prefix inline complete).
/// </summary>
public partial class MainWindow
{
    private string _addressBarTyped = "";
    private bool _addressBarProgrammatic;
    private bool _addressBarNavigatingSuggestions;
    private bool _skipInlineComplete;
    private Point _suggestionsMouseAnchor;
    private bool _suggestionsMouseArmed;

    private void AddressBar_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Back || (e.Key == Key.Delete && Keyboard.Modifiers == ModifierKeys.None))
            _skipInlineComplete = true;

        if (e.Key == Key.Down)
        {
            if (!AddressBarPopup.IsOpen)
                ShowSuggestions(useRecentsIfAllSelected: true);
            MoveSuggestion(1);
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Up && AddressBarPopup.IsOpen)
        {
            MoveSuggestion(-1);
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Escape)
        {
            if (AddressBarPopup.IsOpen)
            {
                HideSuggestions(restoreTyped: true);
                e.Handled = true;
            }
            return;
        }

        if (e.Key == Key.Tab && Keyboard.Modifiers == ModifierKeys.None)
        {
            if (AcceptInlineOrSelectedSuggestion())
                e.Handled = true;
            return;
        }

        if (e.Key == Key.Delete && Keyboard.Modifiers == ModifierKeys.Shift)
        {
            if (RemoveSelectedSuggestion())
                e.Handled = true;
            return;
        }

        if (e.Key == Key.Enter)
        {
            var url = SelectedSuggestionUrl();
            HideSuggestions(restoreTyped: false);
            NavigateTo(string.IsNullOrEmpty(url) ? AddressBar.Text : url);
            ActiveWebView?.Focus();
            e.Handled = true;
        }
    }

    private void AddressBar_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_addressBarProgrammatic || _addressBarNavigatingSuggestions)
            return;
        if (!AddressBar.IsKeyboardFocused)
            return;

        _addressBarTyped = AddressBar.Text;
        ShowSuggestions(useRecentsIfAllSelected: false);
        if (!_skipInlineComplete)
            TryInlineComplete();
    }

    private void AddressBar_PreviewTextInput(object sender, TextCompositionEventArgs e)
    {
        if (!string.IsNullOrEmpty(e.Text) && !char.IsControl(e.Text[0]))
            _skipInlineComplete = false;
    }

    private void AddressBar_GotKeyboardFocus(object sender, KeyboardFocusChangedEventArgs e)
    {
        if (!_addressBarProgrammatic)
            _addressBarTyped = AddressBar.Text;
    }

    private void AddressBar_LostKeyboardFocus(object sender, KeyboardFocusChangedEventArgs e)
    {
        Dispatcher.BeginInvoke(() =>
        {
            if (AddressBarPopup.IsMouseOver)
                return;
            if (AddressBar.IsKeyboardFocused)
                return;
            HideSuggestions(restoreTyped: false);
        }, System.Windows.Threading.DispatcherPriority.Input);
    }

    private void AddressBarSuggestions_MouseMove(object sender, MouseEventArgs e)
    {
        var pos = e.GetPosition(AddressBarSuggestions);
        if (!_suggestionsMouseArmed)
        {
            var dx = pos.X - _suggestionsMouseAnchor.X;
            var dy = pos.Y - _suggestionsMouseAnchor.Y;
            if (dx * dx + dy * dy < 16)
                return;
            _suggestionsMouseArmed = true;
        }

        if (FindAncestor<ListBoxItem>(e.OriginalSource as DependencyObject) is { } item)
            item.IsSelected = true;
    }

    private void AddressBarSuggestions_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (FindAncestor<Button>(e.OriginalSource as DependencyObject) != null)
            return;

        var url = SelectedSuggestionUrl();
        if (string.IsNullOrEmpty(url))
            return;

        HideSuggestions(restoreTyped: false);
        NavigateTo(url);
        ActiveWebView?.Focus();
        e.Handled = true;
    }

    private void ShowSuggestions(bool useRecentsIfAllSelected)
    {
        var query = _addressBarTyped;
        if (useRecentsIfAllSelected
            && AddressBar.SelectionLength == AddressBar.Text.Length
            && AddressBar.Text.Length > 0)
            query = "";

        var matches = _urlCompletion.Suggest(query);
        RebuildSuggestionList(matches);

        if (matches.Count == 0)
        {
            AddressBarPopup.IsOpen = false;
            return;
        }

        AddressBarPopup.MinWidth = AddressBarHost.ActualWidth;
        AddressBarPopup.Width = AddressBarHost.ActualWidth;
        AddressBarPopup.IsOpen = true;
        AddressBarSuggestions.SelectedIndex = -1;
        _suggestionsMouseArmed = false;
        _suggestionsMouseAnchor = Mouse.GetPosition(AddressBarSuggestions);
    }

    private void RebuildSuggestionList(IReadOnlyList<string> urls)
    {
        AddressBarSuggestions.Items.Clear();
        foreach (var url in urls)
            AddressBarSuggestions.Items.Add(CreateSuggestionItem(url));
    }

    private ListBoxItem CreateSuggestionItem(string url)
    {
        var text = new TextBlock
        {
            Text = url,
            TextTrimming = TextTrimming.CharacterEllipsis,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(10, 6, 8, 6),
            ToolTip = url
        };

        var remove = new Button
        {
            Content = "\u00D7",
            Width = 22,
            Height = 22,
            Margin = new Thickness(0, 0, 6, 0),
            Padding = new Thickness(0),
            Background = Brushes.Transparent,
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#888888")),
            BorderThickness = new Thickness(0),
            FontSize = 14,
            Cursor = Cursors.Hand,
            Focusable = false,
            VerticalAlignment = VerticalAlignment.Center,
            ToolTip = "Remove from completion (Shift+Delete)"
        };
        remove.Click += (_, e) =>
        {
            RemoveSuggestion(url);
            e.Handled = true;
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Grid.SetColumn(text, 0);
        Grid.SetColumn(remove, 1);
        grid.Children.Add(text);
        grid.Children.Add(remove);

        return new ListBoxItem
        {
            Content = grid,
            Tag = url,
            Focusable = false,
            HorizontalContentAlignment = HorizontalAlignment.Stretch
        };
    }

    private void MoveSuggestion(int delta)
    {
        if (AddressBarSuggestions.Items.Count == 0)
            return;

        var index = AddressBarSuggestions.SelectedIndex + delta;
        if (index < -1)
            index = AddressBarSuggestions.Items.Count - 1;
        if (index >= AddressBarSuggestions.Items.Count)
            index = -1;

        AddressBarSuggestions.SelectedIndex = index;
        if (index >= 0)
            AddressBarSuggestions.ScrollIntoView(AddressBarSuggestions.Items[index]);

        _addressBarNavigatingSuggestions = true;
        try
        {
            _addressBarProgrammatic = true;
            AddressBar.Text = index >= 0 ? SelectedSuggestionUrl() ?? _addressBarTyped : _addressBarTyped;
            AddressBar.CaretIndex = AddressBar.Text.Length;
        }
        finally
        {
            _addressBarProgrammatic = false;
            _addressBarNavigatingSuggestions = false;
        }
    }

    private void TryInlineComplete()
    {
        var typed = AddressBar.Text;
        if (typed.Length == 0 || AddressBar.CaretIndex != typed.Length)
            return;

        var match = _urlCompletion.BestPrefixMatch(typed);
        if (match == null || match.Equals(typed, StringComparison.OrdinalIgnoreCase))
            return;
        if (!match.StartsWith(typed, StringComparison.OrdinalIgnoreCase))
            return;

        _addressBarProgrammatic = true;
        try
        {
            AddressBar.Text = match;
            AddressBar.Select(typed.Length, match.Length - typed.Length);
        }
        finally
        {
            _addressBarProgrammatic = false;
        }
    }

    private bool AcceptInlineOrSelectedSuggestion()
    {
        if (AddressBar.SelectionLength > 0 && AddressBar.CaretIndex < AddressBar.Text.Length)
        {
            var caret = AddressBar.Text.Length;
            AddressBar.Select(caret, 0);
            AddressBar.CaretIndex = caret;
            _addressBarTyped = AddressBar.Text;
            return true;
        }

        var url = SelectedSuggestionUrl();
        if (string.IsNullOrEmpty(url) && AddressBarPopup.IsOpen && AddressBarSuggestions.Items.Count > 0)
        {
            AddressBarSuggestions.SelectedIndex = 0;
            url = SelectedSuggestionUrl();
        }

        if (string.IsNullOrEmpty(url))
            return false;

        _addressBarProgrammatic = true;
        try
        {
            AddressBar.Text = url;
            AddressBar.CaretIndex = url.Length;
            _addressBarTyped = url;
        }
        finally
        {
            _addressBarProgrammatic = false;
        }

        HideSuggestions(restoreTyped: false);
        return true;
    }

    private bool RemoveSelectedSuggestion()
    {
        var url = SelectedSuggestionUrl();
        if (string.IsNullOrEmpty(url))
            return false;
        RemoveSuggestion(url);
        return true;
    }

    private void RemoveSuggestion(string url)
    {
        _urlCompletion.Remove(url);
        AddressBar.Focus();
        SetAddressBarText(_addressBarTyped);
        ShowSuggestions(useRecentsIfAllSelected: string.IsNullOrEmpty(_addressBarTyped));
    }

    private void HideSuggestions(bool restoreTyped)
    {
        AddressBarPopup.IsOpen = false;
        AddressBarSuggestions.Items.Clear();
        if (restoreTyped)
            SetAddressBarText(_addressBarTyped);
    }

    private void SetAddressBarText(string text)
    {
        _addressBarProgrammatic = true;
        try
        {
            AddressBar.Text = text;
            AddressBar.CaretIndex = text.Length;
        }
        finally
        {
            _addressBarProgrammatic = false;
        }
    }

    private string? SelectedSuggestionUrl()
    {
        if (AddressBarSuggestions.SelectedItem is ListBoxItem { Tag: string url })
            return url;
        return null;
    }

    private static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current != null)
        {
            if (current is T match)
                return match;
            current = VisualTreeHelper.GetParent(current);
        }
        return null;
    }
}
