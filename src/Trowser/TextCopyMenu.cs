using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Trowser;

/// <summary>
/// Dark context menu that copies a whole text area. Used where the UI is a
/// TextBlock, which WPF does not make selectable.
/// </summary>
internal static class TextCopyMenu
{
    private static readonly SolidColorBrush MenuBg = Bc("#2D2D30");
    private static readonly SolidColorBrush HoverBg = Bc("#3E3E42");
    private static readonly SolidColorBrush Fg = Bc("#CCCCCC");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");

    public static void Attach(FrameworkElement target, Func<string?> getText)
    {
        var item = CreateItem();
        var menu = new ContextMenu
        {
            Background = MenuBg,
            BorderBrush = BorderClr,
            HasDropShadow = true
        };
        menu.Items.Add(item);
        menu.Opened += (_, _) => item.IsEnabled = !string.IsNullOrWhiteSpace(getText());
        item.Click += (_, _) =>
        {
            var text = getText()?.Trim();
            if (string.IsNullOrEmpty(text)) return;
            Clipboard.SetText(text);
        };
        target.ContextMenu = menu;
    }

    private static MenuItem CreateItem()
    {
        var template = new ControlTemplate(typeof(MenuItem));
        var border = new FrameworkElementFactory(typeof(Border));
        border.Name = "Bd";
        border.SetValue(Border.BackgroundProperty, MenuBg);
        border.SetValue(Border.PaddingProperty, new Thickness(12, 6, 12, 6));
        var content = new FrameworkElementFactory(typeof(ContentPresenter));
        content.SetValue(ContentPresenter.ContentSourceProperty, "Header");
        border.AppendChild(content);
        template.VisualTree = border;

        var highlight = new Trigger { Property = MenuItem.IsHighlightedProperty, Value = true };
        highlight.Setters.Add(new Setter(Border.BackgroundProperty, HoverBg, "Bd"));
        template.Triggers.Add(highlight);

        return new MenuItem
        {
            Header = "Copy",
            Foreground = Fg,
            Template = template
        };
    }

    private static SolidColorBrush Bc(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }
}
