using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Trowser.Automation;
using Trowser.EndpointProbe;
using Trowser.Security.RaceLab;

namespace Trowser.RaceLab;

/// <summary>Pick one or more captured network requests (Endpoint Probe-style list).</summary>
internal sealed class RaceLabRequestPickerDialog : Window
{
    private readonly AutomationContext _ctx;
    private readonly List<(EndpointProbeItem Item, CheckBox Box)> _rows = [];
    private readonly StackPanel _list;

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentGreen = Bc("#4EC9B0");

    public RaceLabRequestPickerDialog(AutomationContext ctx, Window owner)
    {
        _ctx = ctx;
        Owner = owner;
        Title = "Add from network log";
        Width = 820;
        Height = 520;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = BgMedium;
        ResizeMode = ResizeMode.CanResizeWithGrip;

        var root = new Grid { Margin = new Thickness(12) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        root.Children.Add(new TextBlock
        {
            Text = "Select requests captured in this session (browse the app first, then Refresh).",
            Foreground = FgDim,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 8)
        });

        var scroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1)
        };
        _list = new StackPanel { Margin = new Thickness(4) };
        scroll.Content = _list;
        Grid.SetRow(scroll, 1);
        root.Children.Add(scroll);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
        var refresh = MkBtn("Refresh", Refresh);
        var add = MkBtn("Add selected", () => { DialogResult = true; Close(); });
        add.IsDefault = true;
        buttons.Children.Add(refresh);
        buttons.Children.Add(MkBtn("Cancel", () => { DialogResult = false; Close(); }));
        buttons.Children.Add(add);
        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        Content = root;
        Refresh();
    }

    public IReadOnlyList<RaceLabRequest> GetSelectedRequests()
    {
        var list = new List<RaceLabRequest>();
        foreach (var (item, box) in _rows)
        {
            if (box.IsChecked != true) continue;
            list.Add(FromEndpoint(item));
        }

        return list;
    }

    private static RaceLabRequest FromEndpoint(EndpointProbeItem item)
    {
        var name = $"{item.Method} {Truncate(item.Url, 48)}";
        return new RaceLabRequest
        {
            Name = name,
            Url = item.Url,
            Method = item.Method,
            Headers = item.RequestHeaders.Count > 0
                ? new Dictionary<string, string>(item.RequestHeaders, StringComparer.OrdinalIgnoreCase)
                : null,
            Body = item.RequestBody,
            Session = RaceLabSessions.AllPeers,
            Role = RaceLabRoles.Observe
        };
    }

    private void Refresh()
    {
        _list.Children.Clear();
        _rows.Clear();
        var endpoints = EndpointProbeDiscovery.FromNetworkLog(_ctx.Network.Entries);
        if (endpoints.Count == 0)
        {
            _list.Children.Add(new TextBlock
            {
                Text = "No endpoints in the network log yet.",
                Foreground = FgDim,
                Margin = new Thickness(8)
            });
            return;
        }

        foreach (var item in endpoints.Take(200))
        {
            var cb = new CheckBox { IsChecked = false, Margin = new Thickness(0, 2, 0, 2) };
            var sp = new StackPanel { Orientation = Orientation.Horizontal };
            sp.Children.Add(cb);
            sp.Children.Add(new TextBlock
            {
                Text = $"{item.Method}  {Truncate(item.Url, 90)}",
                Foreground = FgText,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(6, 0, 0, 0)
            });
            _list.Children.Add(sp);
            _rows.Add((item, cb));
        }
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..(max - 1)] + "…";

    private static Button MkBtn(string text, Action onClick)
    {
        var b = new Button
        {
            Content = text,
            Margin = new Thickness(0, 0, 8, 0),
            Padding = new Thickness(10, 4, 10, 4),
            Background = Bc("#3E3E42"),
            Foreground = Bc("#CCCCCC")
        };
        b.Click += (_, _) => onClick();
        return b;
    }

    private static SolidColorBrush Bc(string hex) =>
        new((Color)ColorConverter.ConvertFromString(hex));
}
