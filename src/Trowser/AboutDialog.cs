using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Trowser;

public class AboutDialog : Window
{
    private static readonly SolidColorBrush BgMedium = Freeze("#2D2D30");
    private static readonly SolidColorBrush FgText = Freeze("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Freeze("#888888");
    private static readonly SolidColorBrush BorderClr = Freeze("#3F3F46");
    private static readonly SolidColorBrush AccentClr = Freeze("#EF9552");

    public AboutDialog(Window owner)
    {
        Owner = owner;
        Title = "About Trowser";
        Width = 420;
        Height = 500;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        Background = BgMedium;
        ShowInTaskbar = false;

        var version = Assembly.GetExecutingAssembly().GetName().Version;
        var versionText = version != null
            ? $"{version.Major}.{version.Minor}.{version.Build}"
            : "1.0.0";

        var stack = new StackPanel
        {
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(32, 24, 32, 24)
        };

        var icon = new Image
        {
            Source = new BitmapImage(new Uri("pack://application:,,,/Resources/trowser.ico")),
            Width = 96,
            Height = 96,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 16)
        };
        stack.Children.Add(icon);

        stack.Children.Add(new TextBlock
        {
            Text = "Trowser",
            Foreground = AccentClr,
            FontSize = 32,
            FontWeight = FontWeights.Bold,
            FontFamily = new FontFamily("Segoe UI"),
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 2)
        });

        stack.Children.Add(new TextBlock
        {
            Text = $"Version {versionText}",
            Foreground = FgDim,
            FontSize = 13,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 14)
        });

        stack.Children.Add(new TextBlock
        {
            Text = "Exploratory Tester\u2019s Companion",
            Foreground = FgText,
            FontSize = 16,
            FontStyle = FontStyles.Italic,
            FontFamily = new FontFamily("Segoe UI"),
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 20)
        });

        var separator = new Border
        {
            Height = 1,
            Background = BorderClr,
            Margin = new Thickness(40, 0, 40, 16),
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        stack.Children.Add(separator);

        stack.Children.Add(new TextBlock
        {
            Text = "Powered by WebView2 \u00B7 .NET 8",
            Foreground = FgDim,
            FontSize = 11,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 10)
        });

        stack.Children.Add(new TextBlock
        {
            Text = "Third-party libraries",
            Foreground = FgDim,
            FontSize = 11,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 4)
        });

        stack.Children.Add(new TextBlock
        {
            Text = "axe-core \u00B7 gremlins.js \u00B7 html-validate \u00B7 retire.js",
            Foreground = FgDim,
            FontSize = 11,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 2)
        });

        stack.Children.Add(new TextBlock
        {
            Text = "web-vitals \u00B7 csp-evaluator \u00B7 tldts \u00B7 nuclei-templates",
            Foreground = FgDim,
            FontSize = 11,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 16)
        });

        var licenseLink = new TextBlock
        {
            Text = "License: MIT",
            Foreground = AccentClr,
            FontSize = 11,
            HorizontalAlignment = HorizontalAlignment.Center,
            Cursor = Cursors.Hand,
            TextDecorations = TextDecorations.Underline,
            Margin = new Thickness(0, 0, 0, 12)
        };
        licenseLink.MouseLeftButtonUp += (_, _) =>
        {
            var exeDir = Path.GetDirectoryName(Environment.ProcessPath);
            var licensePath = exeDir != null ? Path.Combine(exeDir, "LICENSE") : null;
            if (licensePath != null && File.Exists(licensePath))
            {
                try { Process.Start(new ProcessStartInfo(licensePath) { UseShellExecute = true }); }
                catch { }
            }
        };
        stack.Children.Add(licenseLink);

        stack.Children.Add(new TextBlock
        {
            Text = "\u00A9 2026 Trowser contributors",
            Foreground = FgText,
            FontSize = 12,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 12)
        });

        var newsletterLink = new TextBlock
        {
            Text = "Add me to newsletter",
            Foreground = AccentClr,
            FontSize = 11,
            HorizontalAlignment = HorizontalAlignment.Center,
            Cursor = Cursors.Hand,
            TextDecorations = TextDecorations.Underline
        };
        newsletterLink.MouseLeftButtonUp += (_, _) =>
        {
            var subject = Uri.EscapeDataString("I want to receive news about Trowser");
            var mailto = $"mailto:rikard.edgren@thetesteye.com?subject={subject}";
            try { Process.Start(new ProcessStartInfo(mailto) { UseShellExecute = true }); }
            catch { }
        };
        stack.Children.Add(newsletterLink);

        Content = stack;
    }

    private static SolidColorBrush Freeze(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }
}
