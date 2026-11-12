using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Markdig;
using Markdig.Extensions.Tables;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;
using MdBlock = Markdig.Syntax.Block;
using MdTable = Markdig.Extensions.Tables.Table;
using MdTableCell = Markdig.Extensions.Tables.TableCell;
using MdTableRow = Markdig.Extensions.Tables.TableRow;
using WpfBlock = System.Windows.Documents.Block;

namespace Trowser.Chat;

/// <summary>
/// Converts Markdown to HTML (for "Show as HTML") and to WPF FlowDocument (for chat bubbles).
/// Raw HTML in Markdown is disabled for safety.
/// </summary>
public static class MarkdownHelper
{
    private static readonly MarkdownPipeline Pipeline = new MarkdownPipelineBuilder()
        .UseAdvancedExtensions()
        .DisableHtml()
        .Build();

    internal const string CodeBoxTag = "ChatCodeBlock";

    private static readonly Brush CodeBackground = FreezeBrush("#1A1A1A");
    private static readonly Brush CodeHeaderBackground = FreezeBrush("#252526");
    private static readonly Brush CodeForeground = FreezeBrush("#DCDCAA");
    private static readonly Brush CodeChromeForeground = FreezeBrush("#9A9A9A");
    private static readonly Brush QuoteBorder = FreezeBrush("#5A5A5A");
    private static readonly Brush LinkForeground = FreezeBrush("#569CD6");
    private static readonly Brush TableBorder = FreezeBrush("#555555");
    private static readonly Brush HeadingForeground = FreezeBrush("#E0E0E0");

    /// <summary>
    /// Renders Markdown to an HTML fragment (no document wrapper). Safe: raw HTML disabled.
    /// </summary>
    public static string ToHtml(string? markdown)
    {
        if (string.IsNullOrEmpty(markdown))
            return "";
        return Markdown.ToHtml(markdown, Pipeline);
    }

    /// <summary>
    /// Builds a FlowDocument suitable for a read-only chat bubble RichTextBox.
    /// </summary>
    public static FlowDocument ToFlowDocument(string? markdown, Brush foreground, double fontSize = 13)
    {
        var doc = new FlowDocument
        {
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = fontSize,
            Foreground = foreground,
            PagePadding = new Thickness(0),
            TextAlignment = TextAlignment.Left
        };

        if (string.IsNullOrWhiteSpace(markdown))
        {
            doc.Blocks.Add(new Paragraph(new Run("")));
            return doc;
        }

        var mdDoc = Markdown.Parse(markdown, Pipeline);
        foreach (var block in mdDoc)
            AddBlock(doc.Blocks, block, foreground, fontSize, 0);

        if (doc.Blocks.Count == 0)
            doc.Blocks.Add(new Paragraph(new Run(markdown)) { Margin = new Thickness(0) });

        return doc;
    }

    /// <summary>
    /// Markdown block at <paramref name="index"/>: fenced code returns the inner code
    /// (including an unclosed fence), otherwise the surrounding paragraph.
    /// </summary>
    public static string GetSegmentAt(string? markdown, int index)
    {
        if (string.IsNullOrEmpty(markdown))
            return "";

        index = Math.Clamp(index, 0, markdown.Length);
        foreach (var fence in FindFences(markdown))
        {
            if (index >= fence.Start && index <= fence.End)
                return TrimCode(markdown[fence.InnerStart..fence.InnerEnd]);
        }

        var start = AfterLastBlankLine(markdown, index);
        var end = NextBlankLine(markdown, index);
        return markdown[start..end].Trim();
    }

    /// <summary>
    /// Splits streamed Markdown so finished blocks (closed fences, earlier paragraphs)
    /// can render while the tail is still growing.
    /// </summary>
    public static (string Complete, string Remainder) SplitCompleteAndRemainder(string? markdown)
    {
        if (string.IsNullOrEmpty(markdown))
            return ("", "");

        var fences = FindFences(markdown);
        if (fences.Count > 0 && !fences[^1].Closed)
        {
            var open = fences[^1];
            return (markdown[..open.Start], markdown[open.Start..]);
        }

        if (fences.Count > 0 && fences[^1].Closed && string.IsNullOrWhiteSpace(markdown[fences[^1].End..]))
            return (markdown, "");

        if (EndsWithBlankLine(markdown))
            return (markdown, "");

        var splitAt = AfterLastBlankLine(markdown, markdown.Length);
        if (fences.Count > 0 && fences[^1].Closed && splitAt < fences[^1].End)
            splitAt = fences[^1].End;

        if (splitAt <= 0)
            return ("", markdown);
        if (splitAt >= markdown.Length)
            return (markdown, "");

        return (markdown[..splitAt], markdown[splitAt..]);
    }

    /// <summary>
    /// Walks a rendered chat document and invokes <paramref name="action"/> for each code box.
    /// </summary>
    public static void ForEachCodeBox(FlowDocument doc, Action<TextBox> action)
    {
        WalkBlocks(doc.Blocks, action);
    }

    private static void AddBlock(BlockCollection blocks, MdBlock block, Brush foreground, double fontSize, int listDepth)
    {
        switch (block)
        {
            case HeadingBlock heading:
                blocks.Add(CreateHeading(heading, foreground, fontSize));
                break;
            case ParagraphBlock para:
                blocks.Add(CreateParagraph(para, foreground, fontSize));
                break;
            case CodeBlock code:
                blocks.Add(CreateCodeBlock(code, fontSize));
                break;
            case QuoteBlock quote:
                blocks.Add(CreateQuote(quote, foreground, fontSize));
                break;
            case ListBlock list:
                blocks.Add(CreateList(list, foreground, fontSize, listDepth));
                break;
            case ThematicBreakBlock:
                blocks.Add(new BlockUIContainer(new System.Windows.Controls.Border
                {
                    Height = 1,
                    Background = QuoteBorder,
                    Margin = new Thickness(0, 8, 0, 8)
                }));
                break;
            case MdTable table:
                blocks.Add(CreateTable(table, foreground, fontSize));
                break;
            case HtmlBlock:
            case LinkReferenceDefinitionGroup:
            case LinkReferenceDefinition:
                // Metadata / disabled HTML — not shown in the chat bubble.
                break;
            default:
                // Unknown extension blocks: skip (ToString is usually just the type name).
                break;
        }
    }

    private static Paragraph CreateHeading(HeadingBlock heading, Brush foreground, double baseFontSize)
    {
        var size = heading.Level switch
        {
            1 => baseFontSize + 6,
            2 => baseFontSize + 4,
            3 => baseFontSize + 2,
            _ => baseFontSize + 1
        };
        var p = new Paragraph
        {
            Margin = new Thickness(0, heading.Level <= 2 ? 10 : 6, 0, 4),
            FontSize = size,
            FontWeight = FontWeights.SemiBold,
            Foreground = HeadingForeground
        };
        AddInlines(p.Inlines, heading.Inline, foreground, size);
        return p;
    }

    private static Paragraph CreateParagraph(ParagraphBlock para, Brush foreground, double fontSize)
    {
        var p = new Paragraph
        {
            Margin = new Thickness(0, 2, 0, 6),
            FontSize = fontSize,
            Foreground = foreground,
            TextAlignment = TextAlignment.Left
        };
        AddInlines(p.Inlines, para.Inline, foreground, fontSize);
        return p;
    }

    private static WpfBlock CreateCodeBlock(CodeBlock code, double fontSize)
    {
        var text = GetCodeBlockText(code);
        var codeBox = new TextBox
        {
            Text = text,
            Tag = CodeBoxTag,
            FontFamily = new FontFamily("Cascadia Code, Consolas, Courier New"),
            FontSize = Math.Max(11, fontSize - 1),
            Foreground = CodeForeground,
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap,
            Padding = new Thickness(10, 8, 10, 10),
            Margin = new Thickness(0),
            IsTabStop = false,
            Cursor = Cursors.IBeam,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            VerticalScrollBarVisibility = ScrollBarVisibility.Disabled
        };

        var stack = new StackPanel();
        stack.Children.Add(CreateCodeHeader(text, GetFenceLanguage(code)));
        stack.Children.Add(codeBox);

        var border = new Border
        {
            Background = CodeBackground,
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(0),
            Margin = new Thickness(0, 4, 0, 8),
            Child = stack
        };

        return new BlockUIContainer(border);
    }

    private static Border CreateCodeHeader(string codeText, string language)
    {
        var copyBtn = new Button
        {
            Content = CopyIcon,
            FontFamily = new FontFamily("Segoe MDL2 Assets"),
            FontSize = 12,
            Width = 22,
            Height = 20,
            Padding = new Thickness(0),
            Background = Brushes.Transparent,
            Foreground = CodeChromeForeground,
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
            ToolTip = "Copy",
            Focusable = false,
            IsTabStop = false,
            VerticalAlignment = VerticalAlignment.Center
        };
        copyBtn.Template = FlatIconButtonTemplate();
        copyBtn.Click += (_, _) =>
        {
            CopyToClipboard(codeText);
            copyBtn.Content = CopiedIcon;
            copyBtn.ToolTip = "Copied";
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                copyBtn.Content = CopyIcon;
                copyBtn.ToolTip = "Copy";
            };
            timer.Start();
        };
        copyBtn.MouseEnter += (_, _) => copyBtn.Foreground = Brushes.White;
        copyBtn.MouseLeave += (_, _) => copyBtn.Foreground = CodeChromeForeground;
        DockPanel.SetDock(copyBtn, Dock.Right);

        var header = new DockPanel { LastChildFill = true };
        header.Children.Add(copyBtn);
        header.Children.Add(new TextBlock
        {
            Text = language,
            FontSize = 10,
            Foreground = CodeChromeForeground,
            VerticalAlignment = VerticalAlignment.Center,
            TextTrimming = TextTrimming.CharacterEllipsis
        });

        return new Border
        {
            Background = CodeHeaderBackground,
            Padding = new Thickness(10, 4, 6, 4),
            CornerRadius = new CornerRadius(4, 4, 0, 0),
            Child = header
        };
    }

    private static Section CreateQuote(QuoteBlock quote, Brush foreground, double fontSize)
    {
        var section = new Section
        {
            BorderBrush = QuoteBorder,
            BorderThickness = new Thickness(3, 0, 0, 0),
            Padding = new Thickness(10, 0, 0, 0),
            Margin = new Thickness(0, 4, 0, 8),
            Foreground = foreground,
            FontStyle = FontStyles.Italic
        };
        foreach (var child in quote)
            AddBlock(section.Blocks, child, foreground, fontSize, 0);
        return section;
    }

    private static List CreateList(ListBlock list, Brush foreground, double fontSize, int depth)
    {
        var wpfList = new List
        {
            MarkerStyle = list.IsOrdered ? TextMarkerStyle.Decimal : TextMarkerStyle.Disc,
            Margin = new Thickness(Math.Min(depth * 8, 24), 2, 0, 6),
            Padding = new Thickness(16, 0, 0, 0),
            Foreground = foreground
        };

        foreach (var item in list)
        {
            if (item is not ListItemBlock listItem) continue;
            var listItemElement = new ListItem();
            foreach (var child in listItem)
            {
                if (child is ListBlock nested)
                    listItemElement.Blocks.Add(CreateList(nested, foreground, fontSize, depth + 1));
                else
                    AddBlock(listItemElement.Blocks, child, foreground, fontSize, depth + 1);
            }
            // Tighten paragraph margins inside list items
            foreach (var b in listItemElement.Blocks)
            {
                if (b is Paragraph p)
                    p.Margin = new Thickness(0, 1, 0, 1);
            }
            wpfList.ListItems.Add(listItemElement);
        }

        return wpfList;
    }

    private static WpfBlock CreateTable(MdTable table, Brush foreground, double fontSize)
    {
        var wpfTable = new System.Windows.Documents.Table
        {
            CellSpacing = 0,
            BorderBrush = TableBorder,
            BorderThickness = new Thickness(1),
            Margin = new Thickness(0, 4, 0, 8),
            Foreground = foreground
        };

        var columnCount = 0;
        foreach (var row in table)
        {
            if (row is MdTableRow mdRow)
                columnCount = Math.Max(columnCount, mdRow.Count);
        }

        for (var i = 0; i < columnCount; i++)
            wpfTable.Columns.Add(new TableColumn());

        var group = new TableRowGroup();
        wpfTable.RowGroups.Add(group);

        foreach (var row in table)
        {
            if (row is not MdTableRow mdRow) continue;
            var wpfRow = new System.Windows.Documents.TableRow();
            var isHeader = mdRow.IsHeader;
            foreach (var cell in mdRow)
            {
                if (cell is not MdTableCell mdCell) continue;
                var wpfCell = new System.Windows.Documents.TableCell
                {
                    BorderBrush = TableBorder,
                    BorderThickness = new Thickness(0.5),
                    Padding = new Thickness(6, 4, 6, 4),
                    FontWeight = isHeader ? FontWeights.SemiBold : FontWeights.Normal
                };
                foreach (var cellBlock in mdCell)
                    AddBlock(wpfCell.Blocks, cellBlock, foreground, fontSize, 0);
                foreach (var b in wpfCell.Blocks)
                {
                    if (b is Paragraph p)
                        p.Margin = new Thickness(0);
                }
                wpfRow.Cells.Add(wpfCell);
            }
            group.Rows.Add(wpfRow);
        }

        return wpfTable;
    }

    private static void AddInlines(InlineCollection inlines, ContainerInline? container, Brush foreground, double fontSize)
    {
        if (container == null) return;
        for (var inline = container.FirstChild; inline != null; inline = inline.NextSibling)
            AddInline(inlines, inline, foreground, fontSize);
    }

    private static void AddInline(InlineCollection inlines, Markdig.Syntax.Inlines.Inline inline, Brush foreground, double fontSize)
    {
        switch (inline)
        {
            case LiteralInline lit:
                inlines.Add(new Run(lit.Content.ToString()) { Foreground = foreground });
                break;
            case CodeInline code:
                inlines.Add(new Run(code.Content)
                {
                    FontFamily = new FontFamily("Cascadia Code, Consolas, Courier New"),
                    FontSize = Math.Max(11, fontSize - 1),
                    Foreground = CodeForeground,
                    Background = CodeBackground
                });
                break;
            case EmphasisInline emphasis:
                var span = new Span { Foreground = foreground };
                if (emphasis.DelimiterCount >= 2)
                    span.FontWeight = FontWeights.Bold;
                else
                    span.FontStyle = FontStyles.Italic;
                AddInlines(span.Inlines, emphasis, foreground, fontSize);
                inlines.Add(span);
                break;
            case LinkInline link when !link.IsImage:
                var hyper = new Hyperlink
                {
                    NavigateUri = TryCreateUri(link.Url),
                    Foreground = LinkForeground,
                    TextDecorations = TextDecorations.Underline,
                    ToolTip = link.Url
                };
                AddInlines(hyper.Inlines, link, LinkForeground, fontSize);
                if (hyper.Inlines.Count == 0 && !string.IsNullOrEmpty(link.Url))
                    hyper.Inlines.Add(new Run(link.Url));
                if (hyper.NavigateUri != null)
                {
                    hyper.RequestNavigate += (_, e) =>
                    {
                        try
                        {
                            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
                        }
                        catch { /* ignore */ }
                        e.Handled = true;
                    };
                }
                inlines.Add(hyper);
                break;
            case LinkInline image when image.IsImage:
                var alt = GetInlinePlainText(image);
                inlines.Add(new Run(string.IsNullOrEmpty(alt) ? "[image]" : $"[{alt}]")
                {
                    FontStyle = FontStyles.Italic,
                    Foreground = foreground
                });
                break;
            case LineBreakInline br:
                inlines.Add(br.IsHard ? new LineBreak() : new Run(" "));
                break;
            case HtmlEntityInline entity:
                inlines.Add(new Run(entity.Transcoded.ToString()) { Foreground = foreground });
                break;
            case ContainerInline nested:
                AddInlines(inlines, nested, foreground, fontSize);
                break;
            default:
                // Skip unknown inlines (ToString is often just the type name).
                break;
        }
    }

    private const string CopyIcon = "\uE8C8";
    private const string CopiedIcon = "\uE73E";

    private static ControlTemplate FlatIconButtonTemplate()
    {
        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        presenter.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        presenter.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        return new ControlTemplate(typeof(Button)) { VisualTree = presenter };
    }

    private static string GetCodeBlockText(CodeBlock code)
    {
        if (code is FencedCodeBlock fenced)
            return TrimCode(fenced.Lines.ToString());
        return TrimCode(code.Lines.ToString());
    }

    private static string GetFenceLanguage(CodeBlock code)
    {
        if (code is not FencedCodeBlock fenced || string.IsNullOrWhiteSpace(fenced.Info))
            return "";
        var info = fenced.Info.Trim();
        var space = info.IndexOfAny([' ', '\t']);
        return space < 0 ? info : info[..space];
    }

    private static void CopyToClipboard(string text)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch
        {
            /* clipboard locked by another process */
        }
    }

    private static void WalkBlocks(BlockCollection blocks, Action<TextBox> action)
    {
        foreach (var block in blocks)
        {
            switch (block)
            {
                case BlockUIContainer ui:
                    if (FindCodeBox(ui.Child) is { } tb)
                        action(tb);
                    break;
                case Section section:
                    WalkBlocks(section.Blocks, action);
                    break;
                case List list:
                    foreach (var item in list.ListItems)
                        WalkBlocks(item.Blocks, action);
                    break;
                case System.Windows.Documents.Table table:
                    foreach (var group in table.RowGroups)
                    {
                        foreach (var row in group.Rows)
                        {
                            foreach (var cell in row.Cells)
                                WalkBlocks(cell.Blocks, action);
                        }
                    }
                    break;
            }
        }
    }

    private static TextBox? FindCodeBox(DependencyObject? root)
    {
        switch (root)
        {
            case TextBox tb when Equals(tb.Tag, CodeBoxTag):
                return tb;
            case Decorator decorator:
                return FindCodeBox(decorator.Child);
            case Panel panel:
                foreach (UIElement child in panel.Children)
                {
                    var found = FindCodeBox(child);
                    if (found != null) return found;
                }
                return null;
            case ContentControl content:
                return FindCodeBox(content.Content as DependencyObject);
            default:
                return null;
        }
    }

    private readonly record struct FenceSpan(int Start, int End, int InnerStart, int InnerEnd, bool Closed);

    private static List<FenceSpan> FindFences(string text)
    {
        var fences = new List<FenceSpan>();
        var inFence = false;
        var fenceChar = '\0';
        var fenceLen = 0;
        var openStart = 0;
        var innerStart = 0;
        var lineStart = 0;

        for (var i = 0; i <= text.Length; i++)
        {
            if (i != text.Length && text[i] != '\n')
                continue;

            var line = text.AsSpan(lineStart, i - lineStart).TrimEnd('\r');
            var trimmed = line.TrimStart();

            if (!inFence)
            {
                if (TryParseOpeningFence(trimmed, out fenceChar, out fenceLen))
                {
                    inFence = true;
                    openStart = lineStart;
                    innerStart = i < text.Length ? i + 1 : text.Length;
                }
            }
            else if (IsClosingFence(trimmed, fenceChar, fenceLen))
            {
                var end = i < text.Length ? i + 1 : text.Length;
                fences.Add(new FenceSpan(openStart, end, innerStart, lineStart, true));
                inFence = false;
            }

            if (i == text.Length)
                break;
            lineStart = i + 1;
        }

        if (inFence)
            fences.Add(new FenceSpan(openStart, text.Length, innerStart, text.Length, false));

        return fences;
    }

    private static bool TryParseOpeningFence(ReadOnlySpan<char> trimmed, out char fenceChar, out int fenceLen)
    {
        fenceChar = '\0';
        fenceLen = 0;
        if (trimmed.Length < 3)
            return false;
        var ch = trimmed[0];
        if (ch != '`' && ch != '~')
            return false;
        var n = 0;
        while (n < trimmed.Length && trimmed[n] == ch)
            n++;
        if (n < 3)
            return false;
        fenceChar = ch;
        fenceLen = n;
        return true;
    }

    private static bool IsClosingFence(ReadOnlySpan<char> trimmed, char fenceChar, int fenceLen)
    {
        if (trimmed.Length < fenceLen || trimmed[0] != fenceChar)
            return false;
        var n = 0;
        while (n < trimmed.Length && trimmed[n] == fenceChar)
            n++;
        if (n < fenceLen)
            return false;
        for (var i = n; i < trimmed.Length; i++)
        {
            if (!char.IsWhiteSpace(trimmed[i]))
                return false;
        }
        return true;
    }

    private static int AfterLastBlankLine(string text, int before)
    {
        var from = Math.Min(Math.Max(before, 0), text.Length);
        var crlf = text.LastIndexOf("\r\n\r\n", from == 0 ? 0 : from - 1, StringComparison.Ordinal);
        var lf = text.LastIndexOf("\n\n", from == 0 ? 0 : from - 1, StringComparison.Ordinal);
        if (crlf < 0 && lf < 0)
            return 0;
        return crlf > lf ? crlf + 4 : lf + 2;
    }

    private static int NextBlankLine(string text, int from)
    {
        from = Math.Clamp(from, 0, text.Length);
        var crlf = text.IndexOf("\r\n\r\n", from, StringComparison.Ordinal);
        var lf = text.IndexOf("\n\n", from, StringComparison.Ordinal);
        if (crlf < 0 && lf < 0)
            return text.Length;
        if (crlf < 0) return lf;
        if (lf < 0) return crlf;
        return Math.Min(crlf, lf);
    }

    private static bool EndsWithBlankLine(string text) =>
        text.EndsWith("\n\n", StringComparison.Ordinal) ||
        text.EndsWith("\r\n\r\n", StringComparison.Ordinal);

    private static string TrimCode(string text) => text.TrimEnd('\r', '\n');

    private static string GetInlinePlainText(ContainerInline container)
    {
        var sb = new System.Text.StringBuilder();
        for (var inline = container.FirstChild; inline != null; inline = inline.NextSibling)
        {
            if (inline is LiteralInline lit)
                sb.Append(lit.Content);
            else if (inline is ContainerInline nested)
                sb.Append(GetInlinePlainText(nested));
        }
        return sb.ToString();
    }

    private static Uri? TryCreateUri(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeMailto))
            return uri;
        return null;
    }

    private static SolidColorBrush FreezeBrush(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }
}
