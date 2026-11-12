using System.Net;
using System.Net.Http;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Trowser.Automation;

namespace Trowser;

/// <summary>
/// Pop-up when a network breakpoint fires: edit the intercepted request, then optionally edit the
/// server response before it reaches the browser.
/// </summary>
public class BreakpointHitDialog : Window
{
    private readonly PendingRequest _pending;
    private bool _resolved;

    // Request phase
    private readonly StackPanel _requestSection;
    private readonly TextBox _methodBox;
    private readonly TextBox _urlBox;
    private readonly TextBox _requestHeadersBox;
    private readonly TextBox _requestBodyBox;
    private readonly StackPanel _requestButtons;

    // Replay section
    private readonly TextBox _concurrencyBox;
    private readonly TextBlock _replayResultText;
    private const int MaxConcurrentRequests = 50;

    // Summary shown in response phase
    private readonly TextBlock _requestSummary;

    // Response phase
    private readonly TextBlock _loadingText;
    private readonly StackPanel _responseSection;
    private readonly TextBox _statusBox;
    private readonly TextBox _responseHeadersBox;
    private readonly TextBox _responseBodyBox;
    private readonly StackPanel _responseButtons;
    private readonly TextBlock _streamHint;
    private readonly StackPanel _streamReadButtons;
    private readonly Button _readMoreBtn;

    private BreakpointForwardStreamSession? _streamSession;

    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush BgInput = Bc("#1E1E1E");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentGreen = Bc("#4EC9B0");
    private static readonly SolidColorBrush AccentBlue = Bc("#569CD6");
    private static readonly SolidColorBrush AccentYellow = Bc("#CCA700");
    private static readonly SolidColorBrush AccentRed = Bc("#F44747");
    private static readonly SolidColorBrush AccentOrange = Bc("#CE9178");

    public BreakpointHitDialog(PendingRequest pending, Window owner)
    {
        _pending = pending;
        Owner = owner;

        var shortUrl = pending.Url.Length > 60 ? pending.Url[..60] + "\u2026" : pending.Url;
        Title = $"Breakpoint \u2014 {pending.Method} {shortUrl}";
        Width = 720;
        Height = 620;
        MinWidth = 520;
        MinHeight = 400;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResizeWithGrip;
        Background = BgMedium;
        Topmost = true;
        ShowInTaskbar = false;

        var scroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
        };

        var root = new StackPanel { Margin = new Thickness(20, 16, 20, 20) };

        // ─── Banner ───
        var banner = new Border
        {
            Background = Bc("#2A2A2D"),
            BorderBrush = AccentYellow,
            BorderThickness = new Thickness(0, 0, 0, 2),
            Padding = new Thickness(12, 8, 12, 8),
            Margin = new Thickness(0, 0, 0, 14)
        };
        banner.Child = new TextBlock
        {
            Text = $"\u26A1 Breakpoint: /{pending.MatchedPattern}/   Type: {pending.ResourceType}   {pending.Timestamp.ToLocalTime():HH:mm:ss}",
            Foreground = AccentYellow,
            FontSize = 12,
            FontFamily = new FontFamily("Consolas"),
            TextWrapping = TextWrapping.Wrap
        };
        root.Children.Add(banner);

        // ─── Request section ───
        _requestSection = new StackPanel();
        AddSectionLabel(_requestSection, "REQUEST");

        var urlRow = new Grid { Margin = new Thickness(0, 6, 0, 0) };
        urlRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(76) });
        urlRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        _methodBox = CreateInputBox(pending.Method, 70);
        Grid.SetColumn(_methodBox, 0);
        urlRow.Children.Add(_methodBox);

        _urlBox = CreateInputBox(pending.Url);
        _urlBox.Margin = new Thickness(4, 0, 0, 0);
        Grid.SetColumn(_urlBox, 1);
        urlRow.Children.Add(_urlBox);
        _requestSection.Children.Add(urlRow);

        var urlLabels = new Grid { Margin = new Thickness(0, 1, 0, 0) };
        urlLabels.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(76) });
        urlLabels.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        AddMicroLabel(urlLabels, "Method", 0);
        AddMicroLabel(urlLabels, "URL", 1, new Thickness(4, 0, 0, 0));
        _requestSection.Children.Add(urlLabels);

        AddFieldLabel(_requestSection, "Headers");
        _requestHeadersBox = CreateMultilineBox(FormatHeaders(pending.Headers), 5);
        _requestSection.Children.Add(_requestHeadersBox);

        AddFieldLabel(_requestSection, "Body");
        _requestBodyBox = CreateMultilineBox(pending.Body ?? "", 4);
        _requestSection.Children.Add(_requestBodyBox);

        root.Children.Add(_requestSection);

        // ─── Request buttons ───
        _requestButtons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(0, 12, 0, 0)
        };

        var forwardBtn = CreateActionButton("Forward \u25B6", AccentGreen,
            "Send request to server (with edits). Response goes straight to browser.");
        forwardBtn.Click += Forward_Click;
        _requestButtons.Children.Add(forwardBtn);

        var forwardEditBtn = CreateActionButton("Forward & Edit Response", AccentBlue,
            "Send to server, then inspect/edit the response before it reaches the browser.");
        forwardEditBtn.Margin = new Thickness(8, 0, 0, 0);
        forwardEditBtn.Click += ForwardAndEditResponse_Click;
        _requestButtons.Children.Add(forwardEditBtn);

        var abortBtn = CreateActionButton("Abort", AccentRed, "Block this request.");
        abortBtn.Margin = new Thickness(8, 0, 0, 0);
        abortBtn.Click += Abort_Click;
        _requestButtons.Children.Add(abortBtn);

        // Replay separator and controls
        var replaySep = new TextBlock
        {
            Text = "\u2502",
            Foreground = FgDim,
            FontSize = 16,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 0, 4, 0)
        };
        _requestButtons.Children.Add(replaySep);

        var replayLabel = new TextBlock
        {
            Text = "\u00D7",
            Foreground = FgText,
            FontSize = 12,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 2, 0)
        };
        _requestButtons.Children.Add(replayLabel);

        _concurrencyBox = new TextBox
        {
            Text = "10",
            Width = 36,
            Height = 26,
            Background = BgInput,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(4, 0, 4, 0),
            FontSize = 12,
            FontFamily = new FontFamily("Consolas"),
            TextAlignment = TextAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            VerticalContentAlignment = VerticalAlignment.Center,
            ToolTip = "Number of concurrent requests (1\u201350)"
        };
        CenterTextVertically(_concurrencyBox);
        _requestButtons.Children.Add(_concurrencyBox);

        var replayBtn = CreateActionButton("Replay", AccentOrange,
            "Fire this request N times concurrently (load test). The original request stays held.");
        replayBtn.Margin = new Thickness(4, 0, 0, 0);
        replayBtn.Click += Replay_Click;
        _requestButtons.Children.Add(replayBtn);

        root.Children.Add(_requestButtons);

        // ─── Replay results (initially hidden) ───
        _replayResultText = new TextBlock
        {
            Foreground = FgText,
            FontSize = 11,
            FontFamily = new FontFamily("Consolas"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0),
            Visibility = Visibility.Collapsed
        };
        root.Children.Add(_replayResultText);

        // ─── Request summary (shown in response phase) ───
        _requestSummary = new TextBlock
        {
            Foreground = FgDim,
            FontSize = 11,
            FontFamily = new FontFamily("Consolas"),
            Margin = new Thickness(0, 0, 0, 8),
            Visibility = Visibility.Collapsed
        };
        root.Children.Add(_requestSummary);

        // ─── Loading ───
        _loadingText = new TextBlock
        {
            Text = "\u23F3 Sending request to server\u2026",
            Foreground = AccentBlue,
            FontSize = 12,
            Margin = new Thickness(0, 12, 0, 0),
            Visibility = Visibility.Collapsed
        };
        root.Children.Add(_loadingText);

        // ─── Response section (initially hidden) ───
        _responseSection = new StackPanel { Visibility = Visibility.Collapsed };
        AddSectionLabel(_responseSection, "RESPONSE");

        var statusRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(0, 6, 0, 0)
        };
        statusRow.Children.Add(new TextBlock
        {
            Text = "Status:",
            Foreground = FgText,
            FontSize = 12,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 6, 0)
        });
        _statusBox = CreateInputBox("200", 80);
        statusRow.Children.Add(_statusBox);
        _responseSection.Children.Add(statusRow);

        AddFieldLabel(_responseSection, "Headers");
        _responseHeadersBox = CreateMultilineBox("", 4);
        _responseSection.Children.Add(_responseHeadersBox);

        AddFieldLabel(_responseSection, "Body");
        _responseBodyBox = CreateMultilineBox("", 8);
        _responseSection.Children.Add(_responseBodyBox);

        root.Children.Add(_responseSection);

        _streamHint = new TextBlock
        {
            Foreground = AccentYellow,
            FontSize = 11,
            FontFamily = new FontFamily("Consolas"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0),
            Visibility = Visibility.Collapsed
        };
        root.Children.Add(_streamHint);

        _streamReadButtons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(0, 8, 0, 0),
            Visibility = Visibility.Collapsed
        };

        _readMoreBtn = CreateActionButton("Read more from server", AccentBlue,
            "Append the next chunk from the live event stream into the body editor.");
        _readMoreBtn.Click += ReadMoreStream_Click;
        _streamReadButtons.Children.Add(_readMoreBtn);

        var doneSamplingBtn = CreateActionButton("Done sampling", AccentGreen,
            "Stop reading from the server. Edit the captured text, then Send to Browser.");
        doneSamplingBtn.Margin = new Thickness(8, 0, 0, 0);
        doneSamplingBtn.Click += DoneSampling_Click;
        _streamReadButtons.Children.Add(doneSamplingBtn);

        root.Children.Add(_streamReadButtons);

        // ─── Response buttons (initially hidden) ───
        _responseButtons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(0, 12, 0, 0),
            Visibility = Visibility.Collapsed
        };

        var sendBtn = CreateActionButton("Send to Browser \u25B6", AccentGreen,
            "Forward this response (with edits) to the browser.");
        sendBtn.Click += SendToBrowser_Click;
        _responseButtons.Children.Add(sendBtn);

        var dropBtn = CreateActionButton("Abort", AccentRed, "Drop the response and abort the request.");
        dropBtn.Margin = new Thickness(8, 0, 0, 0);
        dropBtn.Click += Abort_Click;
        _responseButtons.Children.Add(dropBtn);

        root.Children.Add(_responseButtons);

        scroll.Content = root;
        Content = scroll;
        Closed += (_, _) => EndStreamSession();
    }

    // ─────────────────── Actions ───────────────────

    private void Forward_Click(object sender, RoutedEventArgs e)
    {
        if (_resolved || _pending.IsResolved) { Close(); return; }
        _resolved = true;

        var decision = new InterceptDecision
        {
            Action = InterceptAction.Continue,
            ModifiedUrl = TextChanged(_urlBox, _pending.Url) ? _urlBox.Text.Trim() : null,
            ModifiedMethod = TextChanged(_methodBox, _pending.Method) ? _methodBox.Text.Trim() : null,
            ModifiedHeaders = HeadersChanged() ? ParseHeaders(_requestHeadersBox.Text) : null,
            ModifiedBody = BodyChanged() ? _requestBodyBox.Text : null
        };

        _pending.Resolve(decision);
        Close();
    }

    private async void ForwardAndEditResponse_Click(object sender, RoutedEventArgs e)
    {
        if (_resolved || _pending.IsResolved) { Close(); return; }

        _requestSection.Visibility = Visibility.Collapsed;
        _requestButtons.Visibility = Visibility.Collapsed;
        _requestSummary.Text = $"\u25B6 {_methodBox.Text.Trim()} {_urlBox.Text.Trim()}";
        _requestSummary.Visibility = Visibility.Visible;
        _loadingText.Visibility = Visibility.Visible;
        HideStreamSamplingUi();

        try
        {
            EndStreamSession();

            var headerDict = ParseHeaders(_requestHeadersBox.Text);
            using var request = BreakpointForwardHttp.BuildRequest(
                _urlBox.Text,
                _methodBox.Text,
                headerDict,
                _requestBodyBox.Text);

            var session = await BreakpointForwardHttp.OpenStreamSessionAsync(request);
            var isEventStream = BreakpointForwardHttp.ResponseLooksLikeEventStream(session.Response);

            if (!isEventStream)
            {
                var body = new StringBuilder();
                await session.ReadSliceAsync(
                    body,
                    NetworkCaptureLimits.MaxTextBodyChars,
                    BreakpointForwardHttp.StandardTimeoutSeconds * 1000);
                var status = session.StatusCode;
                var headers = session.ResponseHeaders;
                await session.DisposeAsync();

                ShowForwardedResponse(status, headers, body.ToString());
                return;
            }

            _streamSession = session;
            var sample = new StringBuilder();
            await _streamSession.ReadSliceAsync(
                sample,
                NetworkCaptureLimits.MaxEventStreamBodyChars,
                BreakpointForwardHttp.InitialStreamSliceMs);

            _statusBox.Text = _streamSession.StatusCode.ToString();
            _responseHeadersBox.Text = FormatHeaders(_streamSession.ResponseHeaders);
            _responseBodyBox.Text = sample.ToString();
            _loadingText.Visibility = Visibility.Collapsed;
            _responseSection.Visibility = Visibility.Visible;
            _responseButtons.Visibility = Visibility.Visible;
            ShowStreamSamplingUi();
            UpdateStreamSamplingControls(_streamSession.StreamEnded, _streamSession.HitCharCap);
        }
        catch (Exception ex)
        {
            EndStreamSession();
            _loadingText.Visibility = Visibility.Collapsed;
            _statusBox.Text = "502";
            _responseHeadersBox.Text = "";
            _responseBodyBox.Text = $"Error forwarding request:\n{ex.Message}";
            _responseSection.Visibility = Visibility.Visible;
            _responseButtons.Visibility = Visibility.Visible;
        }
    }

    private async void ReadMoreStream_Click(object sender, RoutedEventArgs e)
    {
        if (_streamSession == null) return;

        _readMoreBtn.IsEnabled = false;
        try
        {
            var sample = new StringBuilder(_responseBodyBox.Text);
            await _streamSession.ReadSliceAsync(
                sample,
                NetworkCaptureLimits.MaxEventStreamBodyChars,
                BreakpointForwardHttp.StreamSliceMs);
            _responseBodyBox.Text = sample.ToString();
            UpdateStreamSamplingControls(_streamSession.StreamEnded, _streamSession.HitCharCap);
        }
        catch (Exception ex)
        {
            _streamHint.Text = $"Read failed: {ex.Message}";
            _streamHint.Visibility = Visibility.Visible;
        }
        finally
        {
            if (_streamSession is { StreamEnded: false, HitCharCap: false })
                _readMoreBtn.IsEnabled = true;
        }
    }

    private void DoneSampling_Click(object sender, RoutedEventArgs e)
    {
        EndStreamSession();
        HideStreamSamplingUi();
        _streamHint.Text = "Sampling stopped. Edit the body, then Send to Browser.";
        _streamHint.Visibility = Visibility.Visible;
    }

    private void ShowForwardedResponse(int status, Dictionary<string, string> headers, string body)
    {
        _loadingText.Visibility = Visibility.Collapsed;
        _statusBox.Text = status.ToString();
        _responseHeadersBox.Text = FormatHeaders(headers);
        _responseBodyBox.Text = body;
        _responseSection.Visibility = Visibility.Visible;
        _responseButtons.Visibility = Visibility.Visible;
    }

    private void ShowStreamSamplingUi()
    {
        _streamHint.Text =
            "Event stream: sample below (not the live browser connection). "
            + "Read more to grow the sample, paste to extend it, or Done sampling — Send to Browser uses the full editor text, not the network log cap.";
        _streamHint.Visibility = Visibility.Visible;
        _streamReadButtons.Visibility = Visibility.Visible;
    }

    private void HideStreamSamplingUi()
    {
        _streamHint.Visibility = Visibility.Collapsed;
        _streamReadButtons.Visibility = Visibility.Collapsed;
    }

    private void UpdateStreamSamplingControls(bool streamEnded, bool hitCharCap)
    {
        if (hitCharCap)
        {
            _streamHint.Text =
                $"Sample reached {NetworkCaptureLimits.MaxEventStreamBodyChars:N0} characters. "
                + "Edit or Send to Browser; Read more is disabled.";
            _readMoreBtn.IsEnabled = false;
            return;
        }

        if (streamEnded)
        {
            _streamHint.Text = "Server closed the stream. Edit the body, then Send to Browser.";
            _readMoreBtn.IsEnabled = false;
            EndStreamSession();
            _streamReadButtons.Visibility = Visibility.Collapsed;
            return;
        }

        _streamHint.Text =
            "Event stream still open upstream. Read more to append, or Done sampling when ready to edit.";
        _readMoreBtn.IsEnabled = true;
    }

    private void EndStreamSession()
    {
        if (_streamSession == null) return;
        _streamSession.DisposeAsync().AsTask().GetAwaiter().GetResult();
        _streamSession = null;
    }

    private void SendToBrowser_Click(object sender, RoutedEventArgs e)
    {
        if (_resolved || _pending.IsResolved) { Close(); return; }
        _resolved = true;
        EndStreamSession();

        int.TryParse(_statusBox.Text.Trim(), out var status);
        if (status <= 0) status = 200;

        _pending.Resolve(new InterceptDecision
        {
            Action = InterceptAction.Fulfill,
            StatusCode = status,
            Body = _responseBodyBox.Text,
            ResponseHeaders = ParseHeaders(_responseHeadersBox.Text)
        });
        Close();
    }

    private void Abort_Click(object sender, RoutedEventArgs e)
    {
        if (_resolved || _pending.IsResolved) { Close(); return; }
        _resolved = true;
        EndStreamSession();

        _pending.Resolve(new InterceptDecision { Action = InterceptAction.Abort });
        Close();
    }

    private async void Replay_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(_concurrencyBox.Text.Trim(), out var concurrency) || concurrency < 1)
            concurrency = 1;
        concurrency = Math.Min(concurrency, MaxConcurrentRequests);

        _replayResultText.Text = $"\u23F3 Replaying {concurrency} concurrent requests\u2026";
        _replayResultText.Foreground = AccentBlue;
        _replayResultText.Visibility = Visibility.Visible;

        try
        {
            var url = _urlBox.Text.Trim();
            var method = _methodBox.Text.Trim();
            var headerDict = ParseHeaders(_requestHeadersBox.Text);
            var body = _requestBodyBox.Text;
            if (string.IsNullOrEmpty(body)) body = null;

            using var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.All,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                AllowAutoRedirect = false,
                MaxConnectionsPerServer = concurrency
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

            var skipHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Host", "Content-Length", "Transfer-Encoding", "Connection", "Content-Type"
            };
            string? contentType = null;
            if (headerDict.TryGetValue("Content-Type", out var ct)) contentType = ct;

            var sw = System.Diagnostics.Stopwatch.StartNew();

            var tasks = Enumerable.Range(0, concurrency).Select(async i =>
            {
                var reqSw = System.Diagnostics.Stopwatch.StartNew();
                try
                {
                    var msg = new HttpRequestMessage(new HttpMethod(method), url);
                    foreach (var kv in headerDict)
                    {
                        if (skipHeaders.Contains(kv.Key)) continue;
                        msg.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
                    }
                    if (body != null)
                    {
                        msg.Content = new StringContent(body, Encoding.UTF8);
                        if (contentType != null)
                        {
                            try { msg.Content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(contentType); }
                            catch { /* keep default */ }
                        }
                    }
                    var resp = await client.SendAsync(msg);
                    reqSw.Stop();
                    return (status: (int)resp.StatusCode, ms: (int)reqSw.ElapsedMilliseconds, error: (string?)null);
                }
                catch (Exception ex)
                {
                    reqSw.Stop();
                    return (status: 0, ms: (int)reqSw.ElapsedMilliseconds, error: ex.Message);
                }
            });

            var results = await Task.WhenAll(tasks);
            sw.Stop();

            var timings = results.Where(r => r.status > 0).Select(r => r.ms).OrderBy(t => t).ToArray();
            var statusGroups = results.GroupBy(r => r.status)
                .Select(g => $"{g.Key}: {g.Count()}")
                .ToList();
            var errorCount = results.Count(r => r.error != null);

            var sb = new StringBuilder();
            sb.AppendLine($"\u2705 Replay complete — {concurrency} requests in {sw.ElapsedMilliseconds}ms");
            sb.AppendLine($"Status codes: {string.Join(", ", statusGroups)}");
            if (timings.Length > 0)
            {
                sb.AppendLine($"Timing: avg={timings.Average():F0}ms  min={timings.First()}ms  max={timings.Last()}ms  p95={timings[(int)(timings.Length * 0.95)]}ms");
            }
            if (errorCount > 0)
                sb.AppendLine($"Errors: {errorCount}");

            _replayResultText.Text = sb.ToString().TrimEnd();
            _replayResultText.Foreground = errorCount > 0 ? AccentYellow : AccentGreen;
        }
        catch (Exception ex)
        {
            _replayResultText.Text = $"\u274C Replay failed: {ex.Message}";
            _replayResultText.Foreground = AccentRed;
        }
    }

    // ─────────────────── Header / diff helpers ───────────────────

    private static string FormatHeaders(Dictionary<string, string> headers)
    {
        var sb = new StringBuilder();
        foreach (var kv in headers)
            sb.AppendLine($"{kv.Key}: {kv.Value}");
        return sb.ToString().TrimEnd();
    }

    private static Dictionary<string, string> ParseHeaders(string text)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            var colon = trimmed.IndexOf(':');
            if (colon > 0)
                dict[trimmed[..colon].Trim()] = trimmed[(colon + 1)..].Trim();
        }
        return dict;
    }

    private static bool TextChanged(TextBox box, string original)
        => !string.Equals(box.Text.Trim(), original, StringComparison.Ordinal);

    private bool HeadersChanged()
    {
        var edited = ParseHeaders(_requestHeadersBox.Text);
        if (edited.Count != _pending.Headers.Count) return true;
        foreach (var kv in edited)
        {
            if (!_pending.Headers.TryGetValue(kv.Key, out var orig) || orig != kv.Value)
                return true;
        }
        return false;
    }

    private bool BodyChanged()
        => !string.Equals(_requestBodyBox.Text, _pending.Body ?? "", StringComparison.Ordinal);

    // ─────────────────── UI factory ───────────────────

    private static void AddSectionLabel(StackPanel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = AccentOrange,
            FontSize = 11,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 4, 0, 0)
        });
    }

    private static void AddFieldLabel(StackPanel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 8, 0, 2)
        });
    }

    private static void AddMicroLabel(Grid grid, string text, int col, Thickness? margin = null)
    {
        var tb = new TextBlock
        {
            Text = text,
            Foreground = FgDim,
            FontSize = 9,
            Margin = margin ?? new Thickness(0)
        };
        Grid.SetColumn(tb, col);
        grid.Children.Add(tb);
    }

    /// <summary>
    /// The text host sits at the top of a fixed-height box. Center it so the digits
    /// are vertically centered, not only horizontally.
    /// </summary>
    private static void CenterTextVertically(TextBox box)
    {
        box.VerticalContentAlignment = VerticalAlignment.Center;
        box.Loaded += (_, _) =>
        {
            box.ApplyTemplate();
            if (box.Template?.FindName("PART_ContentHost", box) is FrameworkElement host)
                host.VerticalAlignment = VerticalAlignment.Center;
        };
    }

    private static TextBox CreateInputBox(string value, double width = double.NaN)
    {
        var tb = new TextBox
        {
            Text = value,
            Background = BgInput,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(6, 3, 6, 3),
            FontSize = 12,
            FontFamily = new FontFamily("Consolas"),
            Height = 26
        };
        if (!double.IsNaN(width))
        {
            tb.Width = width;
            tb.HorizontalAlignment = HorizontalAlignment.Left;
        }
        return tb;
    }

    private static TextBox CreateMultilineBox(string value, int minLines)
    {
        return new TextBox
        {
            Text = value,
            Background = BgInput,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(6, 4, 6, 4),
            FontSize = 12,
            FontFamily = new FontFamily("Consolas"),
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            MinLines = minLines,
            MaxLines = 40
        };
    }

    private static Button CreateActionButton(string text, SolidColorBrush bg, string tooltip)
    {
        return new Button
        {
            Content = text,
            Height = 28,
            Padding = new Thickness(14, 0, 14, 0),
            Background = bg,
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand,
            ToolTip = tooltip
        };
    }

    private static SolidColorBrush Bc(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }
}
