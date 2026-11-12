using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.TextExtraction;

/// <summary>
/// Extracts structured text content from the current page for proofreading workflows.
/// Returns headings, paragraphs, link texts, button labels, form labels, image alt texts,
/// meta description, language, word count, and full concatenated text.
/// </summary>
public class StructuredTextExtractor
{
    private readonly WebView2 _webView;

    public StructuredTextExtractor(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Extract structured text from the current page.
    /// </summary>
    public async Task<StructuredTextResult> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var script = BuildExtractionScript();
        var json = await WebViewUiScript.RunAsync(_webView, script, cancellationToken,
            operationLabel: "Structured text extraction");

        if (string.IsNullOrEmpty(json))
        {
            throw new InvalidOperationException("Structured text extraction returned no data.");
        }

        return ParseResults(json);
    }

    #region Extraction JavaScript

    private static string BuildExtractionScript()
    {
        return @"
(function() {
    try {
        var result = {};

        // URL, title, language
        result.url = location.href;
        result.title = document.title || '';
        result.language = document.documentElement.getAttribute('lang') || null;

        // Meta description
        var metaDesc = document.querySelector('meta[name=""description""]');
        result.metaDescription = metaDesc ? metaDesc.getAttribute('content') : null;

        // Headings
        result.headings = [];
        var headingEls = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
        for (var i = 0; i < headingEls.length; i++) {
            var h = headingEls[i];
            var text = (h.innerText || '').trim();
            if (text) {
                result.headings.push({
                    level: parseInt(h.tagName.substring(1)),
                    text: text
                });
            }
        }

        // Paragraphs
        result.paragraphs = [];
        var paragraphs = document.querySelectorAll('p');
        for (var i = 0; i < paragraphs.length; i++) {
            var text = (paragraphs[i].innerText || '').trim();
            if (text) result.paragraphs.push(text);
        }

        // Links
        result.links = [];
        var anchors = document.querySelectorAll('a[href]');
        for (var i = 0; i < anchors.length; i++) {
            var a = anchors[i];
            var text = (a.innerText || '').trim();
            result.links.push({
                text: text,
                url: a.href
            });
        }

        // Buttons
        result.buttons = [];
        var buttons = document.querySelectorAll('button, input[type=""submit""], input[type=""button""], [role=""button""]');
        for (var i = 0; i < buttons.length; i++) {
            var btn = buttons[i];
            var text = (btn.innerText || btn.value || btn.getAttribute('aria-label') || '').trim();
            if (text) result.buttons.push(text);
        }

        // Labels
        result.labels = [];
        var labels = document.querySelectorAll('label');
        for (var i = 0; i < labels.length; i++) {
            var text = (labels[i].innerText || '').trim();
            if (text) result.labels.push(text);
        }

        // Images
        result.images = [];
        var images = document.querySelectorAll('img');
        for (var i = 0; i < images.length; i++) {
            result.images.push({
                alt: images[i].getAttribute('alt') || '',
                src: images[i].src || ''
            });
        }

        // All visible text and word count
        result.allText = (document.body.innerText || '').trim();
        result.wordCount = result.allText ? result.allText.split(/\s+/).filter(function(w) { return w.length > 0; }).length : 0;

        return JSON.stringify(result);
    } catch(e) {
        return JSON.stringify({ error: e.message || String(e) });
    }
})()";
    }

    #endregion

    #region Result Parsing

    private static StructuredTextResult ParseResults(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("error", out var errorProp))
        {
            throw new InvalidOperationException($"Text extraction error: {errorProp.GetString()}");
        }

        var headings = new List<PageHeading>();
        if (root.TryGetProperty("headings", out var hArray))
        {
            foreach (var h in hArray.EnumerateArray())
            {
                headings.Add(new PageHeading
                {
                    Level = h.TryGetProperty("level", out var lvl) ? lvl.GetInt32() : 1,
                    Text = h.TryGetProperty("text", out var txt) ? txt.GetString() ?? "" : ""
                });
            }
        }

        var paragraphs = new List<string>();
        if (root.TryGetProperty("paragraphs", out var pArray))
        {
            foreach (var p in pArray.EnumerateArray())
            {
                var text = p.GetString();
                if (text != null) paragraphs.Add(text);
            }
        }

        var links = new List<PageLink>();
        if (root.TryGetProperty("links", out var lArray))
        {
            foreach (var l in lArray.EnumerateArray())
            {
                links.Add(new PageLink
                {
                    Text = l.TryGetProperty("text", out var txt) ? txt.GetString() ?? "" : "",
                    Url = l.TryGetProperty("url", out var url) ? url.GetString() ?? "" : ""
                });
            }
        }

        var buttons = new List<string>();
        if (root.TryGetProperty("buttons", out var bArray))
        {
            foreach (var b in bArray.EnumerateArray())
            {
                var text = b.GetString();
                if (text != null) buttons.Add(text);
            }
        }

        var labels = new List<string>();
        if (root.TryGetProperty("labels", out var labArray))
        {
            foreach (var lab in labArray.EnumerateArray())
            {
                var text = lab.GetString();
                if (text != null) labels.Add(text);
            }
        }

        var images = new List<PageImage>();
        if (root.TryGetProperty("images", out var imgArray))
        {
            foreach (var img in imgArray.EnumerateArray())
            {
                images.Add(new PageImage
                {
                    Alt = img.TryGetProperty("alt", out var alt) ? alt.GetString() ?? "" : "",
                    Src = img.TryGetProperty("src", out var src) ? src.GetString() ?? "" : ""
                });
            }
        }

        return new StructuredTextResult
        {
            Url = root.TryGetProperty("url", out var urlProp) ? urlProp.GetString() ?? "" : "",
            Title = root.TryGetProperty("title", out var titleProp) ? titleProp.GetString() ?? "" : "",
            Language = root.TryGetProperty("language", out var langProp) && langProp.ValueKind == JsonValueKind.String ? langProp.GetString() : null,
            MetaDescription = root.TryGetProperty("metaDescription", out var metaProp) && metaProp.ValueKind == JsonValueKind.String ? metaProp.GetString() : null,
            Headings = headings,
            Paragraphs = paragraphs,
            Links = links,
            Buttons = buttons,
            Labels = labels,
            Images = images,
            WordCount = root.TryGetProperty("wordCount", out var wcProp) ? wcProp.GetInt32() : 0,
            AllText = root.TryGetProperty("allText", out var atProp) ? atProp.GetString() ?? "" : ""
        };
    }

    #endregion

}
