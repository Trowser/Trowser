using System.Text;
using Trowser.Recording;
using Trowser.Security;

namespace Trowser.Laws;

/// <summary>Scaffold Law .csx from UI context (point-and-declare, Shadow findings).</summary>
public static class LawCodeGenerator
{
    public static string FromElement(ContextMenuElementInfo el, Uri? pageUrl, bool forScriptConsoleRun = true)
    {
        var host = string.IsNullOrWhiteSpace(pageUrl?.Host) ? "*" : pageUrl!.Host;
        var path = "*";
        if (pageUrl != null && !string.IsNullOrWhiteSpace(pageUrl.AbsolutePath) && pageUrl.AbsolutePath != "/")
            path = pageUrl.AbsolutePath.TrimEnd('/') + "*";

        var name = !string.IsNullOrWhiteSpace(el.Label) ? el.Label.Trim()
            : !string.IsNullOrWhiteSpace(el.Text) ? Truncate(el.Text.Trim(), 48)
            : $"{el.Tag} element".Trim();

        var expect = BuildPageExpect(el);
        var sb = new StringBuilder();
        if (!forScriptConsoleRun)
            sb.AppendLine($"// @title {Truncate(name, 60)}");
        sb.AppendLine("// Point-and-declare — edit Site, OnPage, and Expect as needed");
        sb.AppendLine($"Site(\"{Escape(host)}\");");
        sb.AppendLine();
        sb.AppendLine($"Law(\"{Escape(name)}\")");
        sb.AppendLine($"    .OnPage(\"{Escape(path)}\")");
        sb.AppendLine($"    .Expect(p => {expect});");
        if (forScriptConsoleRun)
        {
            sb.AppendLine();
            sb.AppendLine("await CheckLaws();");
        }

        return sb.ToString();
    }

    private static string BuildPageExpect(ContextMenuElementInfo el)
    {
        if (!string.IsNullOrWhiteSpace(el.Selector))
        {
            var sel = Escape(el.Selector);
            if (!string.IsNullOrWhiteSpace(el.Text))
            {
                var fragment = Escape(Truncate(el.Text.Trim(), 80));
                return $"p.Exists(\"{sel}\") && p.Text(\"{sel}\").Contains(\"{fragment}\")";
            }

            return $"p.Exists(\"{sel}\") && p.Visible(\"{sel}\")";
        }

        if (!string.IsNullOrWhiteSpace(el.Text))
            return $"p.Title.Contains(\"{Escape(Truncate(el.Text.Trim(), 80))}\")";

        return "!string.IsNullOrWhiteSpace(p.Title)";
    }

    private static string? TryGetHost(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return null;
        return Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.Host : null;
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max].TrimEnd() + "…";

    private static string Escape(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    /// <summary>Scaffold a Law .csx from a Shadow finding (scan, audit, or prior Law failure).</summary>
    public static string FromFinding(ShadowFinding finding, bool forScriptConsoleRun = false)
    {
        var host = ShadowFinding.TryGetDomain(finding.Url) ?? "*";
        var path = DefaultPagePattern(finding.Url);
        var title = Truncate(finding.Title.Trim(), 72);
        var desc = finding.Description?.Trim() ?? "";

        var sb = new StringBuilder();
        if (!forScriptConsoleRun)
            sb.AppendLine($"// @title {Truncate(title, 60)}");
        sb.AppendLine($"// From finding #{finding.Id} ({finding.Audit}): {Escape(desc)}");
        sb.AppendLine($"Site(\"{Escape(host)}\"{(path != "*" ? $", \"{Escape(path)}\"" : "")});");
        sb.AppendLine();

        if (TryWriteKnownFindingLaw(sb, finding, title))
        {
            if (forScriptConsoleRun)
            {
                sb.AppendLine();
                sb.AppendLine("await CheckLaws();");
            }
            return sb.ToString();
        }

        sb.AppendLine($"Law(\"{Escape(title)}\")");
        sb.AppendLine($"    .OnPage(\"{Escape(path)}\")");
        sb.AppendLine("    // TODO: replace with a concrete invariant from the finding above");
        sb.AppendLine("    .Expect(p => !string.IsNullOrWhiteSpace(p.Title));");
        if (forScriptConsoleRun)
        {
            sb.AppendLine();
            sb.AppendLine("await CheckLaws();");
        }

        return sb.ToString();
    }

    private static bool TryWriteKnownFindingLaw(StringBuilder sb, ShadowFinding finding, string lawName)
    {
        var blob = (finding.Title + " " + finding.Description).ToLowerInvariant();

        if (blob.Contains("noopener") || blob.Contains("tabnabbing") || blob.Contains("target=_blank"))
        {
            sb.AppendLine($"Law(\"{Escape(lawName)}\")");
            sb.AppendLine("    .OnPage(\"*\")");
            sb.AppendLine("    .Expect(p => p.Count(\"a[target=_blank]:not([rel*=noopener]):not([rel*=noreferrer])\") == 0)");
            sb.AppendLine("    .Severity(Severity.Medium)");
            sb.AppendLine("    .Tags(\"security\", \"from-finding\");");
            return true;
        }

        if (blob.Contains("h1") || (blob.Contains("heading") && blob.Contains("multiple")))
        {
            sb.AppendLine($"Law(\"{Escape(lawName)}\")");
            sb.AppendLine("    .OnPage(\"*\")");
            sb.AppendLine("    .Expect(p => p.Count(\"h1\") == 1)");
            sb.AppendLine("    .Severity(Severity.Low)");
            sb.AppendLine("    .Tags(\"a11y\", \"from-finding\");");
            return true;
        }

        if (blob.Contains("clickjacking") || blob.Contains("x-frame-options") || blob.Contains("frame-ancestors"))
        {
            sb.AppendLine($"Law(\"{Escape(lawName)}\")");
            sb.AppendLine("    .OnResponse(\"GET *\")");
            sb.AppendLine("    .When(r => r.Status >= 200 && r.Status < 400 && (r.ContentType.Contains(\"html\", StringComparison.OrdinalIgnoreCase) || r.ContentType.Contains(\"text/\", StringComparison.OrdinalIgnoreCase)))");
            sb.AppendLine("    .Expect(r => !string.IsNullOrEmpty(r.Header(\"X-Frame-Options\")) || (r.Header(\"Content-Security-Policy\") ?? \"\").Contains(\"frame-ancestors\", StringComparison.OrdinalIgnoreCase))");
            sb.AppendLine("    .Severity(Severity.Medium)");
            sb.AppendLine("    .Tags(\"security\", \"headers\", \"from-finding\");");
            return true;
        }

        if (finding.Audit.Equals("laws", StringComparison.OrdinalIgnoreCase) && finding.Title.StartsWith("Law:", StringComparison.OrdinalIgnoreCase))
            return false;

        return false;
    }

    private static string DefaultPagePattern(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return "*";
        if (string.IsNullOrWhiteSpace(uri.AbsolutePath) || uri.AbsolutePath == "/")
            return "*";
        return uri.AbsolutePath.TrimEnd('/') + "*";
    }

    /// <summary>Remove Script Console runner lines before persisting Law source (Save as Law / MCP add).</summary>
    public static string StripConsoleRunnerLines(string code)
    {
        var kept = new List<string>();
        foreach (var line in code.Replace("\r\n", "\n").Split('\n'))
        {
            var t = line.Trim();
            if (t.StartsWith("await CheckLaws", StringComparison.OrdinalIgnoreCase))
                continue;
            if (t.StartsWith("await AssertLaws", StringComparison.OrdinalIgnoreCase))
                continue;
            if (t.Contains("Evaluates page Laws after declare", StringComparison.OrdinalIgnoreCase))
                continue;
            if (t.Contains("Checks Laws declared above in this Run only", StringComparison.OrdinalIgnoreCase))
                continue;
            kept.Add(line);
        }

        var trimmed = string.Join(Environment.NewLine, kept).TrimEnd();
        return string.IsNullOrEmpty(trimmed) ? trimmed : trimmed + Environment.NewLine;
    }
}
