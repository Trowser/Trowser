// @title Generic web Laws
// @shadow light
// @effects none
// @see Laws/WebPhysics.csx
//
// Conservative invariants that hold for almost every web app. They report at Low/Info so they
// surface as hints, not blockers. Turn off this file on the Shadow Laws tab, mute individual
// Laws there, or copy this file to Documents\Trowser Quicktests\Laws and tune it.

// ── Page structure / accessibility basics ────────────────────────────────────────────────────

Law("Page declares a language (html[lang])")
    .OnPage("*")
    .When((PageFacts p) => p.Exists("body"))
    .Expect((PageFacts p) => !string.IsNullOrWhiteSpace(p.Attr("html", "lang")))
    .Severity(Severity.Low)
    .Tags("generic", "a11y");

Law("Page has a responsive viewport meta tag")
    .OnPage("*")
    .When((PageFacts p) => p.Exists("body"))
    .Expect((PageFacts p) => p.Exists("meta[name=viewport]"))
    .Severity(Severity.Info)
    .Tags("generic", "mobile");

Law("Images missing an alt attribute")
    .OnPage("*")
    .Expect((PageFacts p) => p.Count("img:not([alt])") == 0)
    .Severity(Severity.Low)
    .Tags("generic", "a11y");

// ── Rendering leaks: values the UI should never show to a user ──────────────────────────────

var renderingLeak = new Regex(
    @"\[object Object\]|\bNaN\b|\{\{\s*[A-Za-z_$][\w.$]*\s*\}\}|\$\{\s*[A-Za-z_$][\w.$]*\s*\}",
    RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

Law("No rendering leaks in visible text ([object Object], NaN, {{template}})")
    .OnPage("*")
    .Forbid((PageFacts p) => renderingLeak.IsMatch(p.Text("body")))
    .Confirm()
    .Severity(Severity.Low)
    .Tags("generic", "rendering");

// ── Transport ────────────────────────────────────────────────────────────────────────────────

Law("No password field on a plain-HTTP page")
    .OnPage("*")
    .When((PageFacts p) => p.Url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                           && p.Host != "localhost" && p.Host != "127.0.0.1" && p.Host != "[::1]")
    .Forbid((PageFacts p) => p.Exists("input[type=password]"))
    .Severity(Severity.Low)
    .Tags("generic", "security");

// ── Responses: server internals should not reach the client ─────────────────────────────────

var stackTrace = new Regex(
    @"Traceback \(most recent call last\)|Exception in thread ""|\n\s+at [\w$.]+\([\w$]+\.java:\d+\)|\n\s+at System\.[\w.`]+\(|\n\s+at Microsoft\.[\w.`]+\(|\.php:\d+\s*\nStack trace:|Whitelabel Error Page",
    RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

Law("Responses do not leak server stack traces")
    .OnResponse("*")
    .When((ResponseFacts r) => !string.IsNullOrEmpty(r.Body))
    .Forbid((ResponseFacts r) => stackTrace.IsMatch(r.Body!))
    .Severity(Severity.Low)
    .Tags("generic", "security", "errors");

// ── Console: framework development warnings shipped to users ────────────────────────────────

// Framework dev warnings (React logs them at error level, Vue at warn) mean a development build
// or a real rendering bug reached the browser.
Law("No framework dev-mode warnings in the console")
    .OnConsole()
    .Forbid((ConsoleFacts c) =>
        c.Message.Contains("[Vue warn]", StringComparison.Ordinal)
        || c.Message.Contains("Each child in a list should have a unique \"key\" prop", StringComparison.Ordinal)
        || c.Message.Contains("Hydration failed", StringComparison.Ordinal)
        || c.Message.Contains("ExpressionChangedAfterItHasBeenCheckedError", StringComparison.Ordinal))
    .Severity(Severity.Info)
    .Tags("generic", "console");
