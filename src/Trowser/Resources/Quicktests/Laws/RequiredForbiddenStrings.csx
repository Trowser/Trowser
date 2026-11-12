// @title Required / forbidden strings (Law template)
// @shadow light
// @effects none
// @see Capability/RequiredForbiddenStrings.csx

// "exception" alone matched words like "exceptional"; keep entries specific to error UIs.
var forbidden = new[] { "unknown error", "unhandled exception", "something went wrong" };
// Edit: strings your app must always show (empty = skip the required-strings Law).
var required = Array.Empty<string>();

Law("No forbidden strings on page")
    .OnPage("*")
    .Expect((PageFacts p) => forbidden.All(f => !p.Text("body").Contains(f, StringComparison.OrdinalIgnoreCase)))
    .Severity(Severity.Low)
    .Tags("generic");

if (required.Length > 0)
{
    Law("Required strings present")
        .OnPage("*")
        .Expect((PageFacts p) => required.All(r => p.Text("body").Contains(r, StringComparison.OrdinalIgnoreCase)));
}
