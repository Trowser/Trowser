// @title Html Validation
// @shadow light
// @effects none
// HTML validation: check markup for errors, accessibility issues, and deprecated elements
// This validation is very picky, and doesn't mean that the site won't work

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"HTML validation: {title}");
Log($"URL: {url}");
Log("");

await AssertHtmlValid();
await PrintHtmlReport();
