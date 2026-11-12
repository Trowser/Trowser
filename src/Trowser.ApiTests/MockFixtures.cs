namespace Trowser.ApiTests;

internal static class MockFixtures
{
    public const string Host = "https://trowser-apitest.test";

    public static string Url(string path = "/")
    {
        if (string.IsNullOrEmpty(path)) path = "/";
        if (!path.StartsWith('/')) path = "/" + path;
        return Host + path;
    }

    public static string MinimalHtml(string title, string body) =>
        $@"<!DOCTYPE html><html><head><meta charset=""utf-8""><title>{title}</title></head><body>{body}</body></html>";

    public static async Task SeedExamplePageAsync(RestClient api, string path = "/")
    {
        var url = Url(path);
        var html = MinimalHtml("Example Domain",
            "<h1>Example Domain</h1><p>Fixture copy for API tests.</p>" +
            $"<p><a href=\"{Url("/more")}\">Learn more</a></p>" +
            "<form id=\"f1\"><label for=\"n\">Name</label><input id=\"n\" name=\"n\" placeholder=\"Enter name\" />" +
            "<select id=\"s\"><option value=\"a\">Alpha</option><option value=\"b\">Beta</option></select></form>");

        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/clear-session", new { });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/mock", new
        {
            urlPattern = url,
            status = 200,
            body = html,
            headers = new Dictionary<string, string>
            {
                ["Content-Type"] = "text/html; charset=utf-8",
                ["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
            }
        });
    }
}
