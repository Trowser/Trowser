using Trowser.Automation;
using Xunit;

namespace Trowser.Tests.Automation;

public class NetworkLogSupplementTests
{
    [Fact]
    public void Supplement_fills_missing_body_and_header_without_replacing_them()
    {
        var log = new NetworkLog();
        var id = log.Add(new NetworkEntry
        {
            Method = "GET",
            Url = "https://trowser-regression.test/env.js",
            StatusCode = 200,
            ResourceType = "Script",
            ResponseHeaders = new Dictionary<string, string> { ["Content-Length"] = "12" }
        });

        Assert.True(log.TrySupplement(id, "window.env=1", new Dictionary<string, string> { ["X-CSRF"] = "1" }));

        var entry = log.Entries.Single();
        Assert.Equal("window.env=1", entry.ResponseBody);
        Assert.Equal("1", entry.RequestHeaders["X-CSRF"]);
        Assert.Equal(id, entry.Id);

        Assert.False(log.TrySupplement(id, "other", new Dictionary<string, string> { ["X-CSRF"] = "2" }));
        Assert.Equal("window.env=1", log.Entries.Single().ResponseBody);
        Assert.Equal("1", log.Entries.Single().RequestHeaders["X-CSRF"]);
    }
}
