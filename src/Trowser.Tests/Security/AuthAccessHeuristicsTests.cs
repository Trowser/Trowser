using Trowser.Automation;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public sealed class AuthAccessHeuristicsTests
{
    [Fact]
    public void LooksLikeGenericErrorPage_AspNetSoft404Query()
    {
        var url = "https://app.test/Error/NotFound?aspxerrorpath=/api/admin/users";
        Assert.True(AuthAccessHeuristics.LooksLikeGenericErrorPage("<html>not found</html>", url));
    }

    [Fact]
    public void CapturedMutationLooksActionable_FalseForSoft404AndScannerTraffic()
    {
        var soft404 = new NetworkEntry
        {
            Method = "PUT",
            Url = "https://app.test/Error/NotFound?aspxerrorpath=/api/admin/users",
            StatusCode = 200,
            ResponseBody = "<html><title>Not Found</title></html>"
        };
        Assert.False(AuthAccessHeuristics.CapturedMutationLooksActionable(soft404));

        var scanner = new NetworkEntry
        {
            Method = "PUT",
            Url = "https://app.test/api/admin/users",
            StatusCode = 200,
            IsTrowserGenerated = true
        };
        Assert.False(AuthAccessHeuristics.CapturedMutationLooksActionable(scanner));
    }
}
