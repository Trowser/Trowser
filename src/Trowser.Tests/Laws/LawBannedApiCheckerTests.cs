using Trowser.Laws;
using Xunit;

namespace Trowser.Tests.Laws;

public class LawBannedApiCheckerTests
{
    [Fact]
    public void Blocks_http_client_usage()
    {
        var code = """
            Law("x").OnPage("*").Expect(_ => { var c = new HttpClient(); return true; });
            """;
        var v = LawBannedApiChecker.FindViolations(code);
        Assert.Contains(v, s => s.Contains("HttpClient", StringComparison.Ordinal));
    }

    [Fact]
    public void Blocks_environment_exit()
    {
        var code = """
            Law("x").OnPage("*").Expect(_ => { Environment.Exit(0); return true; });
            """;
        var v = LawBannedApiChecker.FindViolations(code);
        Assert.NotEmpty(v);
    }

    [Fact]
    public void Blocks_tcp_client()
    {
        var code = """
            Law("x").OnPage("*").Expect(_ => { var c = new TcpClient(); return true; });
            """;
        var v = LawBannedApiChecker.FindViolations(code);
        Assert.NotEmpty(v);
    }

    [Fact]
    public void Blocks_appdomain_assembly_load()
    {
        var code = """
            Law("x").OnPage("*").Expect(_ => {
                var asm = System.AppDomain.CurrentDomain.Load("System.Net.Http");
                return true;
            });
            """;
        var v = LawBannedApiChecker.FindViolations(code);
        Assert.Contains(v, s => s.Contains("Load", StringComparison.Ordinal) || s.Contains("AppDomain", StringComparison.Ordinal));
    }
}
