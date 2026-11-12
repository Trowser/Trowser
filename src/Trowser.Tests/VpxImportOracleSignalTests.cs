using System.Text.Json;
using Trowser.Security.Vpx;
using Xunit;

namespace Trowser.Tests;

public class VpxImportOracleSignalTests
{
    [Fact]
    public void ReadOracleActualSignal_accepts_string_or_object()
    {
        using var strDoc = JsonDocument.Parse("""{"actualSignal":"ok"}""");
        Assert.Equal("ok", VpxImportService.ReadOracleActualSignal(strDoc.RootElement.GetProperty("actualSignal")));

        using var objDoc = JsonDocument.Parse("""{"actualSignal":{"error":"boom"}}""");
        Assert.Equal("""{"error":"boom"}""", VpxImportService.ReadOracleActualSignal(objDoc.RootElement.GetProperty("actualSignal")));
    }
}
