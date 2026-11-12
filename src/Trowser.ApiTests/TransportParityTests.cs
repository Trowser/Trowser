using Xunit;

namespace Trowser.ApiTests;

[Collection(BrowserCollection.Name)]
[Trait("Category", "Smoke")]
public class TransportParityTests
{
    private readonly TrowserInstance _instance;

    public TransportParityTests(TrowserInstance instance) => _instance = instance;

    public static IEnumerable<object[]> CaseIds() =>
        ParityCatalog.CaseIds.Select(id => new object[] { id });

    [Theory]
    [MemberData(nameof(CaseIds))]
    public Task Rest_and_mcp_match_for_case(string caseId) =>
        ParityCatalog.RunAsync(caseId, _instance);
}
