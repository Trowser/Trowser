using Trowser.Security;

namespace Trowser.Security.WebSocket;

/// <summary>Benign code-execution oracles for inbound WebSocket frames consumed via eval/Function.</summary>
internal static class WebSocketExecOracle
{
    public sealed record OracleProbe(string Vector, string Payload, string CanaryId);

    public static IReadOnlyList<OracleProbe> BuildProbes(int max = 4)
    {
        var list = new List<OracleProbe>();
        for (var i = 0; i < max; i++)
        {
            var canary = "ws_" + Guid.NewGuid().ToString("N")[..12];
            var execCall = $"{TraceInputPayloadPrep.ExecGlobal}('{canary}')";
            list.Add(new OracleProbe("ws-exec-global", execCall, canary));
            list.Add(new OracleProbe("ws-proof-assign", $"{TraceInputPayloadPrep.ProofGlobal}=1", canary));
            list.Add(new OracleProbe("ws-expr-return", $"(function(){{ {execCall}; return 1; }})()", canary));
        }

        return list
            .GroupBy(p => p.Payload, StringComparer.Ordinal)
            .Select(g => g.First())
            .Take(max)
            .ToList();
    }
}
