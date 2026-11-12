using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class TraceInputConfirmationPayloadTests
{
    private static readonly string Proof = $"{TraceInputPayloadPrep.ProofGlobal}=1";

    [Fact]
    public void FromCanaryContext_quoted_attribute_in_document_write_suggests_breakout()
    {
        const string canary = "trwR_abc1234567";
        var snippet = $"<img src=\"/tracker.gif?searchTerms={canary}\">";
        var payload = TraceInputConfirmationPayload.FromCanaryContext("document.write", snippet, canary);
        Assert.Equal($"test\" onerror=\"{Proof}\"", payload);
    }

    [Fact]
    public void FromCanaryContext_eval_sink_uses_js_expression()
    {
        const string canary = "trwR_evalcanary1";
        var payload = TraceInputConfirmationPayload.FromCanaryContext(
            "eval", canary, canary);
        Assert.Equal(Proof, payload);
    }

    [Fact]
    public void Pick_uses_canary_context_over_generic_img_tag()
    {
        const string canary = "trwR_deadbeef01";
        var reach = new InputTraceResult
        {
            Sinks = new InputTraceResult.SinkTrace
            {
                Hits =
                [
                    new InputTraceResult.SinkHit
                    {
                        Sink = "document.write",
                        ContainsPayload = true,
                        Snippet = $"<img src=\"/x?searchTerms={canary}\">"
                    }
                ]
            }
        };

        var picked = TraceInputConfirmationPayload.Pick(reach, canary, new TraceInputOptions());
        Assert.Equal($"test\" onerror=\"{Proof}\"", picked);
    }
}
