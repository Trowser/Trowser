using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// When sink monitoring is on, prefer execution-oracle payloads over alert() for definitive proof.
/// </summary>
internal static class TraceInputPayloadPrep
{
    private static readonly Regex AlertCall = new(@"alert\s*\(\s*[^)]*\)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ConfirmCall = new(@"confirm\s*\(\s*[^)]*\)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex OnHandlerValue = new(
        @"(on\w+\s*=\s*)(['""]?)([^'"">\s]+)\2",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public const string ExecGlobal = "__trowser_exec";
    public const string ProofGlobal = "__xss_proof";

    public static string ApplyExecCanary(string payload, out string canaryId)
    {
        canaryId = "ti_" + Guid.NewGuid().ToString("N")[..12];
        if (payload.Contains(ExecGlobal, StringComparison.OrdinalIgnoreCase)
            || payload.Contains(ProofGlobal, StringComparison.OrdinalIgnoreCase))
        {
            canaryId = "";
            return payload;
        }

        var exec = $"{ExecGlobal}('{canaryId}')";
        var proofAssign = $"{ProofGlobal}=1";

        if (AlertCall.IsMatch(payload))
            return AlertCall.Replace(payload, exec);
        if (ConfirmCall.IsMatch(payload))
            return ConfirmCall.Replace(payload, exec);

        if (Regex.IsMatch(payload, @"on\w+\s*=", RegexOptions.IgnoreCase))
        {
            if (OnHandlerValue.IsMatch(payload))
            {
                return OnHandlerValue.Replace(payload, m =>
                {
                    var prefix = m.Groups[1].Value;
                    var quote = m.Groups[2].Value;
                    var inner = m.Groups[3].Value;
                    if (inner.Contains(ExecGlobal, StringComparison.OrdinalIgnoreCase))
                        return m.Value;
                    if (AlertCall.IsMatch(inner))
                        inner = AlertCall.Replace(inner, exec);
                    else if (ConfirmCall.IsMatch(inner))
                        inner = ConfirmCall.Replace(inner, exec);
                    else
                        inner = proofAssign;
                    return quote.Length > 0
                        ? $"{prefix}{quote}{inner}{quote}"
                        : $"{prefix}{inner}";
                });
            }

            return payload;
        }

        if (payload.Contains('<', StringComparison.Ordinal))
        {
            if (payload.Contains("<script", StringComparison.OrdinalIgnoreCase))
                return payload;
            if (Regex.IsMatch(payload, @"on\w+\s*=", RegexOptions.IgnoreCase))
                return EmbedOracleInHtmlHandlers(payload, exec, proofAssign);
            return $"<img src=x onerror=\"{proofAssign}\">";
        }

        return $"{exec};void 0";
    }

    public static string EmbedOracleInHtmlHandlers(string html, string? execCall = null, string? proofAssign = null)
    {
        execCall ??= $"{ExecGlobal}('probe')";
        proofAssign ??= $"{ProofGlobal}=1";
        return Regex.Replace(html, @"on(\w+)\s*=\s*([""']?)([^""'>\s]+)\2?", m =>
        {
            var ev = m.Groups[1].Value;
            var q = m.Groups[2].Value;
            var val = m.Groups[3].Value;
            if (val.Contains(ExecGlobal, StringComparison.OrdinalIgnoreCase)
                || val.Contains(ProofGlobal, StringComparison.OrdinalIgnoreCase))
                return m.Value;
            var replacement = AlertCall.IsMatch(val) || ConfirmCall.IsMatch(val)
                ? AlertCall.Replace(ConfirmCall.Replace(val, execCall), execCall)
                : proofAssign;
            return q.Length > 0
                ? $"on{ev}={q}{replacement}{q}"
                : $"on{ev}={replacement}";
        }, RegexOptions.IgnoreCase);
    }

    public static string DefaultImgOnerrorOracle() =>
        $"<img src=x onerror=\"{ProofGlobal}=1\">";
}
