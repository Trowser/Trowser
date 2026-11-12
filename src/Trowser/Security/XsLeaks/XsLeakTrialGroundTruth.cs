using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

internal sealed class XsLeakTrialGroundTruth
{
    public int? StatusCode { get; init; }
    public IReadOnlyList<string> Mitigations { get; init; } = [];
    public Dictionary<string, string> SecFetchRequest { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public static XsLeakTrialGroundTruth FromNetwork(NetworkLog network, string victimUrl, int entriesBefore)
    {
        var mitigations = new List<string>();
        var secFetch = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int? status = null;

        var victimBase = victimUrl.Split('?', '#')[0];
        foreach (var e in network.Entries.Where(x => x.Id > entriesBefore))
        {
            if (string.IsNullOrEmpty(e.Url)
                || !e.Url.StartsWith(victimBase, StringComparison.OrdinalIgnoreCase))
                continue;

            status ??= e.StatusCode;
            foreach (var (k, v) in e.ResponseHeaders)
            {
                var key = k.ToLowerInvariant();
                var val = v ?? "";
                if (key == "cross-origin-opener-policy") mitigations.Add("COOP:" + val);
                if (key == "cross-origin-resource-policy") mitigations.Add("CORP:" + val);
                if (key == "cross-origin-embedder-policy") mitigations.Add("COEP:" + val);
                if (key == "x-frame-options") mitigations.Add("XFO:" + val);
                if (key == "content-security-policy" && val.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase))
                    mitigations.Add("CSP-frame-ancestors");
                if (key == "vary") mitigations.Add("Vary:" + val);
            }

            foreach (var (k, v) in e.RequestHeaders)
            {
                if (k.StartsWith("Sec-Fetch-", StringComparison.OrdinalIgnoreCase))
                    secFetch[k] = v;
            }
        }

        return new XsLeakTrialGroundTruth
        {
            StatusCode = status,
            Mitigations = mitigations.Distinct(StringComparer.OrdinalIgnoreCase).Take(16).ToList(),
            SecFetchRequest = secFetch
        };
    }
}
