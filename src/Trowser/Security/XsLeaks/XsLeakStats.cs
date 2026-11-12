namespace Trowser.Security.XsLeaks;

internal static class XsLeakStats
{
    /// <summary>Welch-ish mean comparison with effect size (Cohen's d) plus Mann-Whitney U p-value when n≥5.</summary>
    public static (bool Significant, double MeanA, double MeanB, double EffectSize, double? PValue) CompareTiming(
        IReadOnlyList<double> a, IReadOnlyList<double> b, double minEffect = 1.0, double minAbsGap = 50)
    {
        if (a.Count < 3 || b.Count < 3)
            return (false, a.DefaultIfEmpty().Average(), b.DefaultIfEmpty().Average(), 0, null);

        var meanA = a.Average();
        var meanB = b.Average();
        var varA = Variance(a, meanA);
        var varB = Variance(b, meanB);
        var pooled = Math.Sqrt((varA + varB) / 2.0);
        var effect = pooled < 1e-9 ? 0 : Math.Abs(meanA - meanB) / pooled;
        var absGap = Math.Abs(meanA - meanB);
        double? pValue = null;
        var mwSig = false;
        if (a.Count >= 5 && b.Count >= 5)
        {
            mwSig = MannWhitneySignificant(a, b, out var p);
            pValue = p;
        }

        var heuristic = effect >= minEffect && absGap >= minAbsGap && !RangesHeavilyOverlap(a, b);
        var significant = heuristic && (mwSig || a.Count < 5);
        return (significant, meanA, meanB, effect, pValue);
    }

    /// <summary>Two-sided Mann-Whitney U test (normal approximation).</summary>
    public static bool MannWhitneySignificant(IReadOnlyList<double> a, IReadOnlyList<double> b, out double pValue)
    {
        pValue = 1.0;
        if (a.Count < 2 || b.Count < 2) return false;

        var combined = a.Concat(b).OrderBy(x => x).ToList();
        var ranks = new Dictionary<double, double>();
        for (var i = 0; i < combined.Count;)
        {
            var j = i;
            while (j < combined.Count && combined[j].Equals(combined[i])) j++;
            var avgRank = (i + 1 + j) / 2.0;
            for (var k = i; k < j; k++)
                ranks[combined[k]] = avgRank;
            i = j;
        }

        double rankSumA = 0;
        foreach (var x in a)
            rankSumA += ranks[x];
        var uA = rankSumA - a.Count * (a.Count + 1) / 2.0;
        var u = Math.Min(uA, a.Count * b.Count - uA);
        var mu = a.Count * b.Count / 2.0;
        var sigma = Math.Sqrt(a.Count * b.Count * (a.Count + b.Count + 1) / 12.0);
        if (sigma < 1e-9) return false;
        var z = (u - mu) / sigma;
        pValue = 2.0 * (1.0 - NormalCdf(Math.Abs(z)));
        return pValue < 0.05;
    }

    private static double NormalCdf(double z)
    {
        // Abramowitz & Stegun approximation
        var t = 1.0 / (1.0 + 0.2316419 * z);
        var d = 0.3989423 * Math.Exp(-z * z / 2.0);
        var p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
        return 1.0 - p;
    }

    public static bool IsNonEvidence(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return true;
        var v = value.Trim();
        return v.Equals("timeout", StringComparison.OrdinalIgnoreCase)
               || v.Equals("pending", StringComparison.OrdinalIgnoreCase)
               || v.StartsWith("error-after", StringComparison.OrdinalIgnoreCase)
               || v.StartsWith("error:", StringComparison.OrdinalIgnoreCase);
    }

    public static List<string?> FilterEvidence(IReadOnlyList<string?> values) =>
        values.Where(v => !IsNonEvidence(v)).ToList();

    /// <summary>True when value sets are disjoint categorical observables (not noisy numeric samples).</summary>
    public static bool DeterministicDistinct(IReadOnlyList<string?> a, IReadOnlyList<string?> b)
    {
        a = FilterEvidence(a);
        b = FilterEvidence(b);
        if (a.Count < 2 || b.Count < 2) return false;
        var setA = a.Where(x => x != null).Select(x => x!).ToHashSet(StringComparer.Ordinal);
        var setB = b.Where(x => x != null).Select(x => x!).ToHashSet(StringComparer.Ordinal);
        if (setA.Count == 0 || setB.Count == 0) return false;
        if (AllNumeric(setA) && AllNumeric(setB))
        {
            // Stable integer observables (iframe frame count, uniform redirect counts, …).
            if (UniformIntegerObservable(a) && UniformIntegerObservable(b))
                return !setA.SetEquals(setB) && !setA.Overlaps(setB);
            return false;
        }
        return !setA.SetEquals(setB) && !setA.Overlaps(setB);
    }

    /// <summary>Every non-null sample is the same integer token (e.g. frame-count oracle).</summary>
    public static bool UniformIntegerObservable(IReadOnlyList<string?> values)
    {
        string? uniform = null;
        foreach (var v in values)
        {
            if (string.IsNullOrWhiteSpace(v)) continue;
            var token = v.Split(':')[0].Trim();
            if (!int.TryParse(token, System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture, out _))
                return false;
            uniform ??= v.Trim();
            if (!string.Equals(uniform, v.Trim(), StringComparison.Ordinal))
                return false;
        }
        return uniform != null;
    }

    public static List<double> ParseNumericObservations(IReadOnlyList<string?> values)
    {
        var list = new List<double>();
        foreach (var v in values)
        {
            if (string.IsNullOrWhiteSpace(v)) continue;
            var token = v.Split(':')[0].Trim();
            if (double.TryParse(token, System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var d))
                list.Add(d);
        }
        return list;
    }

    private static bool AllNumeric(IEnumerable<string> set) =>
        set.All(s => double.TryParse(s.Split(':')[0].Trim(),
            System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out _));

    /// <summary>True when min/max ranges of two samples overlap substantially (timing noise).</summary>
    public static bool RangesHeavilyOverlap(IReadOnlyList<double> a, IReadOnlyList<double> b)
    {
        if (a.Count == 0 || b.Count == 0) return true;
        var minA = a.Min();
        var maxA = a.Max();
        var minB = b.Min();
        var maxB = b.Max();
        var overlap = Math.Min(maxA, maxB) - Math.Max(minA, minB);
        if (overlap <= 0) return false;
        var spanA = Math.Max(maxA - minA, 1e-6);
        var spanB = Math.Max(maxB - minB, 1e-6);
        var overlapRatio = overlap / Math.Min(spanA, spanB);
        return overlapRatio >= 0.65;
    }

    private static double Variance(IReadOnlyList<double> xs, double mean)
    {
        if (xs.Count < 2) return 0;
        var sum = 0.0;
        foreach (var x in xs)
        {
            var d = x - mean;
            sum += d * d;
        }
        return sum / (xs.Count - 1);
    }
}
