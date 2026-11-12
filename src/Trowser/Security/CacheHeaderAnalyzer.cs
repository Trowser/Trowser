using System.Text;

namespace Trowser.Security;

/// <summary>
/// Parses HTTP cache-related response headers into a structured summary.
/// Shared by tech-stack, cache-map, cache-pollution, poison, and deception scanners.
/// Inspired by PortSwigger web cache poisoning / cache deception methodology.
/// </summary>
public static class CacheHeaderAnalyzer
{
    public const string DocumentStatusHit = "hit";
    public const string DocumentStatusMiss = "miss";
    public const string DocumentStatusDynamic = "dynamic";
    public const string DocumentStatusNotCached = "not-cached";
    public const string DocumentStatusUnknown = "unknown";

    /// <summary>Analyze a single response header bag.</summary>
    public static CacheIdentifySummary Analyze(IReadOnlyDictionary<string, string>? headers)
    {
        if (headers == null || headers.Count == 0)
        {
            return new CacheIdentifySummary
            {
                Detected = false,
                DocumentStatus = DocumentStatusUnknown,
                Cacheable = false
            };
        }

        var evidence = new List<string>();
        var vendors = new List<string>();
        var vary = new List<string>();

        TryGet(headers, "Vary", out var varyRaw);
        if (!string.IsNullOrWhiteSpace(varyRaw))
        {
            foreach (var part in varyRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!string.IsNullOrWhiteSpace(part) && !vary.Contains(part, StringComparer.OrdinalIgnoreCase))
                    vary.Add(part);
            }
            evidence.Add($"Vary: {varyRaw}");
        }

        TryGet(headers, "Cache-Control", out var cc);
        var cacheable = false;
        var notCached = false;
        if (!string.IsNullOrWhiteSpace(cc))
        {
            evidence.Add($"Cache-Control: {cc}");
            var lower = cc.ToLowerInvariant();
            if (lower.Contains("no-store") || lower.Contains("private"))
                notCached = true;
            if (lower.Contains("public") || lower.Contains("s-maxage=") || lower.Contains("max-age="))
                cacheable = !notCached;
        }

        foreach (var name in new[] { "CDN-Cache-Control", "Surrogate-Control" })
        {
            if (TryGet(headers, name, out var v) && !string.IsNullOrWhiteSpace(v))
            {
                evidence.Add($"{name}: {v}");
                cacheable = true;
            }
        }

        var status = DocumentStatusUnknown;
        if (TryGet(headers, "Age", out var age) && double.TryParse(age.Trim(), out var ageSec) && ageSec >= 0)
        {
            evidence.Add($"Age: {age}");
            status = ageSec > 0 ? DocumentStatusHit : DocumentStatusMiss;
            cacheable = true;
        }

        if (TryGet(headers, "X-Cache", out var xCache))
        {
            evidence.Add($"X-Cache: {xCache}");
            status = ClassifyHitMiss(xCache, status);
            cacheable = true;
            if (xCache.Contains("cloudfront", StringComparison.OrdinalIgnoreCase))
                AddVendor(vendors, "Amazon CloudFront");
        }

        if (TryGet(headers, "X-Cache-Hits", out var hits)
            && int.TryParse(hits.Trim(), out var hitCount))
        {
            evidence.Add($"X-Cache-Hits: {hits}");
            if (hitCount > 0)
                status = DocumentStatusHit;
            cacheable = true;
        }

        if (TryGet(headers, "CF-Cache-Status", out var cf))
        {
            evidence.Add($"CF-Cache-Status: {cf}");
            AddVendor(vendors, "Cloudflare");
            status = ClassifyCf(cf, status);
            cacheable = true;
        }

        if (TryGet(headers, "X-Vercel-Cache", out var vercel))
        {
            evidence.Add($"X-Vercel-Cache: {vercel}");
            AddVendor(vendors, "Vercel");
            status = ClassifyHitMiss(vercel, status);
            cacheable = true;
        }

        if (TryGet(headers, "X-Sucuri-Cache", out var sucuri))
        {
            evidence.Add($"X-Sucuri-Cache: {sucuri}");
            AddVendor(vendors, "Sucuri");
            status = ClassifyHitMiss(sucuri, status);
            cacheable = true;
        }

        if (TryGet(headers, "X-Drupal-Cache", out var drupal))
        {
            evidence.Add($"X-Drupal-Cache: {drupal}");
            status = ClassifyHitMiss(drupal, status);
            cacheable = true;
        }

        if (TryGet(headers, "X-LiteSpeed-Cache", out var ls))
        {
            evidence.Add($"X-LiteSpeed-Cache: {ls}");
            AddVendor(vendors, "LiteSpeed Cache");
            status = ClassifyHitMiss(ls, status);
            cacheable = true;
        }

        if (TryGet(headers, "X-Varnish", out var varnish))
        {
            evidence.Add($"X-Varnish: {varnish}");
            AddVendor(vendors, "Varnish");
            cacheable = true;
        }

        if (TryGet(headers, "Via", out var via))
        {
            evidence.Add($"Via: {via}");
            if (via.Contains("varnish", StringComparison.OrdinalIgnoreCase))
                AddVendor(vendors, "Varnish");
            if (via.Contains("cloudfront", StringComparison.OrdinalIgnoreCase))
                AddVendor(vendors, "Amazon CloudFront");
        }

        if (TryGet(headers, "CF-Ray", out _))
            AddVendor(vendors, "Cloudflare");
        if (TryGet(headers, "X-Amz-Cf-Id", out _) || TryGet(headers, "X-Amz-Cf-Pop", out _))
            AddVendor(vendors, "Amazon CloudFront");
        if (TryGet(headers, "X-Fastly-Request-Id", out _))
            AddVendor(vendors, "Fastly");
        if (TryGet(headers, "X-Served-By", out var servedBy)
            && servedBy.Contains("cache-", StringComparison.OrdinalIgnoreCase))
            AddVendor(vendors, "Fastly");
        if (TryGet(headers, "X-Vercel-Id", out _))
            AddVendor(vendors, "Vercel");
        if (TryGet(headers, "X-Azure-Ref", out _))
            AddVendor(vendors, "Azure CDN");
        if (TryGet(headers, "X-Akamai-Transformed", out _)
            || (TryGet(headers, "Server", out var srv) && srv.Contains("AkamaiGHost", StringComparison.OrdinalIgnoreCase)))
            AddVendor(vendors, "Akamai");

        if (notCached)
        {
            status = DocumentStatusNotCached;
            cacheable = false;
        }
        else if (status == DocumentStatusUnknown && cacheable)
        {
            status = DocumentStatusMiss;
        }

        var detected = vendors.Count > 0
                       || cacheable
                       || status is DocumentStatusHit or DocumentStatusMiss or DocumentStatusDynamic
                       || evidence.Count > 0 && (TryGet(headers, "Age", out _) || TryGet(headers, "X-Cache", out _)
                                                 || TryGet(headers, "CF-Cache-Status", out _));

        return new CacheIdentifySummary
        {
            Detected = detected,
            Vendors = vendors,
            DocumentStatus = status,
            Cacheable = cacheable && !notCached,
            Vary = vary,
            Evidence = evidence
        };
    }

    /// <summary>True when headers indicate a cache HIT (or Age &gt; 0).</summary>
    public static bool LooksLikeHit(IReadOnlyDictionary<string, string>? headers)
    {
        var s = Analyze(headers);
        return s.DocumentStatus == DocumentStatusHit;
    }

    /// <summary>True when headers indicate MISS / Age 0 / origin-looking after a revalidation attempt.</summary>
    public static bool LooksLikeMiss(IReadOnlyDictionary<string, string>? headers)
    {
        var s = Analyze(headers);
        return s.DocumentStatus is DocumentStatusMiss or DocumentStatusDynamic;
    }

    /// <summary>True when response looks storeable by a shared cache (not no-store/private).</summary>
    public static bool HasCacheabilitySignal(IReadOnlyDictionary<string, string>? headers)
    {
        var s = Analyze(headers);
        return s.Cacheable || s.DocumentStatus == DocumentStatusHit;
    }

    public static bool TryGet(IReadOnlyDictionary<string, string> headers, string name, out string value)
    {
        if (headers.TryGetValue(name, out value!) && !string.IsNullOrWhiteSpace(value))
            return true;
        foreach (var kv in headers)
        {
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(kv.Value))
            {
                value = kv.Value;
                return true;
            }
        }

        value = "";
        return false;
    }

    public static string FormatEvidence(CacheIdentifySummary summary)
    {
        if (summary.Evidence.Count == 0)
            return "(no cache headers observed)";
        return string.Join("; ", summary.Evidence);
    }

    public static string BodyHash(string? body)
    {
        if (string.IsNullOrEmpty(body))
            return "empty";
        // Short stable fingerprint for comparison tables (not cryptographic).
        unchecked
        {
            uint hash = 2166136261;
            foreach (var c in body)
            {
                hash ^= c;
                hash *= 16777619;
            }
            return $"{body.Length:x}-{hash:x8}";
        }
    }

    public static string FormatCacheHeadersPair(
        IReadOnlyDictionary<string, string>? a,
        IReadOnlyDictionary<string, string>? b,
        string labelA = "a",
        string labelB = "b")
    {
        var keys = new[]
        {
            "Cache-Control", "Age", "X-Cache", "CF-Cache-Status", "X-Cache-Hits",
            "X-Vercel-Cache", "Vary", "Location", "X-Varnish", "Via"
        };
        var sb = new StringBuilder();
        foreach (var key in keys)
        {
            string? av = null, bv = null;
            if (a != null) TryGet(a, key, out av!);
            if (b != null) TryGet(b, key, out bv!);
            if (!string.IsNullOrEmpty(av) || !string.IsNullOrEmpty(bv))
                sb.Append($"{key}: {labelA}={av ?? "-"} {labelB}={bv ?? "-"}; ");
        }
        return sb.Length > 0 ? sb.ToString().TrimEnd(' ', ';') : "(no cache headers observed)";
    }

    private static string ClassifyHitMiss(string value, string current)
    {
        var v = value.ToUpperInvariant();
        if (v.Contains("HIT") || v.Contains("STALE") || v.Equals("HIT"))
            return DocumentStatusHit;
        if (v.Contains("MISS") || v.Contains("EXPIRED") || v.Contains("REVALIDATED") || v.Contains("UPDATING"))
            return DocumentStatusMiss;
        if (v.Contains("DYNAMIC") || v.Contains("BYPASS") || v.Contains("NONE"))
            return DocumentStatusDynamic;
        return current;
    }

    private static string ClassifyCf(string value, string current)
    {
        var v = value.Trim().ToUpperInvariant();
        return v switch
        {
            "HIT" or "STALE" or "REVALIDATED" or "UPDATING" => DocumentStatusHit,
            "MISS" or "EXPIRED" => DocumentStatusMiss,
            "DYNAMIC" or "BYPASS" or "NONE" => DocumentStatusDynamic,
            _ => ClassifyHitMiss(value, current)
        };
    }

    private static void AddVendor(List<string> vendors, string name)
    {
        if (!vendors.Contains(name, StringComparer.OrdinalIgnoreCase))
            vendors.Add(name);
    }
}

/// <summary>Structured cache identification result (tech-stack / cache-map step 0).</summary>
public sealed class CacheIdentifySummary
{
    public bool Detected { get; init; }
    public List<string> Vendors { get; init; } = [];
    /// <summary>hit | miss | dynamic | not-cached | unknown</summary>
    public string DocumentStatus { get; init; } = CacheHeaderAnalyzer.DocumentStatusUnknown;
    public bool Cacheable { get; init; }
    public List<string> Vary { get; init; } = [];
    public List<string> Evidence { get; init; } = [];

    public object ToApiObject() => new
    {
        detected = Detected,
        vendors = Vendors,
        documentStatus = DocumentStatus,
        cacheable = Cacheable,
        vary = Vary,
        evidence = Evidence
    };
}
