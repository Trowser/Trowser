using Trowser.Api;

namespace Trowser.Security.Authz;

/// <summary>
/// Multi-signal outcome of a <see cref="LiveAuthzShadow"/> cross-identity replay.
/// </summary>
public enum AuthzVerdictKind
{
    /// <summary>Peer response contains an owner-identifying token (highest-confidence leak signal).</summary>
    ConfirmedLeak,

    /// <summary>Peer got a 2xx response that is content-identical (or near-identical) to the owner's.</summary>
    BolaSuspected,

    /// <summary>Peer got a 2xx response with the same JSON shape as the owner's but different values.</summary>
    SameShapeDifferentData,

    /// <summary>Both sides returned empty/uninformative bodies — nothing to compare.</summary>
    NeedsReview,

    /// <summary>
    /// Peer got a 2xx response with different content. Not proof the peer was limited to its own data.
    /// </summary>
    FilteredResponse,

    /// <summary>Peer was denied (401/403/404 or redirected to a login/denial page) while the owner succeeded.</summary>
    ProperlyDenied,

    /// <summary>Owner baseline was not a success, or the peer fetch errored/was rate-limited — no verdict possible.</summary>
    Inconclusive,

    /// <summary>
    /// A state-changing replay succeeded for both identities. The peer account was mutated.
    /// Different ids are an isolated write, not a leak.
    /// </summary>
    ReplayedWrite,

    /// <summary>A write was replayed without the peer's credential, so the denial is not an authz result.</summary>
    PeerUnauthenticated
}

/// <summary>Result of <see cref="AuthzVerdictEvaluator.Evaluate"/>: kind, confidence, and a human-readable reason.</summary>
public sealed class AuthzVerdict
{
    public required AuthzVerdictKind Kind { get; init; }

    /// <summary>"low" | "medium" | "high" — how much weight to give this verdict without further probing.</summary>
    public required string Confidence { get; init; }

    public required string Reason { get; init; }
}

/// <summary>
/// Pure, side-effect-free classification of a single owner-vs-peer replay pair into an
/// <see cref="AuthzVerdict"/>. Reuses the same status/redirect-denial and body-matching primitives
/// as <c>authz/diff</c> (<see cref="AuthzComparisonService"/>, <see cref="AuthzBodyMatcher"/>) so the
/// on-demand comparison and the live shadow agree on what "looks the same" means.
/// </summary>
public static class AuthzVerdictEvaluator
{
    public static AuthzVerdict Evaluate(
        DirectFetchHelper.DirectFetchResult owner,
        DirectFetchHelper.DirectFetchResult peer,
        IReadOnlyList<string>? ownerTokens = null,
        string? requestUrl = null)
    {
        ownerTokens = TokensThatIdentifyTheOwner(ownerTokens ?? [], requestUrl);

        var ownerBody = owner.Error != null ? "" : owner.Body;
        var peerBody = peer.Error != null ? "" : peer.Body;
        var ownerStatus = owner.Error != null ? 0 : owner.Status;
        var peerStatus = peer.Error != null ? 0 : peer.Status;
        var ownerOk = ownerStatus is >= 200 and < 300;
        var peerOk = peerStatus is >= 200 and < 300;

        if (!ownerOk)
            return Result(AuthzVerdictKind.Inconclusive, "low",
                $"Owner baseline was not a 2xx response (status {ownerStatus}); cannot judge cross-identity access.");

        if (peer.Error != null)
            return Result(AuthzVerdictKind.Inconclusive, "low", $"Peer fetch failed: {peer.Error}");

        if (peerStatus is 429 or 503)
            return Result(AuthzVerdictKind.Inconclusive, "low",
                $"Peer responded {peerStatus} (rate-limited/unavailable) — not a denial signal.");

        var peerDenied = peerStatus is 401 or 403 or 404;
        var peerRedirectDenied = !peerDenied && peerOk && peer.Redirected && peer.FinalUrl != null
            && AuthzComparisonService.AuthzLooksLikeDenialRedirect(peer.FinalUrl, peerBody);

        if (peerDenied)
            return Result(AuthzVerdictKind.ProperlyDenied, "high",
                $"Peer got HTTP {peerStatus} while the owner session succeeded — access correctly denied.");
        if (peerRedirectDenied)
            return Result(AuthzVerdictKind.ProperlyDenied, "medium",
                "Peer was redirected to a login/denial page while the owner session succeeded.");

        if (!peerOk)
            return Result(AuthzVerdictKind.Inconclusive, "low", $"Peer response was inconclusive (status {peerStatus}).");

        // Both sides "succeeded" from here on — decide whether the peer actually saw the owner's data.
        if (string.IsNullOrWhiteSpace(ownerBody) && string.IsNullOrWhiteSpace(peerBody))
            return Result(AuthzVerdictKind.NeedsReview, "low",
                "Both owner and peer bodies are empty (e.g. 204 No Content) — nothing to compare for leakage.");

        if (LooksUndecoded(ownerBody) || LooksUndecoded(peerBody))
            return Result(AuthzVerdictKind.Inconclusive, "low",
                "A response body was not decoded text (compressed or binary), so content cannot be compared.");

        if (ownerTokens.Count > 0)
        {
            var matched = ownerTokens
                .Where(t => !string.IsNullOrWhiteSpace(t) && peerBody.Contains(t, StringComparison.OrdinalIgnoreCase))
                .Take(3)
                .ToList();
            if (matched.Count > 0)
                return Result(AuthzVerdictKind.ConfirmedLeak, "high",
                    $"Peer response contains owner-identifying token(s): {string.Join(", ", matched)}.");
        }

        var normalizedOptions = new AuthzBodyMatchOptions { Strategy = AuthzBodyMatchStrategy.NormalizedJson };
        if (AuthzBodyMatcher.BodiesMatch(ownerBody, peerBody, normalizedOptions))
            return Result(AuthzVerdictKind.BolaSuspected, "high",
                "Peer received a response byte-identical to the owner's after normalizing volatile fields.");

        if (AuthzBodyMatcher.NonJsonBodiesMatchWithLengthTolerance(ownerBody, peerBody))
            return Result(AuthzVerdictKind.BolaSuspected, "medium",
                "Non-JSON bodies for owner and peer have matching status and near-identical length.");

        var structuralOptions = new AuthzBodyMatchOptions { Strategy = AuthzBodyMatchStrategy.Structural };
        if (AuthzBodyMatcher.BodiesMatch(ownerBody, peerBody, structuralOptions))
        {
            var ownObject = PeerHasDifferentEmail(ownerTokens, peerBody);
            return Result(AuthzVerdictKind.SameShapeDifferentData, "medium",
                ownObject
                    ? "Each identity received its own object."
                    : "Peer received a response with the same JSON shape as the owner's but different values — " +
                      "could be the peer's own equivalent resource, or a partial leak. Needs classification to disambiguate.");
        }

        return Result(AuthzVerdictKind.FilteredResponse, "low",
            "Both sessions got a 2xx response with different content. Different content is not proof the peer only saw its own data.");
    }

    /// <summary>
    /// True when a body is still compressed or otherwise not text. Gzip mis-read as a string
    /// starts with 0x1F and contains NULs; UTF-8 replacement characters pile up in the rest.
    /// </summary>
    internal static bool LooksUndecoded(string? body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        if (body[0] == '\x1f' || body.Contains('\0')) return true;

        var n = Math.Min(body.Length, 256);
        var replacements = 0;
        for (var i = 0; i < n; i++)
        {
            if (body[i] == '\uFFFD') replacements++;
        }
        return replacements * 5 > n;
    }

    /// <summary>
    /// A record id that is already in the replayed URL, or a bare number, is the object that was
    /// requested. It is not proof the peer saw the victim.
    /// </summary>
    internal static IReadOnlyList<string> TokensThatIdentifyTheOwner(IReadOnlyList<string> tokens, string? requestUrl)
    {
        if (tokens.Count == 0) return tokens;
        var segments = UrlValues(requestUrl);
        var kept = new List<string>(tokens.Count);
        foreach (var token in tokens)
        {
            if (string.IsNullOrWhiteSpace(token)) continue;
            if (token.All(char.IsDigit)) continue;
            if (segments.Contains(token)) continue;
            kept.Add(token);
        }
        return kept;
    }

    private static HashSet<string> UrlValues(string? url)
    {
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(url)) return values;

        var path = url;
        var query = "";
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            path = uri.AbsolutePath;
            query = uri.Query;
        }
        else
        {
            var q = url.IndexOf('?');
            if (q >= 0)
            {
                path = url[..q];
                query = url[q..];
            }
        }

        foreach (var segment in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            try { values.Add(Uri.UnescapeDataString(segment)); }
            catch (UriFormatException) { values.Add(segment); }
        }

        if (query.Length > 1)
        {
            foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = pair.IndexOf('=');
                var val = eq >= 0 ? pair[(eq + 1)..] : pair;
                try { values.Add(Uri.UnescapeDataString(val)); }
                catch (UriFormatException) { values.Add(val); }
            }
        }

        return values;
    }

    private static readonly System.Text.RegularExpressions.Regex EmailInBody = new(
        @"[\w.+-]+@[\w-]+\.[\w.-]+",
        System.Text.RegularExpressions.RegexOptions.Compiled);

    private static bool PeerHasDifferentEmail(IReadOnlyList<string> ownerTokens, string peerBody)
    {
        var ownerEmails = ownerTokens.Where(t => t.Contains('@')).ToList();
        if (ownerEmails.Count == 0 || string.IsNullOrEmpty(peerBody)) return false;
        foreach (System.Text.RegularExpressions.Match match in EmailInBody.Matches(peerBody))
        {
            if (!ownerEmails.Any(e => e.Equals(match.Value, StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }

    private static AuthzVerdict Result(AuthzVerdictKind kind, string confidence, string reason) =>
        new() { Kind = kind, Confidence = confidence, Reason = reason };
}
