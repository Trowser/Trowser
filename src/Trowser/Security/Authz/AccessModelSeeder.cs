namespace Trowser.Security.Authz;

/// <summary>
/// Pre-fills <see cref="AccessModelResource"/> entries from the attack surface map so the access
/// model starts non-empty without prompts. Every seeded entry is <see cref="AccessSource.Heuristic"/> with low
/// confidence and is never overwritten once a human/AI has classified the resource.
/// </summary>
public static class AccessModelSeeder
{
    private static readonly string[] PublicNouns =
    [
        "/blog", "/post", "/article", "/catalog", "/product", "/category", "/page",
        "/news", "/event", "/faq", "/doc", "/help", "/about", "/contact", "/terms", "/privacy"
    ];

    private static readonly string[] AdminNouns = ["/admin", "/config", "/settings", "/manage", "/internal"];

    private static readonly string[] PerUserNouns =
    [
        "/order", "/account", "/profile", "/basket", "/cart", "/invoice", "/payment",
        "/message", "/notification", "/document", "/file", "/ticket", "/booking"
    ];

    /// <summary>
    /// Seed (or refresh) heuristic entries for every endpoint in <paramref name="endpoints"/> that
    /// the model does not already have a non-heuristic classification for. Returns the number of
    /// resources added or refreshed.
    /// </summary>
    public static int Seed(AccessModel model, IEnumerable<AttackSurfaceEndpoint> endpoints)
    {
        var seeded = 0;
        foreach (var ep in endpoints)
        {
            foreach (var method in ep.Methods.Count > 0 ? ep.Methods : ["GET"])
            {
                var existing = model.FindResource(method, ep.UrlTemplate);
                // Never clobber a human/AI/observed classification with a heuristic re-seed.
                if (existing != null && existing.Source != AccessSource.Heuristic)
                    continue;

                var (sensitivity, ownership, confidence, notes) = Classify(ep);
                model.Resources[AccessModelResource.KeyOf(method, ep.UrlTemplate)] = new AccessModelResource
                {
                    Method = method,
                    UrlTemplate = ep.UrlTemplate,
                    Sensitivity = sensitivity,
                    Ownership = ownership,
                    Source = AccessSource.Heuristic,
                    Confidence = confidence,
                    Notes = notes
                };
                seeded++;
            }
        }

        return seeded;
    }

    private static (AccessSensitivity Sensitivity, AccessOwnership Ownership, double Confidence, string? Notes) Classify(
        AttackSurfaceEndpoint ep)
    {
        var lower = ep.UrlTemplate.ToLowerInvariant();
        var hasPathParam = ep.Parameters.Path.Count > 0 || lower.Contains("{id}") || lower.Contains("{param}");
        var isPublicNoun = PublicNouns.Any(n => lower.Contains(n));
        var isAdminNoun = AdminNouns.Any(n => lower.Contains(n));
        var isPerUserNoun = PerUserNouns.Any(n => lower.Contains(n));
        var authRequired = ep.Auth.Required;
        var highPriority = ep.TestPriority is "high" or "critical";

        // Admin/config surface: role-gated, sensitive by default.
        if (isAdminNoun)
            return (AccessSensitivity.Sensitive, AccessOwnership.RoleGated, 0.35,
                "Heuristic: admin/config path noun.");

        // Per-user nouns beat public nouns, so /catalog/cart is a cart and not a catalog page.
        // Auth.Required is often false when the only traffic seen was an already-logged-in session —
        // a 200 from the owner is not evidence the resource is public.
        if (isPerUserNoun)
        {
            var confidence = authRequired ? (hasPathParam ? 0.4 : 0.3) : 0.25;
            var notes = authRequired
                ? "Heuristic: per-user path noun."
                : "Heuristic: per-user path noun. Authentication was not observed; the owner session may already have been logged in.";
            return (AccessSensitivity.Sensitive, AccessOwnership.PerUser, confidence, notes);
        }

        if (isPublicNoun)
            return (AccessSensitivity.Public, AccessOwnership.Shared, authRequired ? 0.3 : 0.4,
                "Heuristic: content-noun path.");

        // Authenticated + path id, but noun unclear → likely per-user, lower confidence.
        if (authRequired && hasPathParam)
            return (AccessSensitivity.Internal, AccessOwnership.PerUser, 0.25,
                "Heuristic: authenticated endpoint with a path identifier; ownership unconfirmed.");

        // High-priority (credential-sensitive response, write endpoint, etc.) but no other signal.
        if (highPriority && authRequired)
            return (AccessSensitivity.Sensitive, AccessOwnership.Unknown, 0.3,
                "Heuristic: high test-priority authenticated endpoint.");

        if (authRequired)
            return (AccessSensitivity.Unknown, AccessOwnership.Unknown, 0.1,
                "Heuristic: authenticated endpoint with no distinguishing signal — needs classification.");

        // No auth signal and no public-content noun. Leave unclassified. Assuming "public"
        // marks orders and accounts as allow-anyone after a logged-in browse.
        return (AccessSensitivity.Unknown, AccessOwnership.Unknown, 0.1,
            "Heuristic: no authentication observed and the path is not a known public-content noun.");
    }
}
