namespace Trowser.Security;

/// <summary>
/// Evaluates CSRF probe outcomes using response bodies — HTTP 200 alone is not treated as success
/// when apps silently re-render forms (e.g. DVWA Impossible).
/// </summary>
public static class CsrfProbeResponseEvaluator
{
    public sealed class Evaluation
    {
        public bool Vulnerable { get; init; }
        public string Severity { get; init; } = "info";
        public string Summary { get; init; } = "";
    }

    /// <summary>
    /// True when a same-session replay that dropped custom headers was refused.
    /// 401 and 403 count even without the word "csrf": the browser still sent cookies, so the removed headers are what changed.
    /// A 200/202 whose body says the token check failed counts too.
    /// </summary>
    public static bool CustomHeaderReplayRejected(int status, string? body) =>
        status is 401 or 403 || InsecureDesignProbeSupport.LooksLikeCsrfRejection(status, body);

    /// <summary>
    /// HTML form that already has an anti-CSRF field. A 2xx/3xx without a CSRF rejection means the
    /// token was not enforced. This is a different claim from "no token was observed".
    /// </summary>
    public static Evaluation EvaluateFormTokenProbe(int probeStatus, string? probeBody)
    {
        if (probeStatus <= 0)
        {
            return new Evaluation
            {
                Vulnerable = false,
                Severity = "info",
                Summary = $"request failed (HTTP {probeStatus})."
            };
        }

        if (probeStatus is 401 or 403 || InsecureDesignProbeSupport.LooksLikeCsrfRejection(probeStatus, probeBody))
        {
            return new Evaluation
            {
                Vulnerable = false,
                Severity = "info",
                Summary = $"server rejected the token check (HTTP {probeStatus})."
            };
        }

        if (probeStatus >= 400)
        {
            return new Evaluation
            {
                Vulnerable = false,
                Severity = "info",
                Summary = $"returned HTTP {probeStatus}."
            };
        }

        var success = BodySuggestsMutationSuccess(probeBody ?? "");
        return new Evaluation
        {
            Vulnerable = true,
            Severity = success ? "high" : "medium",
            Summary = success
                ? $"server accepted an invalid or missing anti-CSRF value (HTTP {probeStatus}) and the response looks successful."
                : $"server accepted an invalid or missing anti-CSRF value (HTTP {probeStatus}) with no CSRF rejection. Confirm the action actually applied."
        };
    }

    /// <summary>
    /// Compares a token-stripped JSON probe against the baseline (with token).
    /// </summary>
    public static Evaluation EvaluateMissingTokenProbe(
        int baselineStatus,
        string? baselineBody,
        int probeStatus,
        string? probeBody)
    {
        if (probeStatus < 200 || probeStatus >= 300)
        {
            return new Evaluation
            {
                Vulnerable = false,
                Severity = "info",
                Summary = $"returned HTTP {probeStatus}."
            };
        }

        if (InsecureDesignProbeSupport.LooksLikeCsrfRejection(probeStatus, probeBody))
        {
            return new Evaluation
            {
                Vulnerable = false,
                Severity = "info",
                Summary =
                    "returned HTTP 200 but the response indicates CSRF/token validation failure — " +
                    "no evidence the state-changing action succeeded."
            };
        }

        var baseText = baselineBody ?? "";
        var probeText = probeBody ?? "";
        var baseHash = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(baseText);
        var probeHash = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(probeText);

        if (baseHash == probeHash)
        {
            return new Evaluation
            {
                Vulnerable = false,
                Severity = "low",
                Summary =
                    "returned HTTP 200 but the response body matches the baseline (no detectable state change). " +
                    "Manual verification recommended — some applications return 200 when silently rejecting invalid requests."
            };
        }

        var baseSuccess = BodySuggestsMutationSuccess(baseText);
        var probeSuccess = BodySuggestsMutationSuccess(probeText);
        var probeFailure = BodySuggestsMutationFailure(probeText);

        if (baseSuccess && probeSuccess)
        {
            return new Evaluation
            {
                Vulnerable = true,
                Severity = "high",
                Summary =
                    "response contains success indicators with and without the CSRF token — " +
                    "the JSON endpoint may accept forged requests."
            };
        }

        if (probeSuccess && !baseSuccess)
        {
            return new Evaluation
            {
                Vulnerable = true,
                Severity = "medium",
                Summary =
                    "token-stripped probe shows success indicators while the baseline did not — review manually."
            };
        }

        if (baseSuccess && !probeSuccess)
        {
            return new Evaluation
            {
                Vulnerable = false,
                Severity = "info",
                Summary =
                    "baseline shows success indicators but the token-stripped probe did not — CSRF protection may be effective."
            };
        }

        if (probeFailure)
        {
            return new Evaluation
            {
                Vulnerable = false,
                Severity = "info",
                Summary =
                    "returned HTTP 200 but the response contains failure/validation indicators — " +
                    "no evidence the state-changing action succeeded."
            };
        }

        return new Evaluation
        {
            Vulnerable = false,
            Severity = "low",
            Summary =
                "returned HTTP 200 without CSRF token but no success indicators were detected in the response body. " +
                "Manual verification recommended — status code alone is not reliable for this endpoint."
        };
    }

    internal static bool BodySuggestsMutationSuccess(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        return ContainsAny(body,
            "password changed", "password has been changed", "successfully changed",
            "successfully updated", "successfully saved", "successfully created",
            "successfully deleted", "has been updated", "has been saved", "has been created",
            "has been deleted", "operation successful", "changes saved", "record updated",
            "update successful", "delete successful", "created successfully", "updated successfully",
            "saved successfully", "deleted successfully", "change successful");
    }

    internal static bool BodySuggestsMutationFailure(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        return ContainsAny(body,
            "error", "failed", "failure", "invalid", "incorrect", "denied", "forbidden",
            "not allowed", "missing", "required field", "please enter", "must provide",
            "validation error", "bad request", "unable to", "could not", "cannot ",
            "wrong password", "passwords do not match", "does not match",
            "csrf", "anti-forgery", "token mismatch", "token is incorrect");
    }

    private static bool ContainsAny(string haystack, params string[] needles)
    {
        foreach (var needle in needles)
        {
            if (haystack.Contains(needle, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
