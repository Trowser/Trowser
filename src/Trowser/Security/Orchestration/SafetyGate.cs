using System.Text.Json;
using Trowser.Api;

namespace Trowser.Security.Orchestration;

/// <summary>
/// Structured safety-gate refusal with fields echoed in REST/MCP error JSON.
/// </summary>
internal readonly record struct SafetyGateDenial(
    string Message,
    string RequestedSafetyMode,
    string EffectiveSafetyMode,
    string? CappedBy)
{
    public ApiCommandException ToException(int statusCode = 400) =>
        new(statusCode, Message, RequestedSafetyMode, EffectiveSafetyMode, CappedBy);
}

/// <summary>
/// Centralized safety mode resolution for all security endpoints.
/// Accepts the new <c>safetyMode</c> parameter and bridges the legacy
/// <c>confirmBackend</c> / <c>safeDefaults</c> / <c>readOnlyProbes</c> flags.
/// CLI globals (<c>--safe-probes-only</c>, <c>--dangerous-ok</c>) are applied as a ceiling.
/// </summary>
internal static class SafetyGate
{
    /// <summary>
    /// Resolve effective safety mode from MCP tool arguments.
    /// Precedence: explicit safetyMode > confirmBackend bridge > default (safe).
    /// CLI --safe-probes-only caps the result.
    /// </summary>
    public static SafetyMode Resolve(JsonElement args)
        => ApplyCliCeiling(ResolveRequested(args));

    /// <summary>
    /// Resolve effective safety mode from REST JSON body.
    /// </summary>
    public static SafetyMode Resolve(JsonBody body)
        => ApplyCliCeiling(ResolveRequested(body));

    /// <summary>Requested mode from MCP args before CLI ceiling.</summary>
    public static SafetyMode ResolveRequested(JsonElement args) =>
        Resolve(
            GetString(args, "safetyMode"),
            GetBool(args, "confirmBackend"),
            GetBool(args, "safeDefaults"),
            GetBool(args, "readOnlyProbes"));

    /// <summary>Requested mode from REST body before CLI ceiling.</summary>
    public static SafetyMode ResolveRequested(JsonBody body) =>
        Resolve(
            body.GetString("safetyMode"),
            body.HasProperty("confirmBackend") ? body.GetBool("confirmBackend", false) : null,
            body.HasProperty("safeDefaults") ? body.GetBool("safeDefaults", false) : null,
            body.HasProperty("readOnlyProbes") ? body.GetBool("readOnlyProbes", false) : null);

    /// <summary>
    /// Require at least the given mode. Returns null if allowed, or a structured denial if blocked.
    /// When requested/effective are not tracked separately, pass the same value for both.
    /// </summary>
    public static SafetyGateDenial? RequireAtLeast(
        SafetyMode requested,
        SafetyMode effective,
        SafetyMode minimum,
        string toolDescription)
    {
        if (effective >= minimum)
            return null;

        return BuildDenial(requested, effective, minimum, toolDescription);
    }

    public static SafetyGateDenial? RequireAtLeast(
        SafetyMode effective,
        SafetyMode minimum,
        string toolDescription)
        => RequireAtLeast(effective, effective, minimum, toolDescription);

    /// <summary>Shorthand: resolve from args and gate at Active.</summary>
    public static SafetyGateDenial? RequireActive(JsonElement args, string toolDescription)
    {
        var requested = ResolveRequested(args);
        return RequireAtLeast(requested, ApplyCliCeiling(requested), SafetyMode.Active, toolDescription);
    }

    /// <summary>Shorthand: resolve from body and gate at Active.</summary>
    public static SafetyGateDenial? RequireActive(JsonBody body, string toolDescription)
    {
        var requested = ResolveRequested(body);
        return RequireAtLeast(requested, ApplyCliCeiling(requested), SafetyMode.Active, toolDescription);
    }

    /// <summary>
    /// True when oauth-flow-test should skip active authorize/token probes (network log only).
    /// </summary>
    internal static bool OAuthFlowTestIsPassiveOnly(JsonBody body)
    {
        if (body.GetBool("passiveOnly"))
            return true;

        var sm = body.GetString("safetyMode");
        return !string.IsNullOrWhiteSpace(sm) && SafetyModeExtensions.Parse(sm) == SafetyMode.Passive;
    }

    private static SafetyGateDenial BuildDenial(
        SafetyMode requested,
        SafetyMode effective,
        SafetyMode minimum,
        string toolDescription)
    {
        var cappedBy = GetCappedBy(requested, effective);
        var reqLabel = requested.ToLabel();
        var effLabel = effective.ToLabel();
        var minLabel = minimum.ToLabel();

        string message;
        if (cappedBy != null && requested >= minimum)
        {
            message =
                $"{toolDescription} requires safetyMode '{minLabel}' or higher " +
                $"(requested: '{reqLabel}', effective: '{effLabel}'). " +
                $"This instance caps safetyMode because it was started with {cappedBy}; " +
                "the request body cannot raise that ceiling. " +
                $"Restart Trowser without {cappedBy} to run active probes.";
        }
        else if (cappedBy != null && requested > effective)
        {
            message =
                $"{toolDescription} requires safetyMode '{minLabel}' or higher " +
                $"(requested: '{reqLabel}', effective: '{effLabel}'). " +
                $"Effective mode is capped by startup flag {cappedBy}. " +
                HintForMinimum(minimum, requested);
        }
        else
        {
            message =
                $"{toolDescription} requires safetyMode '{minLabel}' or higher " +
                $"(requested: '{reqLabel}', effective: '{effLabel}'). " +
                HintForMinimum(minimum, requested);
        }

        return new SafetyGateDenial(message, reqLabel, effLabel, cappedBy);
    }

    private static string HintForMinimum(SafetyMode minimum, SafetyMode requested) =>
        minimum switch
        {
            SafetyMode.Active when requested == SafetyMode.Passive =>
                "Use passiveOnly: true (or safetyMode: \"passive\") for network-log analysis only, " +
                "or set safetyMode: \"active\" for authorize/token probes.",
            SafetyMode.Active =>
                "Set safetyMode: \"active\" (or confirmBackend: true) to proceed.",
            SafetyMode.Aggressive =>
                "Set safetyMode: \"aggressive\" to proceed.",
            _ => ""
        };

    private static string? GetCappedBy(SafetyMode requested, SafetyMode effective)
    {
        if (App.Api.SafeSecurityProbesOnly && requested > SafetyMode.Safe && effective <= SafetyMode.Safe)
            return "--safe-probes-only";
        return null;
    }

    private static SafetyMode Resolve(string? safetyMode, bool? confirmBackend, bool? safeDefaults, bool? readOnlyProbes)
    {
        if (!string.IsNullOrWhiteSpace(safetyMode))
            return SafetyModeExtensions.Parse(safetyMode);

        if (confirmBackend == true)
            return SafetyMode.Active;

        if (safeDefaults == true || readOnlyProbes == true)
            return SafetyMode.Safe;

        return SafetyMode.Safe;
    }

    private static SafetyMode ApplyCliCeiling(SafetyMode requested)
    {
        if (App.Api.SafeSecurityProbesOnly && requested > SafetyMode.Safe)
            return SafetyMode.Safe;

        return requested;
    }

    private static string? GetString(JsonElement args, string prop)
    {
        if (args.ValueKind != JsonValueKind.Object) return null;
        return args.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;
    }

    private static bool? GetBool(JsonElement args, string prop)
    {
        if (args.ValueKind != JsonValueKind.Object) return null;
        if (!args.TryGetProperty(prop, out var v)) return null;
        return v.ValueKind == JsonValueKind.True;
    }
}
