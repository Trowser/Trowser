using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Turns a client-surface snapshot into a fixed checklist of browser-side bug classes.
/// Clues only: it does not run XS-Leaks, gadget chains, CSTI, or other active probes.
/// </summary>
public static class ClientSurfaceRiskPlanner
{
    public const string Dismiss = "dismiss";
    public const string Lead = "lead";
    public const string Pursue = "pursue";
    public const string Manual = "manual";
    /// <summary>Required evidence was not collected; not a clearance to skip the class.</summary>
    public const string NotObserved = "not-observed";

    private static readonly string[] ExecSinks =
    [
        "eval", "Function", "Function.constructor", "AsyncFunction",
        "document.write", "document.writeln", "Document.prototype.write", "Document.prototype.writeln",
        "innerHTML", "outerHTML", "insertAdjacentHTML", "shadowRoot.innerHTML",
        "setHTMLUnsafe", "Document.parseHTMLUnsafe", "createContextualFragment",
        "script.text", "script.src", "script.append", "iframe.srcdoc",
        "setTimeout(string)", "setInterval(string)",
        "jquery.html", "jquery.parseHTML", "jquery.globalEval", "DOMParser.parseFromString"
    ];

    private static readonly string[] MarkupSinks =
    [
        "innerHTML", "outerHTML", "insertAdjacentHTML", "shadowRoot.innerHTML",
        "document.write", "document.writeln", "Document.prototype.write", "Document.prototype.writeln",
        "setHTMLUnsafe", "Document.parseHTMLUnsafe", "createContextualFragment",
        "jquery.html", "jquery.append", "jquery.parseHTML", "DOMParser.parseFromString"
    ];

    private static readonly string[] NavSinks =
    [
        "location.assign", "location.replace", "location.href", "window.open"
    ];

    private static readonly string[] RequestSinks = ["fetch", "xhr.open"];

    public static ClientSurfaceRiskPlan Build(ClientSurfaceRiskEvidence evidence)
    {
        evidence ??= new ClientSurfaceRiskEvidence();
        var risks = new List<ClientSurfaceRisk>
        {
            XsLeaks(evidence),
            DomXss(evidence),
            ClientCsrf(evidence),
            PostMessage(evidence),
            ClientPrototypePollution(evidence),
            DomClobbering(evidence),
            DomOpenRedirect(evidence),
            ClientAuthz(evidence),
            ClientHtmlInjection(evidence),
            Csti(evidence),
            WebStorage(evidence),
            FrontendLogic(),
            ReverseTabnabbing(evidence),
            Xssi(evidence),
            ServiceWorker(evidence),
            Clickjacking(evidence),
            Cors(evidence),
            CssInjection(evidence),
            DanglingMarkup(evidence),
            TrustedTypes(evidence),
            WebSocket(evidence)
        };

        var next = new List<string>();
        foreach (var status in new[] { Pursue, Lead, Manual, NotObserved })
        {
            foreach (var risk in risks.Where(r => r.Status == status))
            {
                if (string.IsNullOrWhiteSpace(risk.FollowUp)) continue;
                next.Add($"{risk.Title}: {risk.FollowUp}");
            }
        }

        if (next.Count == 0)
        {
            next.Add(SecurityNextActions.ClientSurface +
                     " after browsing key flows with Shadow runtime enabled");
        }

        return new ClientSurfaceRiskPlan
        {
            Risks = risks,
            NextActions = next.Distinct(StringComparer.OrdinalIgnoreCase).Take(24).ToList()
        };
    }

    private static ClientSurfaceRisk XsLeaks(ClientSurfaceRiskEvidence e)
    {
        var net = e.Network;
        if (net.StrongIsolation)
        {
            return Row("xs-leaks", "XS-Leaks", Dismiss,
                $"Document isolation is in place ({net.IsolationDetail}). Skip XS-Leaks unless you have a cache or timing question the headers do not close.",
                null);
        }

        if (net.Empty)
        {
            return Row("xs-leaks", "XS-Leaks", Lead,
                "No document response in the network log, so COOP, COEP, and CORP were not checked. Run XS-Leaks only when two states differ (login, or search hit versus miss).",
                SecurityNextActions.XsLeaks);
        }

        if (net.HasCrossOriginEmbed || net.HasStatePair)
        {
            if (net.HasStatePair && e.HasPageLocalXsLead)
            {
                var pathHint = string.IsNullOrWhiteSpace(net.StatePairPath) ? "an API path" : net.StatePairPath;
                return Row("xs-leaks", "XS-Leaks", Manual,
                    $"Earlier in this session, {pathHint} returned different responses (status or body), but this page has a stronger local signal (WebSocket, service worker, or similar). Prefer that follow-up first; run XS-Leaks when this document loads cross-origin probes or secret-dependent fetches.",
                    SecurityNextActions.XsLeaks);
            }

            var why = net.HasStatePair
                ? (string.IsNullOrWhiteSpace(net.StatePairPath)
                    ? "The network log already has two responses for the same path that differ."
                    : $"{net.StatePairPath} returned different responses on this document (status or body).")
                : $"This document loads a cross-origin subresource ({net.CrossOriginEmbedDetail}).";
            var headers = string.IsNullOrWhiteSpace(net.IsolationDetail)
                ? "COOP, COEP, and CORP are absent."
                : net.IsolationDetail;
            return Row("xs-leaks", "XS-Leaks", Lead,
                $"{why} {headers} Run XS-Leaks with two secret-dependent states.",
                SecurityNextActions.XsLeaks);
        }

        var absent = string.IsNullOrWhiteSpace(net.IsolationDetail)
            ? "COOP, COEP, and CORP are absent on the document response."
            : net.IsolationDetail;
        return Row("xs-leaks", "XS-Leaks", Manual,
            $"{absent} Missing isolation alone does not pick this page. Lead XS-Leaks when the page loads a cross-origin image, script, or frame, or when the log already shows two states.",
            null);
    }

    private static ClientSurfaceRisk DomXss(ClientSurfaceRiskEvidence e)
    {
        var execFlow = e.Flows.Any(f =>
            f.Tier is not ("noise" or "probe-artifact")
            && f.Consequence is "exec" or "executable-markup"
            && DomFlow.DomFlowGraph.IsAttackerReachableSource(f.Source));
        var confirmedCell = e.Cells.Any(c =>
            c.Status == "confirmed"
            && IsExecSink(c.Sink)
            && IsRealSource(e, c.Source));
        if (execFlow || confirmedCell || (HasExecSink(e) && HasAttackerSource(e)))
        {
            return Row("dom-xss", "DOM XSS", Pursue,
                "An executable sink lines up with attacker-controlled input (URL, hash, storage, postMessage, or window.name) on this load.",
                SecurityNextActions.DomXssAudit);
        }

        if (!e.RuntimeSeen)
        {
            return Row("dom-xss", "DOM XSS", Lead,
                "The runtime sensor did not see this document load, so executable sinks may have been missed. Browse with Shadow runtime, then map again before skipping DOM XSS.",
                SecurityNextActions.DomXssAudit);
        }

        if (HasExecSink(e))
        {
            return Row("dom-xss", "DOM XSS", Lead,
                "Executable sinks ran, but no attacker-controlled source was observed feeding them. Confirm with a DOM XSS audit if query, hash, or storage is part of the flow.",
                SecurityNextActions.DomXssAudit);
        }

        if (e.Script.ExecSinks.Count > 0)
        {
            var names = string.Join(", ", e.Script.ExecSinks.Take(4));
            return Row("dom-xss", "DOM XSS", Lead,
                $"Executable sinks are in the page script ({names}) but did not run on this load. An empty fragment or a click gate still leaves the sink in the source. Do not skip the DOM XSS audit.",
                SecurityNextActions.DomXssAudit);
        }

        return Row("dom-xss", "DOM XSS", Dismiss,
            "No executable sinks were observed on this load, and the page script does not contain innerHTML, eval, document.write, or script insertion either. Skip the DOM XSS audit unless another route renders markup.",
            null);
    }

    private static ClientSurfaceRisk ClientCsrf(ClientSurfaceRiskEvidence e)
    {
        var forged = e.Flows.Any(f =>
            f.Consequence == "request-forgery"
            && f.Tier is not ("noise" or "probe-artifact")
            && DomFlow.DomFlowGraph.IsAttackerReachableSource(f.Source));
        if (forged)
        {
            return Row("client-csrf", "Client-side CSRF", Lead,
                "A fetch or XHR followed attacker-controlled data. That is the page building a request from input, which the server CSRF token check does not cover. Navigate once with a canary and diff the request.",
                RequestProbeFollowUp(e.Script));
        }

        if (e.Script.LocationDrivenRequest
            || (HasAny(e.Sinks, RequestSinks) && HasAttackerSource(e)))
        {
            return Row("client-csrf", "Client-side CSRF", Lead,
                "Script reads location, the hash, or postMessage and issues a fetch or XHR. The server CSRF scanner does not test that. Navigate once with a canary and diff the request.",
                RequestProbeFollowUp(e.Script));
        }

        if (!e.RuntimeSeen && e.Network.Empty)
        {
            return Row("client-csrf", "Client-side CSRF", Lead,
                "No fetch/XHR sinks and no captured requests. Browse a state-changing action before deciding this class is absent.",
                null);
        }

        if (TriageIncomplete(e))
        {
            return Row("client-csrf", "Client-side CSRF", NotObserved,
                "Not observed: the runtime sensor did not record this load (or external script was not fully scanned), so location-driven fetch/XHR cannot be ruled out.",
                RequestProbeFollowUp(e.Script));
        }

        return Row("client-csrf", "Client-side CSRF", Dismiss,
            "No fetch or XHR is driven by location, the hash, or postMessage. Static files and ordinary API calls are not client-side CSRF. Skip it on this page.",
            null);
    }

    private static ClientSurfaceRisk PostMessage(ClientSurfaceRiskEvidence e)
    {
        var messages = e.Listeners
            .Where(l => l.Type.Equals("message", StringComparison.OrdinalIgnoreCase)
                        && !l.OriginCheck.Equals("instrumentation", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (messages.Any(l => l.OriginCheck is not "strict"))
        {
            var grades = string.Join(", ", messages.Select(l => l.OriginCheck).Distinct());
            return Row("postmessage", "postMessage", Pursue,
                $"Message listener origin check is {grades}. A missing or weak check is the precondition for a cross-origin message bug.",
                SecurityNextActions.PostMessageAudit);
        }

        if (messages.Count > 0)
        {
            return Row("postmessage", "postMessage", Dismiss,
                "Every observed message listener has a strict origin check. Skip the postMessage audit unless a later route adds another listener.",
                null);
        }

        if (e.SameOriginIframeCount > 0)
        {
            return Row("postmessage", "postMessage", Lead,
                $"{e.SameOriginIframeCount} same-origin iframe(s) are on this page but no message listeners were recorded for them. The runtime sensor may not have instrumented child frames — run the postMessage audit (iframe descent) before skipping.",
                SecurityNextActions.PostMessageAudit);
        }

        if (!e.LoadObserved || !e.RuntimeSeen)
        {
            return Row("postmessage", "postMessage", Lead,
                "No message listeners were recorded. The sensor may have missed listeners registered before it was installed.",
                SecurityNextActions.PostMessageAudit);
        }

        return Row("postmessage", "postMessage", Dismiss,
            "No message listeners were observed on this load. Skip the postMessage audit.",
            null);
    }

    private static ClientSurfaceRisk ClientPrototypePollution(ClientSurfaceRiskEvidence e)
    {
        if (e.ProtoReadCount > 0)
        {
            return Row("client-prototype-pollution", "Client-side prototype pollution", Pursue,
                $"{e.ProtoReadCount} proto-read event(s) show application code reading through Object.prototype.",
                SecurityNextActions.ClientPrototypePollution);
        }

        if (e.Sources.Any(s => s.Contains("JSON.parse", StringComparison.OrdinalIgnoreCase)))
        {
            return Row("client-prototype-pollution", "Client-side prototype pollution", Lead,
                "JSON.parse ran. Client prototype pollution is interesting when that parse includes query, hash, or message data. The active probe confirms it.",
                SecurityNextActions.ClientPrototypePollution);
        }

        if (!e.RuntimeSeen)
        {
            return Row("client-prototype-pollution", "Client-side prototype pollution", Lead,
                "No JSON.parse or proto-read events. Proto-read traps are not on during a normal surface map, so this is not a clear skip until the page has been exercised.",
                SecurityNextActions.ClientPrototypePollution);
        }

        return Row("client-prototype-pollution", "Client-side prototype pollution", Dismiss,
            "No JSON.parse and no proto-read on this load. Skip client prototype pollution unless another route parses attacker JSON. Proto-read traps run only in an explicit gadget-radar session.",
            null);
    }

    private static ClientSurfaceRisk DomClobbering(ClientSurfaceRiskEvidence e)
    {
        if (e.GadgetReadCount > 0)
        {
            return Row("dom-clobbering", "DOM clobbering", Pursue,
                $"{e.GadgetReadCount} missing-global read(s) are in the sensor buffer. Gadget chains can try to clobber those names where HTML is reflected.",
                SecurityNextActions.GadgetChains);
        }

        if (e.Script.GadgetReads.Count > 0)
        {
            var reads = string.Join(", ", e.Script.GadgetReads.Take(4));
            return Row("dom-clobbering", "DOM clobbering", Lead,
                $"Script reads {reads}. A missing global throws on a clean load; that read is still the gadget. Inject a form with a named input before the script, or start the gadget radar before the next navigation.",
                SecurityNextActions.GadgetChains);
        }

        if (e.ClobberIds.Count > 0)
        {
            var ids = string.Join(", ", e.ClobberIds.Take(5));
            return Row("dom-clobbering", "DOM clobbering", Lead,
                $"Duplicate ids or named form access ({ids}). That is a candidate list, not a gadget. Read the gadget radar before running clobber probes.",
                SecurityNextActions.GadgetRadarRead);
        }

        return Row("dom-clobbering", "DOM clobbering", Dismiss,
            "No window.name.prop reads in the page script, no duplicate-id candidates, and no missing-global reads in the radar buffer. Skip clobber probes on this page.",
            null);
    }

    private static ClientSurfaceRisk DomOpenRedirect(ClientSurfaceRiskEvidence e)
    {
        var hijack = e.Flows.Any(f =>
            f.Consequence == "nav-hijack" && f.Tier is not ("noise" or "probe-artifact"));
        if (hijack || (HasAny(e.Sinks, NavSinks) && HasAttackerSource(e)))
        {
            return Row("dom-open-redirect", "DOM open redirect", Pursue,
                "A navigation sink (location or window.open) lines up with attacker-controlled input.",
                e.Script.LocationParams.Any(ClientScriptTextScanner.IsRedirectParam)
                    ? OpenRedirectFollowUp(e.Script)
                    : SecurityNextActions.DomXssAudit);
        }

        if (!e.RuntimeSeen)
        {
            return Row("dom-open-redirect", "DOM open redirect", Lead,
                "Navigation sinks were not observed. Map again after the sensor has seen the load before skipping open redirects.",
                SecurityNextActions.DomFlowsObserve);
        }

        if (HasAny(e.Sinks, NavSinks) || e.Script.NavSinks.Count > 0)
        {
            var where = e.Script.NavSinks.Count > 0 && !HasAny(e.Sinks, NavSinks)
                ? "location or window.open is in the page script and did not run on this load (click or auto gate)."
                : "location or window.open ran, without an attacker-controlled source on this load.";
            return Row("dom-open-redirect", "DOM open redirect", Lead,
                $"{where} Trace redirect-like parameters (next, url, return, to) and pass auto=1 when the script reads that flag.",
                OpenRedirectFollowUp(e.Script));
        }

        return Row("dom-open-redirect", "DOM open redirect", Dismiss,
            "No location or window.open sinks were observed, and the page script does not assign location either. Skip the DOM open-redirect probe on this page.",
            null);
    }

    private static ClientSurfaceRisk ClientAuthz(ClientSurfaceRiskEvidence e)
    {
        var hints = SensitiveNames(e, static n =>
            n.Contains("role", StringComparison.OrdinalIgnoreCase)
            || n.Contains("isadmin", StringComparison.OrdinalIgnoreCase)
            || n.Contains("is_admin", StringComparison.OrdinalIgnoreCase)
            || n.Contains("is-admin", StringComparison.OrdinalIgnoreCase)
            || n.Contains("privilege", StringComparison.OrdinalIgnoreCase));
        if (hints.Count > 0)
        {
            return Row("client-authz", "Client-side authorization", Lead,
                $"Names that look like a client-side role check: {string.Join(", ", hints.Take(6))}. UI-only gates are not covered by server authorization probes.",
                "Inspect route guards and role checks in the page script by hand.");
        }

        return Row("client-authz", "Client-side authorization", Manual,
            "A surface map cannot see authorization that exists only in JavaScript. Do not treat a quiet map as proof the UI enforces nothing, and do not treat it as a finding either.",
            "Inspect route guards by hand when the app hides admin or other-user actions in the client.");
    }

    private static ClientSurfaceRisk ClientHtmlInjection(ClientSurfaceRiskEvidence e)
    {
        if (e.InlineDocumentWrite || HasAny(e.Sinks, MarkupSinks))
        {
            return Row("client-html-injection", "Client-side HTML injection", Lead,
                "Markup sinks or an inline document.write are present (includes dangling-markup and CSS-injection leads via dom-flows — not separate scanners). DOM flows separate markup from exec.",
                SecurityNextActions.DomFlowsObserve);
        }

        if (!e.RuntimeSeen)
        {
            return Row("client-html-injection", "Client-side HTML injection", Lead,
                "No markup sinks were recorded, and the sensor may have missed the load.",
                SecurityNextActions.DomFlowsObserve);
        }

        return Row("client-html-injection", "Client-side HTML injection", Dismiss,
            "No innerHTML, document.write, or other markup sinks on this load. Skip a separate HTML-injection pass.",
            null);
    }

    private static ClientSurfaceRisk Csti(ClientSurfaceRiskEvidence e)
    {
        var engines = TemplateEngineNames(e).ToList();
        var custom = e.Script.CustomTemplate
                     || e.Sinks.Any(s => s.Equals("Function", StringComparison.OrdinalIgnoreCase)
                                         || s.Equals("Function.constructor", StringComparison.OrdinalIgnoreCase));
        if (engines.Count > 0 || custom)
        {
            var why = engines.Count > 0
                ? $"Template-engine signal present: {string.Join(", ", engines)}."
                : "Script compiles a template with Function, {{ }}, or a template literal passed to eval.";
            if (engines.Count > 0 && custom)
                why += " Custom Function / {{ }} compilation is present as well.";
            else if (engines.Count == 0)
                why += " A missing Angular, Vue, or Nuxt global does not clear this.";
            return Row("csti", "Client-side template injection", Pursue,
                $"{why} A CSTI scan is the next step, not this map.",
                SecurityNextActions.CstiScan);
        }

        if (TriageIncomplete(e))
        {
            return Row("csti", "Client-side template injection", NotObserved,
                "Not observed: bundled frameworks may not expose window globals; inline and captured script may be truncated. DOM framework hints and runtime are required before skipping CSTI.",
                SecurityNextActions.CstiScan);
        }

        return Row("csti", "Client-side template injection", Dismiss,
            "No template-engine global or DOM hint, and the page script does not compile templates with Function, {{ }}, or eval of a template literal. Skip client-side template injection.",
            null);
    }

    private static ClientSurfaceRisk WebStorage(ClientSurfaceRiskEvidence e)
    {
        var touched = e.StorageKeysTouched;
        var leftovers = e.StorageKeys
            .Where(k => !touched.Contains(k, StringComparer.OrdinalIgnoreCase))
            .ToList();
        var sensitiveTouched = NamesMatching(touched, IsSensitiveStorageName);
        var sensitiveLeftover = NamesMatching(leftovers, IsSensitiveStorageName);
        if (sensitiveTouched.Count > 0)
        {
            return Row("web-storage", "Web storage", Lead,
                $"This document read or wrote sensitive keys ({string.Join(", ", sensitiveTouched.Take(6))}). Values were not read. Run the storage audit.",
                SecurityNextActions.StorageAudit);
        }

        if (sensitiveLeftover.Count > 0)
        {
            return Row("web-storage", "Web storage", Lead,
                $"Sensitive keys are present in this origin from earlier navigations, not read or written by this document ({string.Join(", ", sensitiveLeftover.Take(6))}). Run the storage audit if this origin is in scope.",
                SecurityNextActions.StorageAudit);
        }

        if (touched.Count > 0 || e.IndexedDbNames.Count > 0)
        {
            var bits = new List<string>();
            if (touched.Count > 0) bits.Add($"this document touched {touched.Count} key(s)");
            if (e.IndexedDbNames.Count > 0) bits.Add($"IndexedDB: {string.Join(", ", e.IndexedDbNames.Take(4))}");
            return Row("web-storage", "Web storage", Lead,
                $"{string.Join("; ", bits)}. Key names were not classified as secrets. Run the storage audit before skipping.",
                SecurityNextActions.StorageAudit);
        }

        if (leftovers.Count > 0)
        {
            return Row("web-storage", "Web storage", Lead,
                $"{leftovers.Count} key(s) are present in this origin from earlier navigations and were not read or written by this document ({string.Join(", ", leftovers.Take(4))}).",
                SecurityNextActions.StorageAudit);
        }

        return Row("web-storage", "Web storage", Dismiss,
            "No localStorage or sessionStorage keys, and no IndexedDB database names were returned. Nothing to harvest until the app writes storage.",
            null);
    }

    private static ClientSurfaceRisk FrontendLogic() =>
        Row("frontend-logic", "Frontend business logic", Manual,
            "Price, quantity, and disabled controls are not classified by this map. A quiet client-surface is not a business-logic pass.",
            "Exercise price, quantity, and hidden-field flows by hand.");

    private static ClientSurfaceRisk ReverseTabnabbing(ClientSurfaceRiskEvidence e)
    {
        if (e.Script.WindowOpenWithoutNoopener)
        {
            return Row("reverse-tabnabbing", "Reverse tabnabbing", Lead,
                "window.open appears in page script without noopener/noreferrer in the call. That can leave window.opener reachable (unlike modern target=_blank anchors). Review and add noopener or use rel on the navigation path.",
                "Review window.open call sites and add noopener,noreferrer.");
        }

        if (e.TabnabbingHygieneCount > 0)
        {
            return Row("reverse-tabnabbing", "Reverse tabnabbing", Manual,
                $"{e.TabnabbingHygieneCount} target=_blank anchor(s) lack explicit rel=noopener/noreferrer. WebView2/Chromium normally applies implicit noopener for anchor target=_blank — this is hardening hygiene, not proof the opener is reachable. No out-of-scope destination was opened.",
                "Add rel=noopener,noreferrer for defense in depth, or run a local opener-topology test on a mocked origin.");
        }

        return Row("reverse-tabnabbing", "Reverse tabnabbing", Dismiss,
            "No target=_blank links missing explicit rel, and no window.open without noopener in scanned script.",
            null);
    }

    private static ClientSurfaceRisk Xssi(ClientSurfaceRiskEvidence e)
    {
        switch (e.Network.Xssi)
        {
            case "lead-array":
                return Row("xssi", "XSSI", Lead,
                    "A same-origin array is served as JSON without nosniff, or as JavaScript. A cross-site script include may be able to read it.",
                    "browser_security_xssi_scan — confirm the array or assignment and missing nosniff.");
            case "lead-jsonp":
                return Row("xssi", "XSSI", Lead,
                    "A captured script is a callback wrapper or assigns data to a global (classic XSSI). Confirm whether it carries authenticated data.",
                    "browser_security_xssi_scan — confirm the callback reflection or assignment.");
            case "unknown-empty":
                return Row("xssi", "XSSI", Lead,
                    "The network log has no responses to judge. Browse authenticated API calls before skipping XSSI.",
                    null);
            case "dismissed-nosniff":
                return Row("xssi", "XSSI", Dismiss,
                    "JSON responses that start with '[' include nosniff, so a script tag should not execute them.",
                    null);
            default:
                return Row("xssi", "XSSI", Dismiss,
                    "No JSON-array or JSONP responses in the captured log. Skip XSSI unless a later call returns an array without nosniff.",
                    null);
        }
    }

    private static ClientSurfaceRisk ServiceWorker(ClientSurfaceRiskEvidence e)
    {
        if (e.ServiceWorkerScopes.Count == 0 && string.IsNullOrWhiteSpace(e.ControllingWorkerScriptUrl))
        {
            return Row("service-worker", "Service workers", Dismiss,
                "No service worker registrations on this origin.",
                null);
        }

        var script = e.ControllingWorkerScriptUrl;
        var scriptBit = string.IsNullOrWhiteSpace(script)
            ? string.Join(", ", e.ServiceWorkerScriptUrls.Take(2))
            : script;
        if (string.IsNullOrWhiteSpace(scriptBit))
            scriptBit = string.Join(", ", e.ServiceWorkerScopes.Take(2));
        if (e.ServiceWorkerRegisteredByDocument)
        {
            return Row("service-worker", "Service workers", Pursue,
                $"This document registers a service worker. Controlling script: {scriptBit}. Scope, importScripts, and caching of authenticated responses need a structured audit.",
                SecurityNextActions.ServiceWorkerAudit);
        }

        return Row("service-worker", "Service workers", Lead,
            $"A service worker is already controlling this origin (script: {scriptBit}). This document did not register it. Audit the controlling script if this origin is in scope; do not treat later pages as the registration.",
            SecurityNextActions.ServiceWorkerAudit);
    }

    private static ClientSurfaceRisk Clickjacking(ClientSurfaceRiskEvidence e)
    {
        return e.Network.Framing switch
        {
            "protected" => Row("clickjacking", "Clickjacking", Dismiss,
                "The document sets X-Frame-Options or CSP frame-ancestors. Skip a clickjacking test unless a child frame opts out.",
                null),
            "absent" => Row("clickjacking", "Clickjacking", Lead,
                "The document response has no X-Frame-Options and no CSP frame-ancestors. A framed page can host a clickjack.",
                SecurityNextActions.ClickjackTest),
            _ => Row("clickjacking", "Clickjacking", Manual,
                "No document response in the network log, so framing headers were not checked.",
                null)
        };
    }

    private static ClientSurfaceRisk Cors(ClientSurfaceRiskEvidence e)
    {
        return e.Network.Cors switch
        {
            "credentialed" => Row("cors", "CORS", Pursue,
                "A response allows any origin and credentials. Confirm which endpoint reflects or wildcards Access-Control-Allow-Origin.",
                SecurityNextActions.CorsScan),
            "wildcard" or "reflected" => Row("cors", "CORS", Lead,
                e.Network.Cors == "wildcard"
                    ? "A captured response sends Access-Control-Allow-Origin: *. Check whether it carries authenticated data."
                    : "A captured response allows a cross-origin Access-Control-Allow-Origin. Check whether the origin is reflected.",
                SecurityNextActions.CorsScan),
            "unknown" => Row("cors", "CORS", Manual,
                "The network log has no responses to judge Access-Control-Allow-Origin.",
                null),
            _ => Row("cors", "CORS", Dismiss,
                "No wildcard or cross-origin Access-Control-Allow-Origin on the captured responses. Skip a CORS scan unless a later API call adds one.",
                null)
        };
    }

    private static ClientSurfaceRisk CssInjection(ClientSurfaceRiskEvidence e)
    {
        if (e.Flows.Any(f => f.Consequence == "css-injection" && f.Tier is not ("noise" or "probe-artifact"))
            || e.Script.StyleSink)
        {
            return Row("css-injection", "CSS injection", Lead,
                "The page writes CSS (cssText, style, or insertRule) or a DOM flow already labeled css-injection. That class is separate from HTML injection.",
                SecurityNextActions.DomFlowsObserve);
        }

        if (TriageIncomplete(e))
        {
            return Row("css-injection", "CSS injection", NotObserved,
                "Not observed: runtime did not record style sinks and external modules may not have been fully scanned.",
                SecurityNextActions.DomFlowsObserve);
        }

        return Row("css-injection", "CSS injection", Dismiss,
            "No style sink in the page script and no css-injection flow. Skip a CSS-injection pass on this page.",
            null);
    }

    private static ClientSurfaceRisk DanglingMarkup(ClientSurfaceRiskEvidence e)
    {
        var flow = e.Flows.Any(f => f.Consequence == "dangling-markup" && f.Tier is not ("noise" or "probe-artifact"));
        if (flow || (e.Script.MarkupSinks.Count > 0 && e.Script.HasAttackerSource))
        {
            return Row("dangling-markup", "Dangling markup", Lead,
                "A markup sink sits next to URL or referrer input, which is the unclosed-attribute case. DOM flows can label it after the sink runs; the script already has both pieces.",
                SecurityNextActions.DomFlowsObserve);
        }

        if (TriageIncomplete(e))
        {
            return Row("dangling-markup", "Dangling markup", NotObserved,
                "Not observed: markup sinks paired with URL input were not seen on this load and script coverage may be incomplete.",
                SecurityNextActions.DomFlowsObserve);
        }

        return Row("dangling-markup", "Dangling markup", Dismiss,
            "No dangling-markup flow, and the page script does not combine a markup sink with location or referrer input.",
            null);
    }

    private static ClientSurfaceRisk TrustedTypes(ClientSurfaceRiskEvidence e)
    {
        var sinks = e.Script.ExecSinks.Count > 0 || e.Script.MarkupSinks.Count > 0 || HasExecSink(e) || HasAny(e.Sinks, MarkupSinks);
        if (e.Network.TrustedTypes == "enforced" && e.Script.CreatesTrustedTypesPolicy)
        {
            return Row("trusted-types", "Trusted Types", Lead,
                "CSP require-trusted-types-for 'script' is set, and the page creates a Trusted Types policy. Check that policy for a sink bypass.",
                SecurityNextActions.DomFlowsObserve);
        }

        if (e.Network.TrustedTypes == "enforced")
        {
            return Row("trusted-types", "Trusted Types", Dismiss,
                "CSP require-trusted-types-for 'script' is set and the page script does not create its own policy.",
                null);
        }

        if (sinks && e.Network.TrustedTypes != "enforced")
        {
            var why = e.Network.TrustedTypes == "absent"
                ? "The document has HTML or script sinks and does not require Trusted Types."
                : "HTML or script sinks are present, and no document response showed require-trusted-types-for 'script'.";
            return Row("trusted-types", "Trusted Types", Lead,
                $"{why} Legacy sinks stay reachable.",
                SecurityNextActions.DomFlowsObserve);
        }

        if (TriageIncomplete(e) || e.Network.TrustedTypes == "unknown")
        {
            return Row("trusted-types", "Trusted Types", NotObserved,
                "Not observed: document CSP was missing from the network log and/or runtime and script scans did not establish whether legacy sinks exist.",
                SecurityNextActions.DomFlowsObserve);
        }

        return Row("trusted-types", "Trusted Types", Dismiss,
            "No HTML or script sinks to enforce on this load, and the document does not require Trusted Types.",
            null);
    }

    private static ClientSurfaceRisk WebSocket(ClientSurfaceRiskEvidence e)
    {
        if (e.WebSocketEvaluates)
        {
            return Row("websocket", "WebSocket", Pursue,
                "A WebSocket message listener compiles or evaluates the payload. That is not a window postMessage listener.",
                SecurityNextActions.WebSocketAudit);
        }

        if (e.WebSocketListeners > 0 || e.Script.UsesWebSocket)
        {
            return Row("websocket", "WebSocket", Lead,
                e.WebSocketListeners > 0
                    ? $"{e.WebSocketListeners} WebSocket message listener(s). Audit the socket; do not file them as postMessage."
                    : "The page script constructs a WebSocket. Audit the socket if the handler is not visible yet.",
                SecurityNextActions.WebSocketAudit);
        }

        return Row("websocket", "WebSocket", Dismiss,
            "No WebSocket constructor and no WebSocket message listener on this page.",
            null);
    }

    private static string RequestProbeFollowUp(ClientScriptTextFacts script)
    {
        if (script.LocationParams.Count > 0)
        {
            var names = string.Join(", ", script.LocationParams.Take(4));
            var source = script.ReadsLocationHash && !script.ReadsLocationSearch ? "url-hash" : "url-query";
            return "POST /api/security/trace-input "
                   + $"(source {source}, queryParam '{script.LocationParams[0]}', monitorSinks true). "
                   + $"Params read from location: {names}. Navigate once with a canary and diff the request.";
        }

        if (script.ReadsLocationHash)
            return "POST /api/security/trace-input (source url-hash, monitorSinks true). Navigate once with a canary fragment and diff the fetch.";

        return SecurityNextActions.TraceInputMonitorSinks;
    }

    private static string OpenRedirectFollowUp(ClientScriptTextFacts script)
    {
        var names = script.LocationParams.Where(ClientScriptTextScanner.IsRedirectParam).Take(4).ToList();
        if (names.Count == 0)
            return SecurityNextActions.DomXssAudit;

        var auto = script.ReadsAutoFlag ? ", extraQuery auto=1" : "";
        return "POST /api/security/trace-input "
               + $"(source url-query, queryParam '{names[0]}', monitorSinks true, fireEvents true{auto}). "
               + $"Redirect-like params in script: {string.Join(", ", names)}.";
    }

    private static bool HasExecSink(ClientSurfaceRiskEvidence e) => HasAny(e.Sinks, ExecSinks);
    private static bool HasAttackerSource(ClientSurfaceRiskEvidence e) =>
        e.Sources.Any(IsAttackerSourceName);

    private static bool IsRealSource(ClientSurfaceRiskEvidence e, string source) =>
        e.Sources.Any(s => s.Equals(source, StringComparison.OrdinalIgnoreCase))
        || (source.Equals("postMessage", StringComparison.OrdinalIgnoreCase)
            && e.Listeners.Any(l => l.Type.Equals("message", StringComparison.OrdinalIgnoreCase)));

    private static bool IsAttackerSourceName(string name)
    {
        var s = name.ToLowerInvariant();
        return s.Contains("location") || s.Contains("hash") || s.Contains("search")
               || s.Contains("url") || s.Contains("postmessage") || s.Contains("storage")
               || s.Contains("window.name") || s.Contains("referrer") || s.Contains("indexeddb");
    }

    private static bool IsExecSink(string sink) =>
        ExecSinks.Any(s => s.Equals(sink, StringComparison.OrdinalIgnoreCase));

    private static bool IsTemplateEngine(string global) =>
        global.Equals("angular", StringComparison.OrdinalIgnoreCase)
        || global.Equals("ng", StringComparison.OrdinalIgnoreCase)
        || global.Equals("Vue", StringComparison.OrdinalIgnoreCase)
        || global.Equals("__NUXT__", StringComparison.OrdinalIgnoreCase)
        || global.StartsWith("ng-version=", StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<string> TemplateEngineNames(ClientSurfaceRiskEvidence e)
    {
        foreach (var g in e.FrameworkGlobals.Where(IsTemplateEngine))
            yield return g;
        foreach (var hint in e.DomFrameworkHints.Where(h => h.StartsWith("ng-version=", StringComparison.OrdinalIgnoreCase)))
        {
            if (!e.FrameworkGlobals.Contains(hint, StringComparer.OrdinalIgnoreCase))
                yield return hint;
        }
    }

    private static bool TriageIncomplete(ClientSurfaceRiskEvidence e) =>
        !e.RuntimeSeen || e.ScriptSurfaceIncomplete;

    private static bool HasAny(IReadOnlyList<string> names, IReadOnlyList<string> wanted) =>
        names.Any(n => wanted.Any(w => w.Equals(n, StringComparison.OrdinalIgnoreCase)));

    private static List<string> NamesMatching(IEnumerable<string> keys, Func<string, bool> match)
    {
        var found = new List<string>();
        foreach (var key in keys)
        {
            var bare = key.StartsWith("local:", StringComparison.OrdinalIgnoreCase) ? key[6..]
                : key.StartsWith("session:", StringComparison.OrdinalIgnoreCase) ? key[8..]
                : key;
            if (match(bare) && !found.Contains(key, StringComparer.OrdinalIgnoreCase))
                found.Add(key);
        }
        return found;
    }

    private static List<string> SensitiveNames(ClientSurfaceRiskEvidence e, Func<string, bool> match)
    {
        var found = new List<string>();
        foreach (var key in e.StorageKeys.Concat(e.IndexedDbNames).Concat(e.FormFieldNames))
        {
            var bare = key.StartsWith("local:", StringComparison.OrdinalIgnoreCase) ? key[6..]
                : key.StartsWith("session:", StringComparison.OrdinalIgnoreCase) ? key[8..]
                : key;
            if (match(bare) && !found.Contains(key, StringComparer.OrdinalIgnoreCase))
                found.Add(key);
        }
        return found;
    }

    private static bool IsSensitiveStorageName(string name)
    {
        var n = name.ToLowerInvariant();
        return n.Contains("token") || n.Contains("jwt") || n.Contains("auth")
               || n.Contains("session") || n.Contains("password") || n.Contains("secret")
               || n.Contains("apikey") || n.Contains("api_key") || n.Contains("bearer")
               || n.Contains("credential");
    }

    private static ClientSurfaceRisk Row(string id, string title, string status, string reason, string? followUp) =>
        new()
        {
            Id = id,
            Title = title,
            Status = status,
            Reason = reason,
            FollowUp = followUp
        };
}

public sealed class ClientSurfaceRiskPlan
{
    public List<ClientSurfaceRisk> Risks { get; init; } = [];
    public List<string> NextActions { get; init; } = [];
}

public sealed class ClientSurfaceRisk
{
    public string Id { get; init; } = "";
    public string Title { get; init; } = "";
    public string Status { get; init; } = "";
    public string Reason { get; init; } = "";
    public string? FollowUp { get; init; }
}

public sealed class ClientSurfaceRiskEvidence
{
    public bool RuntimeSeen { get; init; }
    public List<string> Sources { get; init; } = [];
    public List<string> Sinks { get; init; } = [];
    public List<(string Type, string OriginCheck)> Listeners { get; init; } = [];
    public List<(string Source, string Sink, string Status)> Cells { get; init; } = [];
    public List<(string Source, string Sink, string Consequence, string Tier)> Flows { get; init; } = [];
    public int TabnabbingHygieneCount { get; init; }
    public List<string> DomFrameworkHints { get; init; } = [];
    public bool ScriptSurfaceIncomplete { get; init; }
    public List<string> ClobberIds { get; init; } = [];
    public List<string> FrameworkGlobals { get; init; } = [];
    public bool InlineDocumentWrite { get; init; }
    public List<string> FormFieldNames { get; init; } = [];
    public List<string> StorageKeys { get; init; } = [];
    public List<string> ServiceWorkerScopes { get; init; } = [];
    public List<string> IndexedDbNames { get; init; } = [];
    public int GadgetReadCount { get; init; }
    public int ProtoReadCount { get; init; }
    public ClientScriptTextFacts Script { get; init; } = new();
    /// <summary>Keys read or written since this document was created (local: / session: prefix).</summary>
    public List<string> StorageKeysTouched { get; init; } = [];
    public List<string> ServiceWorkerScriptUrls { get; init; } = [];
    public string? ControllingWorkerScriptUrl { get; init; }
    public bool ServiceWorkerRegisteredByDocument { get; init; }
    public int WebSocketListeners { get; init; }
    public bool WebSocketEvaluates { get; init; }
    public ClientSurfaceNetworkSignals Network { get; init; } = new();
    /// <summary>False when the sensor was installed after this document loaded.</summary>
    public bool LoadObserved { get; init; } = true;
    public int SameOriginIframeCount { get; init; }
    /// <summary>WebSocket, on-page service worker registration, etc. — should outrank session-wide XS-Leaks hints.</summary>
    public bool HasPageLocalXsLead { get; init; }
}

/// <summary>Passive hints from the captured network log. No extra requests.</summary>
public sealed class ClientSurfaceNetworkSignals
{
    public bool Empty { get; init; } = true;
    public bool StrongIsolation { get; init; }
    public bool HasMutatingRequest { get; init; }
    public string IsolationDetail { get; init; } = "";
    public bool HasCrossOriginEmbed { get; init; }
    public string CrossOriginEmbedDetail { get; init; } = "";
    public bool HasStatePair { get; init; }
    public string? StatePairPath { get; init; }
    /// <summary>unknown | absent | protected</summary>
    public string Framing { get; init; } = "unknown";
    /// <summary>unknown | none | wildcard | reflected | credentialed</summary>
    public string Cors { get; init; } = "unknown";
    /// <summary>unknown | absent | enforced</summary>
    public string TrustedTypes { get; init; } = "unknown";
    /// <summary>none | lead-array | lead-jsonp | dismissed-nosniff | unknown-empty</summary>
    public string Xssi { get; init; } = "unknown-empty";

    public static ClientSurfaceNetworkSignals From(IEnumerable<NetworkEntry>? entries, string? pageUrl)
    {
        var list = entries?
            .Where(e => !e.IsTrowserGenerated)
            .ToList() ?? [];
        if (list.Count == 0)
            return new ClientSurfaceNetworkSignals();

        var pageHost = HostOf(pageUrl);
        var document = list.LastOrDefault(e =>
                           e.ResourceType.Equals("Document", StringComparison.OrdinalIgnoreCase)
                           && (pageHost.Length == 0 || HostOf(e.Url).Equals(pageHost, StringComparison.OrdinalIgnoreCase)))
                       ?? list.LastOrDefault(e => e.ResourceType.Equals("Document", StringComparison.OrdinalIgnoreCase));

        var coop = Header(document, "Cross-Origin-Opener-Policy");
        var coep = Header(document, "Cross-Origin-Embedder-Policy");
        var corp = Header(document, "Cross-Origin-Resource-Policy");
        var strong = coop.Contains("same-origin", StringComparison.OrdinalIgnoreCase)
                     && !coop.Contains("same-origin-allow-popups", StringComparison.OrdinalIgnoreCase)
                     && (coep.Contains("require-corp", StringComparison.OrdinalIgnoreCase)
                         || corp.Contains("same-origin", StringComparison.OrdinalIgnoreCase)
                         || corp.Contains("same-site", StringComparison.OrdinalIgnoreCase));
        var isolationBits = new List<string>();
        if (coop.Length > 0) isolationBits.Add($"COOP={coop}");
        if (coep.Length > 0) isolationBits.Add($"COEP={coep}");
        if (corp.Length > 0) isolationBits.Add($"CORP={corp}");

        var mutating = list.Any(e =>
            e.Method is "POST" or "PUT" or "PATCH" or "DELETE"
            && (pageHost.Length == 0 || HostOf(e.Url).Equals(pageHost, StringComparison.OrdinalIgnoreCase)));

        var csp = Header(document, "Content-Security-Policy");
        var xfo = Header(document, "X-Frame-Options");
        var framing = document == null
            ? "unknown"
            : FrameProtected(xfo, csp) ? "protected" : "absent";
        var trustedTypes = document == null
            ? "unknown"
            : csp.Contains("require-trusted-types-for", StringComparison.OrdinalIgnoreCase)
              && csp.Contains("script", StringComparison.OrdinalIgnoreCase)
                ? "enforced"
                : "absent";

        var arrayNoSniff = false;
        var arrayWithSniff = false;
        var jsonp = false;
        var cors = "none";
        var embeds = new List<string>();
        foreach (var entry in list)
        {
            var entryHost = HostOf(entry.Url);
            var sameHost = pageHost.Length == 0 || entryHost.Equals(pageHost, StringComparison.OrdinalIgnoreCase);
            if (!sameHost && IsCrossOriginEmbed(entry))
            {
                var kind = string.IsNullOrEmpty(entry.ResourceType) ? "subresource" : entry.ResourceType.ToLowerInvariant();
                if (embeds.Count < 3)
                    embeds.Add($"{kind} {entryHost}");
            }

            var acao = Header(entry, "Access-Control-Allow-Origin");
            var acac = Header(entry, "Access-Control-Allow-Credentials");
            if (acao.Length > 0)
            {
                var star = acao.Trim() == "*";
                var creds = acac.Contains("true", StringComparison.OrdinalIgnoreCase);
                if (star && creds) cors = "credentialed";
                else if (cors != "credentialed" && star) cors = "wildcard";
                else if (cors is "none" && !star && !acao.Contains(pageHost, StringComparison.OrdinalIgnoreCase))
                    cors = "reflected";
            }

            if (!sameHost) continue;
            var body = entry.ResponseBody?.TrimStart();
            if (string.IsNullOrEmpty(body)) continue;
            var nosniff = Header(entry, "X-Content-Type-Options");
            var script = XssiBodySignals.IsJavaScriptType(entry.ContentType)
                         || entry.ResourceType.Equals("Script", StringComparison.OrdinalIgnoreCase);
            var type = script && !XssiBodySignals.IsJsonType(entry.ContentType)
                ? "text/javascript"
                : entry.ContentType;
            if (!XssiBodySignals.IsIncludable(type, body, nosniff, entry.Url, out var shape))
            {
                if (XssiBodySignals.IsJsonType(entry.ContentType)
                    && XssiBodySignals.IsArrayBody(body)
                    && XssiBodySignals.HasNosniff(nosniff))
                    arrayNoSniff = true;
                continue;
            }

            if (shape is "jsonp" or "callback" or "assignment")
                jsonp = true;
            else
                arrayWithSniff = true;
        }

        string xssi;
        if (jsonp || arrayWithSniff)
            xssi = jsonp && !arrayWithSniff ? "lead-jsonp" : "lead-array";
        else if (arrayNoSniff)
            xssi = "dismissed-nosniff";
        else
            xssi = "none";

        var (hasStatePair, statePairPath) = HasPairedResponses(list, pageHost);

        return new ClientSurfaceNetworkSignals
        {
            Empty = false,
            StrongIsolation = strong,
            HasMutatingRequest = mutating,
            IsolationDetail = isolationBits.Count == 0 ? "" : string.Join(", ", isolationBits),
            HasCrossOriginEmbed = embeds.Count > 0,
            CrossOriginEmbedDetail = string.Join(", ", embeds),
            HasStatePair = hasStatePair,
            StatePairPath = statePairPath,
            Framing = framing,
            Cors = cors,
            TrustedTypes = trustedTypes,
            Xssi = xssi
        };
    }

    private static bool FrameProtected(string xfo, string csp)
    {
        if (xfo.Contains("deny", StringComparison.OrdinalIgnoreCase)
            || xfo.Contains("sameorigin", StringComparison.OrdinalIgnoreCase))
            return true;
        return csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase)
               && (csp.Contains("'none'", StringComparison.OrdinalIgnoreCase)
                   || csp.Contains("'self'", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsCrossOriginEmbed(NetworkEntry entry)
    {
        var type = entry.ResourceType;
        return type.Equals("Image", StringComparison.OrdinalIgnoreCase)
               || type.Equals("Script", StringComparison.OrdinalIgnoreCase)
               || type.Equals("SubFrame", StringComparison.OrdinalIgnoreCase)
               || type.Equals("Frame", StringComparison.OrdinalIgnoreCase);
    }

    private static (bool HasPair, string? Path) HasPairedResponses(List<NetworkEntry> list, string pageHost)
    {
        var groups = new Dictionary<string, List<NetworkEntry>>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in list)
        {
            if (pageHost.Length > 0 && !HostOf(entry.Url).Equals(pageHost, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            var path = uri.AbsolutePath.Length == 0 ? "/" : uri.AbsolutePath;
            var key = $"{entry.Method.ToUpperInvariant()}|{path}|{entry.ResourceType}";
            if (!groups.TryGetValue(key, out var bucket))
            {
                bucket = [];
                groups[key] = bucket;
            }
            bucket.Add(entry);
        }

        foreach (var (key, bucket) in groups)
        {
            if (bucket.Count < 2) continue;
            var statuses = bucket.Select(e => e.StatusCode).Distinct().Count();
            var lengths = bucket.Select(e => e.ResponseBody?.Length ?? -1).Where(n => n >= 0).Distinct().Count();
            if (statuses <= 1 && lengths <= 1) continue;

            var method = key.Split('|')[0];
            var path = key.Split('|')[1];
            var statusSample = bucket.Select(e => e.StatusCode).Distinct().OrderBy(c => c).Take(3);
            return (true, $"{method} {path} ({string.Join(" vs ", statusSample)})");
        }

        return (false, null);
    }

    private static string Header(NetworkEntry? entry, string name)
    {
        if (entry == null) return "";
        foreach (var kv in entry.ResponseHeaders)
        {
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return kv.Value ?? "";
        }
        return "";
    }

    private static string HostOf(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return "";
        return Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : "";
    }
}
