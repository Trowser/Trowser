using Trowser.Automation;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class ClientSurfaceRiskPlannerTests
{
    [Fact]
    public void Checklist_has_a_stable_class_order()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence());
        Assert.Equal(
            ["xs-leaks", "dom-xss", "client-csrf", "postmessage", "client-prototype-pollution",
             "dom-clobbering", "dom-open-redirect", "client-authz", "client-html-injection", "csti",
             "web-storage", "frontend-logic", "reverse-tabnabbing", "xssi", "service-worker",
             "clickjacking", "cors", "css-injection", "dangling-markup", "trusted-types", "websocket"],
            plan.Risks.Select(r => r.Id).ToArray());
    }

    [Fact]
    public void Unobserved_runtime_does_not_dismiss_sink_classes()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence());
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "dom-xss"));
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "postmessage"));
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "dom-open-redirect"));
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "xssi"));
        Assert.Equal(ClientSurfaceRiskPlanner.NotObserved, Status(plan, "csti"));
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(plan, "reverse-tabnabbing"));
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(plan, "service-worker"));
        Assert.Equal(ClientSurfaceRiskPlanner.Manual, Status(plan, "frontend-logic"));
        Assert.Equal(ClientSurfaceRiskPlanner.Manual, Status(plan, "client-authz"));
    }

    [Fact]
    public void Weak_message_listener_is_pursue_and_dismiss_rows_are_not_next_actions()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Listeners = [("message", "none")]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Pursue, Status(plan, "postmessage"));
        Assert.Contains(plan.NextActions, a => a.Contains("postmessage", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(plan.NextActions, a => a.StartsWith("Reverse tabnabbing", StringComparison.Ordinal));
    }

    [Fact]
    public void Same_origin_iframe_without_listeners_is_postmessage_lead_not_dismiss()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            LoadObserved = true,
            SameOriginIframeCount = 1
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "postmessage"));
        Assert.Contains("iframe", Reason(plan, "postmessage"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Session_state_pair_on_other_pages_is_manual_when_page_has_websocket()
    {
        var signals = ClientSurfaceNetworkSignals.From(
        [
            Entry("https://app.test/api/avatar", "Fetch", "{}", "application/json", status: 200),
            Entry("https://app.test/api/avatar", "Fetch", "{}", "application/json", status: 404)
        ], "https://app.test/chat");
        Assert.True(signals.HasStatePair);
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            HasPageLocalXsLead = true,
            Network = signals
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Manual, Status(plan, "xs-leaks"));
    }

    [Fact]
    public void Strict_listeners_and_no_sinks_dismiss_postmessage_and_dom_xss()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Listeners = [("message", "strict")]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(plan, "postmessage"));
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(plan, "dom-xss"));
    }

    [Fact]
    public void Executable_sink_plus_attacker_source_pursues_dom_xss()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Sources = ["postMessage"],
            Sinks = ["innerHTML"]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Pursue, Status(plan, "dom-xss"));
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "client-html-injection"));
    }

    [Fact]
    public void Padded_url_cell_does_not_pursue_dom_xss()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Cells = [("url", "innerHTML", "confirmed")]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(plan, "dom-xss"));
    }

    [Fact]
    public void Template_global_pursues_csti_and_react_does_not()
    {
        var angular = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            FrameworkGlobals = ["angular", "jQuery"]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Pursue, Status(angular, "csti"));

        var react = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            FrameworkGlobals = ["React", "__NEXT_DATA__"]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(react, "csti"));
    }

    [Fact]
    public void Sensitive_storage_key_is_a_lead_and_empty_storage_is_dismissed()
    {
        var lead = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            StorageKeys = ["local:access_token", "local:theme"]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(lead, "web-storage"));

        var dismiss = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence());
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(dismiss, "web-storage"));
    }

    [Fact]
    public void Gadget_read_pursues_clobber_and_duplicate_id_is_only_a_lead()
    {
        var pursue = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            GadgetReadCount = 2
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Pursue, Status(pursue, "dom-clobbering"));

        var lead = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            ClobberIds = ["config"]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(lead, "dom-clobbering"));
    }

    [Fact]
    public void Nav_hijack_flow_pursues_open_redirect()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Flows = [("location.search", "location.assign", "nav-hijack", "hygiene")]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Pursue, Status(plan, "dom-open-redirect"));
    }

    [Fact]
    public void Role_field_name_makes_client_authz_a_lead()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            FormFieldNames = ["isAdmin"]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "client-authz"));
    }

    [Fact]
    public void Json_array_without_nosniff_is_an_xssi_lead()
    {
        var signals = ClientSurfaceNetworkSignals.From(
        [
            Entry("https://app.test/api/notes", "Fetch", "[{\"id\":1}]", "application/json")
        ], "https://app.test/");
        Assert.Equal("lead-array", signals.Xssi);
        Assert.False(signals.StrongIsolation);
    }

    [Fact]
    public void Json_array_with_nosniff_and_coop_coep_dismiss_xssi_and_isolate()
    {
        var signals = ClientSurfaceNetworkSignals.From(
        [
            new NetworkEntry
            {
                Method = "GET",
                Url = "https://app.test/",
                ResourceType = "Document",
                ResponseHeaders = new Dictionary<string, string>
                {
                    ["Cross-Origin-Opener-Policy"] = "same-origin",
                    ["Cross-Origin-Embedder-Policy"] = "require-corp"
                }
            },
            Entry("https://app.test/api/notes", "Fetch", "[{\"id\":1}]", "application/json",
                new Dictionary<string, string> { ["X-Content-Type-Options"] = "nosniff" })
        ], "https://app.test/");
        Assert.Equal("dismissed-nosniff", signals.Xssi);
        Assert.True(signals.StrongIsolation);

        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence { Network = signals });
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(plan, "xs-leaks"));
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(plan, "xssi"));
    }

    [Fact]
    public void Tabnabbing_links_are_hygiene_manual_not_exploitable_lead()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence { TabnabbingHygieneCount = 3 });
        Assert.Equal(ClientSurfaceRiskPlanner.Manual, Status(plan, "reverse-tabnabbing"));
        Assert.Contains("3", plan.Risks.Single(r => r.Id == "reverse-tabnabbing").Reason);
        Assert.Contains("implicit noopener", Reason(plan, "reverse-tabnabbing"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Window_open_without_noopener_is_a_lead()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Script = new ClientScriptTextFacts { WindowOpenWithoutNoopener = true }
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "reverse-tabnabbing"));
    }

    [Fact]
    public void Different_http_methods_on_same_path_are_not_xs_leak_state_pairs()
    {
        var signals = ClientSurfaceNetworkSignals.From(
        [
            Entry("https://app.test/secure/staff", "Fetch", "ok", "application/json", status: 200, method: "GET"),
            Entry("https://app.test/secure/staff", "Fetch", "", "application/json", status: 204, method: "PUT")
        ], "https://app.test/");
        Assert.False(signals.HasStatePair);
    }

    [Fact]
    public void Same_method_different_status_on_same_path_is_xs_leak_state_pair()
    {
        var signals = ClientSurfaceNetworkSignals.From(
        [
            Entry("https://app.test/api/avatar", "Fetch", "{}", "application/json", status: 200),
            Entry("https://app.test/api/avatar", "Fetch", "{}", "application/json", status: 404)
        ], "https://app.test/chat");
        Assert.True(signals.HasStatePair);
    }

    [Fact]
    public void Ng_version_dom_hint_pursues_csti_without_window_global()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            DomFrameworkHints = ["ng-version=22.2.0"]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Pursue, Status(plan, "csti"));
    }

    [Fact]
    public void Client_csrf_is_not_observed_when_runtime_empty_but_network_has_traffic()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = false,
            ScriptSurfaceIncomplete = true,
            Network = new ClientSurfaceNetworkSignals { Empty = false }
        });
        Assert.Equal(ClientSurfaceRiskPlanner.NotObserved, Status(plan, "client-csrf"));
    }

    [Fact]
    public void Script_text_sink_keeps_dom_xss_as_a_lead()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Script = ClientScriptTextScanner.Scan(
                ["if (location.hash) { document.getElementById('o').innerHTML = location.hash; }"])
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "dom-xss"));
        Assert.Contains("did not run", Reason(plan, "dom-xss"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Custom_function_template_pursues_csti_without_a_framework_global()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Script = ClientScriptTextScanner.Scan(
                ["var html = new Function('return `' + template + '`')();"])
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Pursue, Status(plan, "csti"));
        Assert.Contains("Function", Reason(plan, "csti"), StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_isolation_without_a_cross_origin_embed_is_not_an_xs_leak_lead()
    {
        var signals = ClientSurfaceNetworkSignals.From(
        [
            Entry("https://app.test/", "Document", "<html></html>", "text/html")
        ], "https://app.test/");
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Network = signals
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Manual, Status(plan, "xs-leaks"));
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "clickjacking"));
    }

    [Fact]
    public void Cross_origin_image_is_an_xs_leak_lead()
    {
        var signals = ClientSurfaceNetworkSignals.From(
        [
            Entry("https://app.test/", "Document", "<html></html>", "text/html"),
            Entry("https://cdn.example/a.png", "Image", "", "image/png")
        ], "https://app.test/");
        Assert.True(signals.HasCrossOriginEmbed);
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence { Network = signals });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "xs-leaks"));
    }

    [Fact]
    public void Fetch_without_location_input_does_not_lead_client_csrf()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Sinks = ["fetch"],
            Network = new ClientSurfaceNetworkSignals { Empty = false }
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(plan, "client-csrf"));
    }

    [Fact]
    public void Location_driven_fetch_leads_client_csrf_with_a_trace_input_follow_up()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Script = ClientScriptTextScanner.Scan(
            [
                "var email = new URLSearchParams(location.search).get('email'); fetch('/api/profile', {method:'POST', body: email});"
            ])
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "client-csrf"));
        var follow = plan.Risks.Single(r => r.Id == "client-csrf").FollowUp;
        Assert.Contains("/api/security/trace-input", follow, StringComparison.Ordinal);
        Assert.Contains("email", follow, StringComparison.Ordinal);
    }

    [Fact]
    public void Storage_keys_from_earlier_navigations_are_labeled_as_such()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            StorageKeys = ["local:api_token", "session:session_jwt_parts"]
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "web-storage"));
        Assert.Contains("earlier navigations", Reason(plan, "web-storage"), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("/api/security/storage", plan.Risks.Single(r => r.Id == "web-storage").FollowUp, StringComparison.Ordinal);
    }

    [Fact]
    public void Controlling_worker_not_registered_here_is_a_lead()
    {
        var stuck = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            ServiceWorkerScopes = ["https://app.test/"],
            ControllingWorkerScriptUrl = "https://app.test/sw.js"
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(stuck, "service-worker"));
        Assert.Contains("sw.js", Reason(stuck, "service-worker"), StringComparison.Ordinal);
        Assert.Contains("did not register", Reason(stuck, "service-worker"), StringComparison.OrdinalIgnoreCase);

        var here = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            ServiceWorkerScopes = ["https://app.test/"],
            ControllingWorkerScriptUrl = "https://app.test/sw.js",
            ServiceWorkerRegisteredByDocument = true
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Pursue, Status(here, "service-worker"));
    }

    [Fact]
    public void Dotted_window_read_is_a_clobber_lead()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Script = ClientScriptTextScanner.Scan(["var key = window.config.apiKey;"])
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "dom-clobbering"));
        Assert.Contains("config.apiKey", Reason(plan, "dom-clobbering"), StringComparison.Ordinal);
    }

    [Fact]
    public void Javascript_array_without_nosniff_is_an_xssi_lead()
    {
        var signals = ClientSurfaceNetworkSignals.From(
        [
            Entry("https://app.test/session.js", "Script", "[{\"user\":1}]", "text/javascript")
        ], "https://app.test/");
        Assert.Equal("lead-array", signals.Xssi);
        Assert.True(XssiBodySignals.IsIncludable("text/javascript", "var session = {\"a\":1};", "", "https://app.test/s.js", out var shape));
        Assert.Equal("assignment", shape);
        Assert.True(XssiBodySignals.CallbackReflects("https://app.test/api?callback=steal", "steal({\"a\":1})"));
    }

    [Fact]
    public void WebSocket_message_listener_is_not_postmessage()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            WebSocketListeners = 1,
            WebSocketEvaluates = true
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Dismiss, Status(plan, "postmessage"));
        Assert.Equal(ClientSurfaceRiskPlanner.Pursue, Status(plan, "websocket"));
    }

    [Fact]
    public void Redirect_params_in_script_name_the_trace_including_auto()
    {
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = true,
            Script = ClientScriptTextScanner.Scan(
            [
                "var next = new URLSearchParams(location.search).get('next'); var auto = new URLSearchParams(location.search).get('auto'); location.href = next;"
            ])
        });
        Assert.Equal(ClientSurfaceRiskPlanner.Lead, Status(plan, "dom-open-redirect"));
        var follow = plan.Risks.Single(r => r.Id == "dom-open-redirect").FollowUp;
        Assert.Contains("next", follow, StringComparison.Ordinal);
        Assert.Contains("auto=1", follow, StringComparison.Ordinal);
    }

    [Fact]
    public void Listener_from_another_hash_document_is_dropped()
    {
        Assert.False(ClientSurfaceMapper.ListenerStillOnDocument(
            "https://app.test/pm#easy", "https://app.test/pm#hard"));
        Assert.True(ClientSurfaceMapper.ListenerStillOnDocument(
            "https://app.test/pm?x=1#hard", "https://app.test/pm#hard"));
        Assert.False(ClientSurfaceMapper.ListenerStillOnDocument(null, "https://app.test/pm#hard"));
    }

    private static string Status(ClientSurfaceRiskPlan plan, string id) =>
        plan.Risks.Single(r => r.Id == id).Status;

    private static string Reason(ClientSurfaceRiskPlan plan, string id) =>
        plan.Risks.Single(r => r.Id == id).Reason;

    private static NetworkEntry Entry(
        string url, string type, string body, string contentType, Dictionary<string, string>? extra = null,
        int status = 200, string method = "GET")
    {
        var headers = extra ?? new Dictionary<string, string>();
        headers["Content-Type"] = contentType;
        return new NetworkEntry
        {
            Method = method,
            Url = url,
            StatusCode = status,
            ResourceType = type,
            ResponseBody = body,
            ResponseHeaders = headers
        };
    }
}
