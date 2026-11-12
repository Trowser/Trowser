using System.Text;
using System.Text.Json;

namespace Trowser.Automation;

/// <summary>
/// Adaptive form attack ("Attack this form") - the flagship adaptive quicktest.
///
/// Unlike a static .csx, this inspects the *live* DOM to discover the editable fields
/// wired to a form/submit control, infers each field's semantic type, and probes it with
/// type-aware payloads. Phase A (always on, safe, no navigation) finds client-side
/// validation gaps: required fields not enforced, email/number/date fields implemented as
/// plain text with no validation, unenforced pattern/min/max constraints. Phase B (opt-in,
/// mutates server state) replays the form via in-page fetch with attack payloads and flags
/// server errors, stack-trace disclosure, and payload reflection.
/// </summary>
public partial class AutomationContext
{
    /// <summary>One payload attempt against one field.</summary>
    public sealed class FormAttackProbe
    {
        public string Category { get; set; } = "";
        public string Payload { get; set; } = "";
        /// <summary>True when a correctly-validating field should reject this payload.</summary>
        public bool ExpectedInvalid { get; set; }
        /// <summary>True when the browser (or field) actually rejected the payload client-side.</summary>
        public bool Rejected { get; set; }
        public string? ValidationMessage { get; set; }
        // Phase B (submit) outcome:
        public int? Status { get; set; }
        public bool? ServerError { get; set; }
        public bool? Reflected { get; set; }
        public string? Note { get; set; }
    }

    /// <summary>Discovery + probe results for one editable field.</summary>
    public sealed class FormAttackField
    {
        public string Name { get; set; } = "";
        public string Label { get; set; } = "";
        public string Type { get; set; } = "";
        public string Semantic { get; set; } = "";
        public bool Required { get; set; }
        public int? MaxLength { get; set; }
        public string? Pattern { get; set; }
        public string? Min { get; set; }
        public string? Max { get; set; }
        public List<FormAttackProbe> Probes { get; set; } = [];
        public List<string> Notes { get; set; } = [];
    }

    /// <summary>Overall result of an adaptive form attack.</summary>
    public sealed class FormAttackResult
    {
        public bool FormFound { get; set; }
        public string? FormLabel { get; set; }
        public string? Action { get; set; }
        public string Method { get; set; } = "get";
        public int FieldCount { get; set; }
        public bool Submitted { get; set; }
        public List<FormAttackField> Fields { get; set; } = [];
        public List<string> Anomalies { get; set; } = [];
        public string Summary { get; set; } = "";
        public string? Note { get; set; }
        /// <summary>Internal marker attribute value used to re-find the form for phase B (not for callers).</summary>
        internal string? FormMarker { get; set; }
    }

    /// <summary>
    /// Run an adaptive form attack. <paramref name="target"/> may be a CSS selector or semantic
    /// locator for a form, a submit button, or any field in the form. When null, the element from
    /// the last "Run Script" context menu (<see cref="This"/>) is used, otherwise the page's primary
    /// form is auto-selected. Set <paramref name="submit"/> to also replay the form server-side
    /// (mutates state - gate behind an explicit opt-in).
    /// </summary>
    public async Task<FormAttackResult> AttackForm(string? target = null, bool submit = false,
        int maxFields = 15, int perField = 18)
    {
        await CheckScriptExecutionAsync();

        string? sel = !string.IsNullOrWhiteSpace(target) ? target : This;
        if (sel == RunScriptTarget) sel = This;

        string? resolvedCss = null;
        if (!string.IsNullOrWhiteSpace(sel))
            resolvedCss = await TryResolveLocatorOnce(sel) ?? sel;

        var js = BuildAttackFormClientJs(resolvedCss, Math.Clamp(maxFields, 1, 40), Math.Clamp(perField, 1, 30));
        var json = await RunJs(js);
        var result = ParseFormAttackResult(json);

        if (submit && result.FormFound && !string.IsNullOrEmpty(result.FormMarker))
        {
            try
            {
                var submitJs = BuildAttackFormSubmitJs(result.FormMarker!);
                var subJson = await RunJsAsync(submitJs, 60_000);
                MergeSubmitResults(result, subJson);
                result.Submitted = true;
            }
            catch (Exception ex)
            {
                result.Note = (result.Note == null ? "" : result.Note + " ") +
                    $"Submit phase failed: {ex.Message}";
            }
        }

        result.Summary = BuildFormAttackSummary(result);
        return result;
    }

    /// <summary>Run <see cref="AttackForm"/> and return a human-readable report (for the script console).</summary>
    public async Task<string> AttackFormReport(string? target = null, bool submit = false,
        int maxFields = 15, int perField = 18)
    {
        var result = await AttackForm(target, submit, maxFields, perField);
        return FormatFormAttackReport(result);
    }

    // ---- result parsing / formatting ----

    private static FormAttackResult ParseFormAttackResult(string json)
    {
        var result = new FormAttackResult();
        if (string.IsNullOrWhiteSpace(json)) { result.Note = "No result from page."; return result; }
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            result.FormFound = root.TryGetProperty("formFound", out var ff) && ff.ValueKind == JsonValueKind.True;
            result.FormLabel = GetStr(root, "formLabel");
            result.Action = GetStr(root, "action");
            result.Method = GetStr(root, "method") ?? "get";
            result.FormMarker = GetStr(root, "formMarker");
            result.Note = GetStr(root, "note") ?? result.Note;

            if (root.TryGetProperty("fields", out var fields) && fields.ValueKind == JsonValueKind.Array)
            {
                foreach (var f in fields.EnumerateArray())
                {
                    var field = new FormAttackField
                    {
                        Name = GetStr(f, "name") ?? "",
                        Label = GetStr(f, "label") ?? "",
                        Type = GetStr(f, "type") ?? "",
                        Semantic = GetStr(f, "semantic") ?? "",
                        Required = f.TryGetProperty("required", out var rq) && rq.ValueKind == JsonValueKind.True,
                        Pattern = GetStr(f, "pattern"),
                        Min = GetStr(f, "min"),
                        Max = GetStr(f, "max"),
                    };
                    if (f.TryGetProperty("maxlength", out var ml) && ml.ValueKind == JsonValueKind.Number)
                        field.MaxLength = ml.GetInt32();
                    if (f.TryGetProperty("notes", out var notes) && notes.ValueKind == JsonValueKind.Array)
                        foreach (var n in notes.EnumerateArray())
                            if (n.GetString() is { } ns) field.Notes.Add(ns);
                    if (f.TryGetProperty("probes", out var probes) && probes.ValueKind == JsonValueKind.Array)
                        foreach (var p in probes.EnumerateArray())
                            field.Probes.Add(new FormAttackProbe
                            {
                                Category = GetStr(p, "category") ?? "",
                                Payload = GetStr(p, "payload") ?? "",
                                ExpectedInvalid = p.TryGetProperty("expectedInvalid", out var ei) && ei.ValueKind == JsonValueKind.True,
                                Rejected = p.TryGetProperty("rejected", out var rj) && rj.ValueKind == JsonValueKind.True,
                                ValidationMessage = GetStr(p, "validationMessage"),
                            });
                    result.Fields.Add(field);
                }
            }
            result.FieldCount = result.Fields.Count;

            if (root.TryGetProperty("anomalies", out var an) && an.ValueKind == JsonValueKind.Array)
                foreach (var a in an.EnumerateArray())
                    if (a.GetString() is { } s) result.Anomalies.Add(s);
        }
        catch (Exception ex)
        {
            result.Note = $"Failed to parse form-attack result: {ex.Message}";
        }
        return result;
    }

    private static void MergeSubmitResults(FormAttackResult result, string subJson)
    {
        if (string.IsNullOrWhiteSpace(subJson)) return;
        try
        {
            using var doc = JsonDocument.Parse(subJson);
            var root = doc.RootElement;
            if (root.TryGetProperty("anomalies", out var an) && an.ValueKind == JsonValueKind.Array)
                foreach (var a in an.EnumerateArray())
                    if (a.GetString() is { } s && !result.Anomalies.Contains(s))
                        result.Anomalies.Add(s);
            if (root.TryGetProperty("note", out var note) && note.GetString() is { } nn)
                result.Note = (result.Note == null ? "" : result.Note + " ") + nn;
        }
        catch { /* best-effort */ }
    }

    private static string BuildFormAttackSummary(FormAttackResult r)
    {
        if (!r.FormFound)
            return r.Note ?? "No form found to attack.";
        var probeCount = r.Fields.Sum(f => f.Probes.Count);
        var target = string.IsNullOrEmpty(r.FormLabel) ? "form" : $"form \"{r.FormLabel}\"";
        var phase = r.Submitted ? "client-side + server replay" : "client-side";
        return $"{target}: {r.FieldCount} field(s), {probeCount} probe(s) ({phase}); " +
               $"{r.Anomalies.Count} anomaly(ies).";
    }

    private static string FormatFormAttackReport(FormAttackResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Attack this form ===");
        if (!r.FormFound)
        {
            sb.AppendLine(r.Note ?? "No form found on the page.");
            return sb.ToString();
        }
        if (!string.IsNullOrEmpty(r.FormLabel)) sb.AppendLine($"Form: {r.FormLabel}");
        if (!string.IsNullOrEmpty(r.Action)) sb.AppendLine($"Action: {r.Method.ToUpperInvariant()} {r.Action}");
        var totalProbes = r.Fields.Sum(f => f.Probes.Count);
        sb.AppendLine($"Fields probed: {r.FieldCount};  payloads executed: {totalProbes}" + (r.Submitted ? " (client-side + server replay)" : " (client-side)"));
        sb.AppendLine();

        if (r.Anomalies.Count == 0)
        {
            sb.AppendLine("No client-side validation anomalies detected.");
        }
        else
        {
            sb.AppendLine($"ANOMALIES ({r.Anomalies.Count}):");
            foreach (var a in r.Anomalies) sb.AppendLine($"  ! {a}");
        }
        sb.AppendLine();

        foreach (var f in r.Fields)
        {
            var name = !string.IsNullOrEmpty(f.Label) ? f.Label : (!string.IsNullOrEmpty(f.Name) ? f.Name : "(unnamed)");
            var constraints = new List<string> { $"type={f.Type}" };
            if (!string.IsNullOrEmpty(f.Semantic) && f.Semantic != "text") constraints.Add($"looks-like={f.Semantic}");
            if (f.Required) constraints.Add("required");
            if (f.MaxLength is int max) constraints.Add($"maxlength={max}");
            if (!string.IsNullOrEmpty(f.Pattern)) constraints.Add("pattern");
            if (!string.IsNullOrEmpty(f.Min)) constraints.Add($"min={f.Min}");
            if (!string.IsNullOrEmpty(f.Max)) constraints.Add($"max={f.Max}");
            constraints.Add($"{f.Probes.Count} payloads");
            sb.AppendLine($"- {name} [{string.Join(", ", constraints)}]");
            foreach (var note in f.Notes) sb.AppendLine($"    {note}");
        }

        if (!string.IsNullOrEmpty(r.Note)) { sb.AppendLine(); sb.AppendLine(r.Note); }
        return sb.ToString();
    }

    private static string? GetStr(JsonElement el, string name) =>
        el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    // ---- JS builders ----

    private static string BuildAttackFormClientJs(string? targetSelector, int maxFields, int perField)
    {
        var sb = new StringBuilder(8192);
        sb.Append("(function(){\n");
        sb.Append("var TARGET=").Append(targetSelector == null ? "null" : JsonEscape(targetSelector)).Append(";\n");
        sb.Append("var MAXF=").Append(maxFields).Append(";\n");
        sb.Append("var PER=").Append(perField).Append(";\n");
        sb.Append(AttackFormClientBody);
        sb.Append("\n})()");
        return sb.ToString();
    }

    private static string BuildAttackFormSubmitJs(string marker)
    {
        var sb = new StringBuilder(8192);
        sb.Append("(function(){\n");
        sb.Append("var MARKER=").Append(JsonEscape(marker)).Append(";\n");
        sb.Append(AttackFormSubmitBody);
        sb.Append("\n})()");
        return sb.ToString();
    }

    // Phase A: discovery + client-side validation-gap probing. Returns JSON.
    private const string AttackFormClientBody = """
        function deepQuery(sel){
            try { var el=document.querySelector(sel); if(el) return el; } catch(e){}
            function s(root){var h=root.querySelectorAll('*');for(var i=0;i<h.length;i++){if(h[i].shadowRoot){try{var f=h[i].shadowRoot.querySelector(sel);if(f)return f;}catch(e){}var r=s(h[i].shadowRoot);if(r)return r;}}return null;}
            return s(document);
        }
        function labelOf(el){
            var a=el.getAttribute&&el.getAttribute('aria-label'); if(a) return a.trim();
            if(el.id){var l=document.querySelector('label[for="'+el.id.replace(/"/g,'\\"')+'"]'); if(l) return (l.innerText||l.textContent||'').trim();}
            var p=el.closest&&el.closest('label'); if(p){var c=p.cloneNode(true);var ins=c.querySelectorAll('input,select,textarea');for(var i=0;i<ins.length;i++)ins[i].remove();var t=(c.innerText||c.textContent||'').trim(); if(t) return t;}
            if(el.placeholder) return el.placeholder.trim();
            if(el.name) return el.name;
            return '';
        }
        function isVisible(el){ try{var r=el.getBoundingClientRect(); if(r.width===0&&r.height===0) return false; var st=getComputedStyle(el); if(st.display==='none'||st.visibility==='hidden') return false;}catch(e){} return true; }
        function isEditable(el){
            var t=el.tagName.toLowerCase();
            if(t==='textarea') return true;
            if(el.isContentEditable) return true;
            if(t!=='input') return false;
            var it=(el.type||'text').toLowerCase();
            return ['text','email','url','tel','search','number','password','date','datetime-local','month','week','time'].indexOf(it)>=0;
        }
        function editableIn(scope){
            var all=scope.querySelectorAll('input,textarea,[contenteditable=""],[contenteditable=true]');
            var out=[]; for(var i=0;i<all.length;i++){ if(isEditable(all[i]) && isVisible(all[i]) && !all[i].disabled) out.push(all[i]); }
            return out;
        }
        // Resolve the form / field scope
        var form=null, scopeEl=null;
        if(TARGET){
            var t=deepQuery(TARGET);
            if(t){
                if(t.tagName && t.tagName.toLowerCase()==='form') form=t;
                else if(t.form) form=t.form;
                else if(t.closest) form=t.closest('form');
                if(!form) scopeEl=t.closest ? (t.closest('form,section,div,fieldset')||document.body) : document.body;
            }
        }
        if(!form && !scopeEl){
            // Auto-pick the visible form with the most editable fields
            var forms=Array.prototype.slice.call(document.querySelectorAll('form'));
            var best=null,bestN=0;
            for(var i=0;i<forms.length;i++){ if(!isVisible(forms[i]))continue; var n=editableIn(forms[i]).length; if(n>bestN){bestN=n;best=forms[i];} }
            if(best){ form=best; }
        }
        var scope = form || scopeEl;
        if(!scope){
            // last resort: all editable fields on the page as a synthetic group
            var any=editableIn(document);
            if(any.length===0) return JSON.stringify({formFound:false, note:'No editable form fields found on the page.'});
            scope=document.body;
        }
        var fieldsEls=editableIn(scope).slice(0,MAXF);
        if(fieldsEls.length===0) return JSON.stringify({formFound:false, note:'The target has no editable fields.'});

        var marker='_af_'+Math.random().toString(36).substr(2,8);
        if(form) form.setAttribute('data-trowser-af', marker);

        function semanticOf(el){
            var it=(el.type||'text').toLowerCase();
            if(it==='email')return 'email';
            if(it==='number')return 'number';
            if(it==='url')return 'url';
            if(it==='tel')return 'tel';
            if(it==='date'||it==='datetime-local'||it==='month'||it==='week'||it==='time')return 'date';
            var hint=((el.name||'')+' '+(el.id||'')+' '+labelOf(el)+' '+(el.placeholder||'')).toLowerCase();
            if(/e-?mail/.test(hint))return 'email';
            if(/(qty|quantity|amount|price|count|\bage\b|number|\bnum\b)/.test(hint))return 'number';
            if(/(url|website|homepage|link)/.test(hint))return 'url';
            if(/(phone|mobile|\btel\b)/.test(hint))return 'tel';
            if(/(date|dob|birth)/.test(hint))return 'date';
            return 'text';
        }
        // Invalid-for-semantic payloads (a correct validator should reject these)
        function invalidPayloads(sem, el){
            switch(sem){
                case 'email': return [['bad-email','plainaddress'],['bad-email','a@'],['bad-email','a b@c.com'],['bad-email','@nodomain.com'],['bad-email','two@@at.com'],['bad-email','x@y']];
                case 'number':
                    var p=[['non-numeric','abc'],['negative','-1'],['huge','99999999999999999999'],['scientific','1e10'],['hex','0x1F'],['not-a-number','NaN'],['infinity','Infinity']];
                    if(el.min!=='' && el.min!=null){ var mn=parseFloat(el.min); if(!isNaN(mn)) p.push(['below-min',String(mn-1)]); }
                    if(el.max!=='' && el.max!=null){ var mx=parseFloat(el.max); if(!isNaN(mx)) p.push(['above-max',String(mx+1)]); }
                    if(el.step && el.step!=='any'){ p.push(['fractional-step','1.0000001']); }
                    return p;
                case 'url': return [['bad-url','notaurl'],['js-url','javascript:alert(1)'],['no-scheme','//evil.example'],['space-url','http:// bad']];
                case 'tel': return [['non-tel','abcdef'],['too-short','1']];
                case 'date': return [['bad-date','not-a-date'],['impossible-date','2025-13-45'],['zero-date','0000-00-00']];
                default: return [];
            }
        }
        // A good, categorized attack set applied to every text-like field.
        var GENERIC=[
            ['xss','<script>alert(1)</script>'],
            ['xss-attr','"><img src=x onerror=alert(1)>'],
            ['xss-svg',"'\"><svg/onload=alert(1)>"],
            ['sqli',"' OR 1=1--"],
            ['sqli-quote','" OR "1"="1'],
            ['template','{{7*7}}'],
            ['template-el','${7*7}'],
            ['path-traversal','../../../etc/passwd'],
            ['cmd-injection','; id'],
            ['format-string','%s%n%x%x'],
            ['long-1k','A'.repeat(1024)],
            ['unicode','caf\u00e9 \u2603 \u2460\u2461\u2462'],
            ['whitespace','   '],
            ['rtl-override','\u202eabc'],
            ['null-word','null']
        ];

        function probe(el, category, payload, expectedInvalid){
            var orig = el.isContentEditable ? el.textContent : el.value;
            try{
                if(el.isContentEditable) el.textContent=payload; else el.value=payload;
                el.dispatchEvent(new Event('input',{bubbles:true}));
                el.dispatchEvent(new Event('change',{bubbles:true}));
            }catch(e){}
            var valid=true, vmsg='';
            try{ if(typeof el.checkValidity==='function'){ valid=el.checkValidity(); vmsg=el.validationMessage||''; } }catch(e){}
            var readback = el.isContentEditable ? el.textContent : el.value;
            var cleared = (readback==='' && payload!=='');
            var rejected = (!valid) || cleared;
            // restore
            try{
                if(el.isContentEditable) el.textContent=orig; else el.value=orig;
                el.dispatchEvent(new Event('input',{bubbles:true}));
                el.dispatchEvent(new Event('change',{bubbles:true}));
            }catch(e){}
            return {category:category, payload:payload.length>60?payload.substr(0,57)+'...':payload, expectedInvalid:expectedInvalid, rejected:rejected, validationMessage:vmsg||null};
        }

        var out={formFound:true, formMarker: form?marker:'', method:(form&&form.method?form.method.toLowerCase():'get'), fields:[], anomalies:[]};
        try{ if(form){ out.action=form.getAttribute('action')||location.href; out.formLabel=labelOf(form)|| (form.getAttribute('name')||form.id||'')||''; } else { out.formLabel='(page fields)'; } }catch(e){}

        for(var fi=0; fi<fieldsEls.length; fi++){
            var el=fieldsEls[fi];
            var it=(el.type||el.tagName.toLowerCase());
            var sem=semanticOf(el);
            var label=labelOf(el);
            var field={name:el.name||el.id||'', label:label, type:(el.type||el.tagName.toLowerCase()), semantic:sem, required:!!el.required, pattern:el.getAttribute?el.getAttribute('pattern'):null, min:(el.min!==undefined?el.min:null)||null, max:(el.max!==undefined?el.max:null)||null, probes:[], notes:[]};
            var mlAttr = el.getAttribute?el.getAttribute('maxlength'):null;
            if(mlAttr!=null && mlAttr!=='' && !isNaN(parseInt(mlAttr,10))) field.maxlength=parseInt(mlAttr,10);
            var dispName = label|| field.name || ('field '+(fi+1));

            // 1) required enforcement
            if(el.required){
                var pr=probe(el,'required-empty','',true);
                field.probes.push(pr);
                if(!pr.rejected) out.anomalies.push('Required field "'+dispName+'" is not enforced client-side (empty value accepted).');
            }
            // 2) semantic/type validation gaps
            var inv=invalidPayloads(sem, el);
            var isNativeTyped = ['email','number','url','tel','date','datetime-local','month','week','time'].indexOf((el.type||'').toLowerCase())>=0;
            for(var pi=0; pi<inv.length && field.probes.length<PER; pi++){
                var pr2=probe(el, inv[pi][0], inv[pi][1], true);
                field.probes.push(pr2);
                if(!pr2.rejected){
                    if(!isNativeTyped && !field.pattern){
                        out.anomalies.push('Field "'+dispName+'" looks like '+sem+' but is type='+field.type+' with no validation; accepted invalid value "'+pr2.payload+'".');
                    } else {
                        out.anomalies.push('Field "'+dispName+'" (type='+field.type+(field.pattern?', pattern':'')+') did not reject invalid value "'+pr2.payload+'" ('+inv[pi][0]+').');
                    }
                }
            }
            // 3) pattern enforcement (independent of semantic)
            if(field.pattern){
                try{
                    var re=new RegExp('^(?:'+field.pattern+')$');
                    var bad="<x>' oNmouse=1 "+Math.random().toString(36).substr(2,4);
                    if(!re.test(bad) && field.probes.length<PER){
                        var pr3=probe(el,'pattern-violate',bad,true);
                        field.probes.push(pr3);
                        if(!pr3.rejected) out.anomalies.push('Field "'+dispName+'" has a pattern but did not reject a non-matching value.');
                    }
                }catch(e){}
            }
            // 4) info notes
            var textLike = ['text','search','textarea','email','url','tel','password'].indexOf((el.type||el.tagName.toLowerCase()).toLowerCase())>=0 || el.isContentEditable;
            if(textLike && field.maxlength==null) field.notes.push('No maxlength: unbounded input length accepted (try very long input).');
            if(textLike){
                // Execute the full attack set; record acceptance (not an anomaly without server confirmation).
                var acceptedCats=[];
                for(var gi=0; gi<GENERIC.length && field.probes.length<PER; gi++){
                    var gp=probe(el, GENERIC[gi][0], GENERIC[gi][1], false);
                    field.probes.push(gp);
                    if(!gp.rejected) acceptedCats.push(GENERIC[gi][0]);
                }
                if(acceptedCats.indexOf('xss')>=0 || acceptedCats.indexOf('xss-attr')>=0 || acceptedCats.indexOf('xss-svg')>=0)
                    field.notes.push('Accepts HTML/script markup verbatim; verify where this value is later rendered (use submit=true or check the page).');
                if(acceptedCats.length>0)
                    field.notes.push('Accepted these payload types unchanged: '+acceptedCats.join(', ')+'.');
            }
            out.fields.push(field);
        }
        try{ if(form) form.removeAttribute('data-trowser-af'); }catch(e){}
        // Re-add marker only if we will need it for submit phase (kept on the form for the caller)
        try{ if(form) form.setAttribute('data-trowser-af', marker); }catch(e){}
        return JSON.stringify(out);
        """;

    // Phase B: replay the form via in-page fetch with attack payloads. Returns JSON { anomalies:[], note }.
    private const string AttackFormSubmitBody = """
        function deepQuery(sel){ try{var el=document.querySelector(sel); if(el) return el;}catch(e){} return null; }
        var form=document.querySelector('form[data-trowser-af="'+MARKER+'"]');
        if(!form) return Promise.resolve(JSON.stringify({anomalies:[], note:'Submit phase skipped: form no longer present.'}));
        var action=form.getAttribute('action')||location.href;
        var method=(form.method||'get').toLowerCase();
        var enctype=(form.enctype||'application/x-www-form-urlencoded').toLowerCase();
        // Same-origin only (avoid CORS surprises and off-site submissions)
        var abs; try{ abs=new URL(action, location.href); }catch(e){ return Promise.resolve(JSON.stringify({anomalies:[], note:'Submit phase skipped: bad action URL.'})); }
        if(abs.origin!==location.origin) return Promise.resolve(JSON.stringify({anomalies:[], note:'Submit phase skipped: form posts cross-origin ('+abs.origin+').'}));

        function baseParams(){
            var fd=new FormData(form); var obj=[];
            fd.forEach(function(v,k){ obj.push([k, typeof v==='string'?v:'']); });
            return obj;
        }
        var editable=[]; var els=form.querySelectorAll('input,textarea');
        for(var i=0;i<els.length;i++){ var t=(els[i].type||'text').toLowerCase(); if(['hidden','submit','button','reset','file','checkbox','radio','password'].indexOf(t)>=0)continue; if(!els[i].name)continue; editable.push(els[i].name); }
        var PAYLOADS=[['xss','<script>alert(1)</script>'],['sqli',"' OR 1=1--"],['neg','-1']];
        var STACK=/(java\.lang\.|System\.\w+Exception|Traceback \(most recent|ORA-\d{5}|SQL syntax|stack trace|at [\w\.]+\([\w]+\.\w+:\d+\))/i;

        function encode(params){
            if(enctype.indexOf('multipart')>=0){ var fd=new FormData(); params.forEach(function(p){fd.append(p[0],p[1]);}); return fd; }
            return params.map(function(p){return encodeURIComponent(p[0])+'='+encodeURIComponent(p[1]);}).join('&');
        }
        var jobs=[]; var anomalies=[]; var count=0; var MAXREQ=24;
        outer:
        for(var fi=0; fi<editable.length; fi++){
            for(var pi=0; pi<PAYLOADS.length; pi++){
                if(count>=MAXREQ) break outer;
                count++;
                (function(fname, cat, payload){
                    var params=baseParams().map(function(p){ return p[0]===fname?[p[0],payload]:p; });
                    var url=abs.href; var opts={method:method.toUpperCase(), credentials:'include', redirect:'manual', headers:{}};
                    if(method==='get'){ var u=new URL(abs.href); params.forEach(function(p){u.searchParams.set(p[0],p[1]);}); url=u.href; }
                    else { var body=encode(params); if(!(body instanceof FormData)) opts.headers['Content-Type']='application/x-www-form-urlencoded'; opts.body=body; }
                    jobs.push(fetch(url,opts).then(function(res){
                        return res.text().then(function(txt){
                            if(res.status>=500) anomalies.push('Server error HTTP '+res.status+' when '+fname+'='+cat+' ("'+payload.substr(0,40)+'").');
                            if(STACK.test(txt)) anomalies.push('Stack-trace / server error text disclosed when '+fname+'='+cat+'.');
                            if(cat==='xss' && txt.indexOf('<script>alert(1)</script>')>=0) anomalies.push('Payload reflected unescaped in response for '+fname+' (possible XSS).');
                        });
                    }).catch(function(e){}));
                })(editable[fi], PAYLOADS[pi][0], PAYLOADS[pi][1]);
            }
        }
        return Promise.all(jobs).then(function(){
            try{ form.removeAttribute('data-trowser-af'); }catch(e){}
            var note = count>=MAXREQ ? 'Submit phase capped at '+MAXREQ+' requests.' : ('Submit phase sent '+count+' request(s).');
            return JSON.stringify({anomalies:anomalies, note:note});
        });
        """;
}
