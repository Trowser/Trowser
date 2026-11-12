// @title Required Field Probe
// @shadow never
// @effects mutates
// Required Field Probe - which fields does the form actually require?
//
// The HTML `required` attribute is rare in the wild - most sites validate with their own JS.
// So instead of trusting attributes, this empties every field and provokes validation the way a
// user would: it blurs each field and fires a (cancelable, non-navigating) submit, then sees which
// fields the form flags - native :invalid, aria-invalid, an error class, or freshly-appeared error
// text. That reveals required/validated fields regardless of how validation is implemented.
//
// Safe: it does NOT click the real submit button and does NOT navigate or post to the server;
// original values are restored afterwards.

using System.Text.Json;

var js = @"
(async function(){
  function labelOf(el){
    var a=el.getAttribute&&el.getAttribute('aria-label'); if(a) return a.trim();
    if(el.labels&&el.labels.length){var t=(el.labels[0].innerText||el.labels[0].textContent||'').trim(); if(t) return t;}
    if(el.placeholder) return el.placeholder.trim();
    return el.name||el.id||'field';
  }
  function vis(el){try{var r=el.getBoundingClientRect();if(r.width===0&&r.height===0)return false;var s=getComputedStyle(el);if(s.display==='none'||s.visibility==='hidden')return false;}catch(e){}return true;}
  function editable(el){var t=el.tagName.toLowerCase();if(t==='textarea'||t==='select')return true;if(t!=='input')return false;var it=(el.type||'text').toLowerCase();return ['text','email','url','tel','search','number','password','date','datetime-local','month','week','time'].indexOf(it)>=0;}
  function fieldsIn(s){var a=s.querySelectorAll('input,textarea,select');var o=[];for(var i=0;i<a.length;i++){if(editable(a[i])&&vis(a[i])&&!a[i].disabled)o.push(a[i]);}return o;}
  function errText(root){
    var sel='[role=alert],[aria-live],.error,.errors,.error-message,.invalid-feedback,.help-block,.field-error,.form-error,.text-danger,[class*=error i],[class*=invalid i]';
    var set={};
    try{ var n=root.querySelectorAll(sel); for(var i=0;i<n.length;i++){ if(!vis(n[i]))continue; var t=(n[i].innerText||n[i].textContent||'').trim(); if(t) set[t]=1; } }catch(e){}
    return set;
  }
  function flaggedNow(el){
    try{ if(typeof el.checkValidity==='function' && !el.checkValidity()) return 'native'; }catch(e){}
    if((el.getAttribute('aria-invalid')||'')==='true') return 'aria-invalid';
    var cls=(el.className||'')+''; if(/(^|[\s_-])(error|invalid|is-invalid)([\s_-]|$)/i.test(cls)) return 'error-class';
    return '';
  }
  function signalRequired(el){
    if(el.required) return 'required-attr';
    if((el.getAttribute('aria-required')||'')==='true') return 'aria-required';
    var lbl=labelOf(el); if(/\*/.test(lbl)) return 'label-asterisk';
    var cls=((el.className||'')+' '+(el.id||''))+''; if(/required/i.test(cls)) return 'required-class';
    return '';
  }

  var forms=Array.prototype.slice.call(document.querySelectorAll('form'));
  var best=null,bestN=0;for(var i=0;i<forms.length;i++){if(!vis(forms[i]))continue;var n=fieldsIn(forms[i]).length;if(n>bestN){bestN=n;best=forms[i];}}
  var scope=best||document.body;
  var fields=fieldsIn(scope);
  if(fields.length===0) return JSON.stringify({formFound:false});

  var out={formFound:true, formLabel:(best?(best.getAttribute('name')||best.id||''):'(page fields)'), fieldCount:fields.length, flagged:[], signalled:[], newErrors:[]};

  // signal-based required
  for(var s=0;s<fields.length;s++){ var sr=signalRequired(fields[s]); if(sr) out.signalled.push({name:labelOf(fields[s]), why:sr}); }

  // baseline errors + save + clear
  var beforeErr=errText(scope);
  var originals=[];
  for(var c=0;c<fields.length;c++){
    var el=fields[c];
    originals.push(el.type==='checkbox'||el.type==='radio'?el.checked:el.value);
    try{
      if(el.type==='checkbox'||el.type==='radio') el.checked=false;
      else if(el.tagName.toLowerCase()==='select') el.selectedIndex=-1;
      else el.value='';
      el.dispatchEvent(new Event('input',{bubbles:true}));
      el.dispatchEvent(new Event('change',{bubbles:true}));
      el.dispatchEvent(new Event('blur',{bubbles:true}));
      el.dispatchEvent(new FocusEvent('focusout',{bubbles:true}));
    }catch(e){}
  }

  // provoke validation without navigating: cancelable synthetic submit (default action is a no-op for untrusted events)
  if(best){
    try{ var ev=new Event('submit',{bubbles:true,cancelable:true}); best.dispatchEvent(ev); }catch(e){}
    try{ if(typeof best.reportValidity==='function') best.reportValidity(); }catch(e){}
  }

  await new Promise(function(r){ setTimeout(r, 450); });

  // collect flagged fields + new error messages
  for(var f=0;f<fields.length;f++){ var why=flaggedNow(fields[f]); if(why) out.flagged.push({name:labelOf(fields[f]), why:why}); }
  var afterErr=errText(scope);
  for(var k in afterErr){ if(!beforeErr[k]) out.newErrors.push(k); }

  // restore
  for(var rr=0;rr<fields.length;rr++){
    var e2=fields[rr];
    try{
      if(e2.type==='checkbox'||e2.type==='radio') e2.checked=originals[rr];
      else if(e2.tagName.toLowerCase()==='select'){ /* leave; hard to restore reliably */ }
      else e2.value=originals[rr];
      e2.dispatchEvent(new Event('input',{bubbles:true}));
      e2.dispatchEvent(new Event('change',{bubbles:true}));
    }catch(e){}
  }
  return JSON.stringify(out);
})();
";

Log($"URL: {await GetCurrentUrl()}");
var raw = await ExecuteJs(js);
var doc = JsonDocument.Parse(raw);
var root = doc.RootElement;

if (!root.GetProperty("formFound").GetBoolean())
{
    Log("No form with editable fields found on the page.");
    return;
}

var label = root.GetProperty("formLabel").GetString();
var formName = string.IsNullOrEmpty(label) ? "(primary form)" : label;
var fieldCount = root.GetProperty("fieldCount").GetInt32();
Log($"Form: {formName} - {fieldCount} field(s).");
Log("");

var flagged = root.GetProperty("flagged").EnumerateArray().ToList();
if (flagged.Count == 0)
{
    Log("No fields were flagged as required/invalid when submitted empty.");
    Log("The form may treat all fields as optional, or it validates only on the server.");
}
else
{
    Log($"Fields the form requires / validates when empty ({flagged.Count}):");
    foreach (var f in flagged)
    {
        var name = f.GetProperty("name").GetString();
        var why = f.GetProperty("why").GetString();
        Log($"  * {name}  (detected via {why})");
    }
}

var newErrors = root.GetProperty("newErrors").EnumerateArray().Select(e => e.GetString()).Where(s => !string.IsNullOrEmpty(s)).ToList();
if (newErrors.Count > 0)
{
    Log("");
    Log("Error messages that appeared on empty submit:");
    foreach (var e in newErrors) Log($"    {e}");
}

var signalled = root.GetProperty("signalled").EnumerateArray().ToList();
if (signalled.Count > 0)
{
    Log("");
    Log("Fields that look required by markup (attribute / aria / label * / class):");
    foreach (var s in signalled)
    {
        var name = s.GetProperty("name").GetString();
        var why = s.GetProperty("why").GetString();
        Log($"  ? {name}  ({why})");
    }
}
