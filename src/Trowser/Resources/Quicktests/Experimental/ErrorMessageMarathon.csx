// @title Error Message Marathon
// @shadow never
// @effects mutates
// Error Message Marathon (experimental) - harvest a form's validation messages in one pass.
//
// For the primary form, deliberately makes every field invalid (clears required fields, puts
// a bad value into typed fields), asks the browser to validate, and collects every resulting
// error message - both native constraint-validation messages and any app-rendered error text
// (role=alert, aria-invalid, .error / .invalid-feedback / .help-block, etc.). The point is to
// read all your error copy side by side and judge it for clarity, consistency, tone, and
// whether messages are actionable. Client-side only; values are restored afterwards.

using System.Text.Json;

var js = @"
(function(){
  function labelOf(el){
    var a=el.getAttribute&&el.getAttribute('aria-label'); if(a) return a.trim();
    if(el.labels&&el.labels.length){var t=(el.labels[0].innerText||el.labels[0].textContent||'').trim(); if(t) return t;}
    if(el.placeholder) return el.placeholder.trim();
    return el.name||el.id||'field';
  }
  function vis(el){try{var r=el.getBoundingClientRect();if(r.width===0&&r.height===0)return false;var s=getComputedStyle(el);if(s.display==='none'||s.visibility==='hidden')return false;}catch(e){}return true;}
  function editable(el){var t=el.tagName.toLowerCase();if(t==='textarea')return true;if(t!=='input')return false;var it=(el.type||'text').toLowerCase();return ['text','email','url','tel','search','number','date','datetime-local','month','week','time','password'].indexOf(it)>=0;}
  function fieldsIn(s){var a=s.querySelectorAll('input,textarea,select');var o=[];for(var i=0;i<a.length;i++){if((editable(a[i])||a[i].tagName.toLowerCase()==='select')&&vis(a[i])&&!a[i].disabled)o.push(a[i]);}return o;}
  var forms=Array.prototype.slice.call(document.querySelectorAll('form'));
  var best=null,bestN=0;for(var i=0;i<forms.length;i++){if(!vis(forms[i]))continue;var n=fieldsIn(forms[i]).length;if(n>bestN){bestN=n;best=forms[i];}}
  if(!best) return JSON.stringify({formFound:false});
  var fields=fieldsIn(best);

  function badFor(el){
    var it=(el.type||'text').toLowerCase();
    if(it==='email')return 'plainaddress';
    if(it==='number')return 'abc';
    if(it==='url')return 'notaurl';
    if(it==='date'||it==='datetime-local'||it==='month'||it==='week'||it==='time')return 'not-a-date';
    return '';  // clear it (bad for required)
  }
  var originals=[];
  for(var f=0;f<fields.length;f++){
    var el=fields[f]; originals.push(el.value);
    try{ el.value=badFor(el); el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); el.dispatchEvent(new Event('blur',{bubbles:true})); }catch(e){}
  }
  var messages=[];
  // Native constraint validation messages
  for(var f2=0;f2<fields.length;f2++){
    var el2=fields[f2];
    try{ if(typeof el2.checkValidity==='function' && !el2.checkValidity() && el2.validationMessage) messages.push({field:labelOf(el2), source:'native', text:el2.validationMessage}); }catch(e){}
  }
  // App-rendered error text
  var sel='[role=alert],[aria-live=assertive],.error,.errors,.error-message,.invalid-feedback,.help-block,.field-error,.form-error,.text-danger,[class*=error i]';
  var seen={};
  try{
    var nodes=best.querySelectorAll(sel);
    for(var n=0;n<nodes.length;n++){
      var node=nodes[n]; if(!vis(node))continue;
      var t=(node.innerText||node.textContent||'').trim();
      if(t && !seen[t]){ seen[t]=1; messages.push({field:'', source:'app', text:t}); }
    }
    // aria-invalid fields with described-by text
    var inv=best.querySelectorAll('[aria-invalid=true]');
    for(var iv=0;iv<inv.length;iv++){
      var db=inv[iv].getAttribute('aria-describedby');
      if(db){ var d=document.getElementById(db); if(d){ var dt=(d.innerText||d.textContent||'').trim(); if(dt&&!seen[dt]){seen[dt]=1;messages.push({field:labelOf(inv[iv]),source:'app',text:dt});} } }
    }
  }catch(e){}
  // restore
  for(var r=0;r<fields.length;r++){ try{ fields[r].value=originals[r]; fields[r].dispatchEvent(new Event('input',{bubbles:true})); fields[r].dispatchEvent(new Event('change',{bubbles:true})); }catch(e){} }
  return JSON.stringify({formFound:true, formLabel:(best.getAttribute('name')||best.id||''), fieldCount:fields.length, messages:messages});
})();
";

Log($"URL: {await GetCurrentUrl()}");
var raw = await ExecuteJs(js);
var doc = JsonDocument.Parse(raw);
var root = doc.RootElement;

if (!root.GetProperty("formFound").GetBoolean())
{
    Log("No form found on the page.");
    return;
}

var label = root.GetProperty("formLabel").GetString();
var formName = string.IsNullOrEmpty(label) ? "(primary form)" : label;
var fieldCount = root.GetProperty("fieldCount").GetInt32();
Log($"Form: {formName} - {fieldCount} field(s) probed.");
Log("");

var messages = root.GetProperty("messages").EnumerateArray().ToList();
if (messages.Count == 0)
{
    Log("No validation messages surfaced. The form may not validate client-side, or messages appear only after a real submit.");
    return;
}

Log($"Collected {messages.Count} error message(s) - review for clarity, consistency and tone:");
Log("");
foreach (var m in messages)
{
    var field = m.GetProperty("field").GetString();
    var source = m.GetProperty("source").GetString();
    var text = m.GetProperty("text").GetString();
    var prefix = string.IsNullOrEmpty(field) ? $"[{source}]" : $"[{source}] {field}:";
    Log($"  {prefix} {text}");
}
