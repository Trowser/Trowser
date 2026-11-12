// @title Copy Paste Vs Type
// @shadow never
// @effects mutates
// Copy/Paste vs Type - does a field behave differently when pasted vs typed?
//
// Many fields format or validate on every keystroke (phone masks, card spacing, character
// allow-lists, live maxlength) but do nothing on PASTE - so pasted input slips past rules that
// typing enforces (or the reverse). This drives the same string into ONE field two ways and
// compares the result:
//   - Typed: fires keydown/keypress/input per character (runs per-keystroke handlers).
//   - Pasted: one paste event + bulk value set (skips per-keystroke handlers).
//
// The field is scrolled into view and highlighted, and each phase pauses briefly so you can WATCH
// it happen (blue outline = typing, orange = pasting). Right-click a field and choose Run Script to
// target it; otherwise the first visible text field of the primary form is used. The original value
// is restored at the end.

using System.Text.Json;

var thisSel = string.IsNullOrEmpty(This) ? "" : This;
var TEST = "aB3! xY9? zQ_12345";

// --- Phase 1: locate + highlight the target field ---
var findJs = @"
(function(){
  var THIS = " + JsonSerializer.Serialize(thisSel) + @";
  function deepQuery(sel){ try{var el=document.querySelector(sel); if(el) return el;}catch(e){} return null; }
  function vis(el){try{var r=el.getBoundingClientRect();if(r.width===0&&r.height===0)return false;var s=getComputedStyle(el);if(s.display==='none'||s.visibility==='hidden')return false;}catch(e){}return true;}
  function labelOf(el){var a=el.getAttribute&&el.getAttribute('aria-label');if(a)return a.trim();if(el.labels&&el.labels.length){var t=(el.labels[0].innerText||el.labels[0].textContent||'').trim();if(t)return t;}if(el.placeholder)return el.placeholder.trim();return el.name||el.id||'field';}
  function textLike(el){if(el.tagName.toLowerCase()==='textarea')return true;if(el.tagName.toLowerCase()!=='input')return false;var it=(el.type||'text').toLowerCase();return ['text','email','url','tel','search','password'].indexOf(it)>=0;}
  var el=null;
  if(THIS){ el=deepQuery(THIS); }
  if(!el){
    var forms=Array.prototype.slice.call(document.querySelectorAll('form'));
    var best=null,bestN=0;
    for(var i=0;i<forms.length;i++){ if(!vis(forms[i]))continue; var n=forms[i].querySelectorAll('input,textarea').length; if(n>bestN){bestN=n;best=forms[i];} }
    var scope=best||document;
    var cands=scope.querySelectorAll('input,textarea');
    for(var c=0;c<cands.length;c++){ if(textLike(cands[c])&&vis(cands[c])&&!cands[c].disabled){ el=cands[c]; break; } }
  }
  if(!el) return JSON.stringify({found:false});
  if(!textLike(el)) return JSON.stringify({found:false, note:'Target is not a text-like field.'});
  el.setAttribute('data-cpvt','1');
  try{ el.scrollIntoView({behavior:'smooth',block:'center'}); }catch(e){}
  el.style.transition='outline 0.15s'; el.style.outline='3px solid #2d7dff'; el.style.outlineOffset='2px';
  el.focus();
  return JSON.stringify({found:true, field:labelOf(el), type:(el.type||el.tagName.toLowerCase()), maxLength:((el.maxLength&&el.maxLength>0)?el.maxLength:0), orig:el.value});
})();
";

var typeJs = @"
(function(){
  var el=document.querySelector('[data-cpvt=""1""]'); if(!el) return '';
  var TEST=" + JsonSerializer.Serialize(TEST) + @";
  var maxLen=(el.maxLength&&el.maxLength>0)?el.maxLength:0;
  el.style.outline='3px solid #2d7dff';
  el.focus(); el.value=''; el.dispatchEvent(new Event('input',{bubbles:true}));
  for(var k=0;k<TEST.length;k++){
    var ch=TEST[k];
    var kd; try{ kd=new KeyboardEvent('keydown',{key:ch,bubbles:true,cancelable:true}); }catch(e){ kd=null; }
    var cancelled = kd? !el.dispatchEvent(kd) : false;
    if(cancelled) continue;
    try{ el.dispatchEvent(new KeyboardEvent('keypress',{key:ch,bubbles:true,cancelable:true})); }catch(e){}
    if(!(maxLen && el.value.length>=maxLen)){ el.value=el.value+ch; el.dispatchEvent(new Event('input',{bubbles:true})); }
    try{ el.dispatchEvent(new KeyboardEvent('keyup',{key:ch,bubbles:true})); }catch(e){}
  }
  el.dispatchEvent(new Event('change',{bubbles:true})); el.dispatchEvent(new Event('blur',{bubbles:true}));
  return el.value;
})();
";

var pasteJs = @"
(function(){
  var el=document.querySelector('[data-cpvt=""1""]'); if(!el) return '';
  var TEST=" + JsonSerializer.Serialize(TEST) + @";
  var maxLen=(el.maxLength&&el.maxLength>0)?el.maxLength:0;
  el.style.outline='3px solid #ff8a00';
  el.focus(); el.value=''; el.dispatchEvent(new Event('input',{bubbles:true}));
  var prevented=false;
  try{ var dt=new DataTransfer(); dt.setData('text/plain',TEST); var pe=new ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:dt}); prevented=!el.dispatchEvent(pe); }catch(e){}
  if(!prevented){ var v=TEST; if(maxLen && v.length>maxLen) v=v.slice(0,maxLen); el.value=v; el.dispatchEvent(new Event('input',{bubbles:true})); }
  el.dispatchEvent(new Event('change',{bubbles:true})); el.dispatchEvent(new Event('blur',{bubbles:true}));
  return el.value;
})();
";

Log($"URL: {await GetCurrentUrl()}");
var findRaw = await ExecuteJs(findJs);
var root = JsonDocument.Parse(findRaw).RootElement;
if (!root.GetProperty("found").GetBoolean())
{
    var note = root.TryGetProperty("note", out var n) ? n.GetString() : null;
    Log(note ?? "No text-like field found. Right-click a text field and choose Run Script.");
    return;
}

var field = root.GetProperty("field").GetString();
var ftype = root.GetProperty("type").GetString();
var maxLen = root.GetProperty("maxLength").GetInt32();
var orig = root.GetProperty("orig").GetString() ?? "";
var maxNote = maxLen > 0 ? $", maxlength={maxLen}" : "";
Log($"Field: {field} (type={ftype}{maxNote})");
Log($"Sending: '{TEST}'");
await Sleep(700);

var typed = await ExecuteJs(typeJs);
Log($"Typed  -> '{typed}'  (len {typed?.Length})");
await Sleep(1100);

var pasted = await ExecuteJs(pasteJs);
Log($"Pasted -> '{pasted}'  (len {pasted?.Length})");
await Sleep(1100);

// restore original value + remove highlight
var restoreJs = @"
(function(){
  var el=document.querySelector('[data-cpvt=""1""]'); if(!el) return '';
  el.value=" + JsonSerializer.Serialize(orig) + @";
  el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true}));
  el.style.outline=''; el.style.outlineOffset=''; el.removeAttribute('data-cpvt');
  return 'ok';
})();
";
await ExecuteJs(restoreJs);

Log("");
if (typed != pasted)
{
    Log("! Typed and pasted results DIFFER - the field treats typing and pasting differently.");
    Log("  Likely a per-keystroke mask/validator that paste bypasses (or the reverse). Check whether");
    Log("  the bypassed path lets invalid / over-length / unformatted data through.");
}
else
{
    Log("Typed and pasted results match - no keystroke-vs-paste discrepancy for this input.");
}
