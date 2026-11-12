// @title Reload State Persistence
// @shadow never
// @effects mutates
// Reload State Persistence - do in-progress inputs survive a page reload?
//
// Captures the current values of editable fields, reloads the page, then compares. Fields
// that held a value before but come back empty (or changed) are reported. Losing a half-filled
// form on an accidental refresh is a classic, high-annoyance bug. This does NOT submit anything;
// it only re-navigates to the current URL.

using System.Text.Json;

var captureJs = @"
(function(){
  function vis(el){try{var r=el.getBoundingClientRect();if(r.width===0&&r.height===0)return false;var s=getComputedStyle(el);if(s.display==='none'||s.visibility==='hidden')return false;}catch(e){}return true;}
  function key(el,i){return (el.name||el.id||el.tagName.toLowerCase())+'#'+i;}
  var all=document.querySelectorAll('input,textarea,select');
  var out=[];
  for(var i=0;i<all.length;i++){
    var el=all[i]; var t=(el.type||'').toLowerCase();
    if(['hidden','submit','button','reset','file','password'].indexOf(t)>=0) continue;
    if(!vis(el)||el.disabled) continue;
    var v;
    if(t==='checkbox'||t==='radio') v = el.checked?'[checked]':'[unchecked]';
    else v = el.value;
    out.push({key:key(el,i), value:(v||'')});
  }
  return JSON.stringify(out);
})();
";

var url = await GetCurrentUrl();
Log($"URL: {url}");

var beforeRaw = await ExecuteJs(captureJs);
var before = JsonDocument.Parse(beforeRaw).RootElement.EnumerateArray()
    .ToDictionary(e => e.GetProperty("key").GetString()!, e => e.GetProperty("value").GetString() ?? "");

var nonEmpty = before.Where(kv => !string.IsNullOrEmpty(kv.Value) && kv.Value != "[unchecked]").ToList();
Log($"Captured {before.Count} field(s); {nonEmpty.Count} had a value before reload.");

if (nonEmpty.Count == 0)
{
    Log("No filled-in fields to test. Type into the form first, then run this quicktest.");
    return;
}

Log("Reloading...");
await Reload();
await Sleep(800);

var afterRaw = await ExecuteJs(captureJs);
var after = JsonDocument.Parse(afterRaw).RootElement.EnumerateArray()
    .ToDictionary(e => e.GetProperty("key").GetString()!, e => e.GetProperty("value").GetString() ?? "");

var lost = new List<string>();
var changed = new List<string>();
var kept = 0;

foreach (var kv in nonEmpty)
{
    after.TryGetValue(kv.Key, out var newVal);
    newVal ??= "";
    if (string.IsNullOrEmpty(newVal) || newVal == "[unchecked]") lost.Add(kv.Key);
    else if (newVal != kv.Value) changed.Add($"{kv.Key}: '{kv.Value}' -> '{newVal}'");
    else kept++;
}

Log("");
Log($"After reload: {kept} kept, {lost.Count} lost, {changed.Count} changed.");
if (lost.Count > 0)
{
    Log("Fields that LOST their value on reload:");
    foreach (var l in lost) Log($"  ! {l}");
}
if (changed.Count > 0)
{
    Log("Fields that CHANGED on reload:");
    foreach (var c in changed) Log($"  ~ {c}");
}
if (lost.Count == 0 && changed.Count == 0)
    Log("All filled-in values persisted across the reload.");
