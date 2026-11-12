// @title Attack Form
// @shadow never
// @effects mutates
// Attack this form - the adaptive quicktest.
//
// Inspects the LIVE page: discovers the editable fields wired to a form, infers each
// field's semantic type (email, number, date, url, tel, text), and probes them with
// type-aware payloads to expose client-side validation gaps - required fields that are
// not enforced, "email"/"number"/"date" fields implemented as plain text with no
// validation, unenforced pattern/min/max constraints, and unbounded-length inputs.
//
// Two ways to aim it:
//   - Right-click a form / submit button / field and choose Run Script (uses that element).
//   - Run it directly and it auto-picks the primary form on the page.
//
// This client-side pass does NOT submit the form (safe, no navigation, no server state
// change). To also replay the form server-side (flags 5xx, stack traces, reflected XSS),
// set submit = true below. That mutates server state - only do it when that is acceptable.

var submit = false;

Log($"URL: {await GetCurrentUrl()}");

// If launched from a right-click, target that element; otherwise auto-pick the primary form.
var target = string.IsNullOrEmpty(This) ? null : RunScriptTarget;

var report = await AttackFormReport(target, submit: submit);
Log(report);
