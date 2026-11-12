// @title Click Frenzy
// @shadow never
// @effects mutates
// Right-click an element and select **Run Script**.
// Set clickCount as needed. Uses RapidClick so multiple real clicks are delivered at the same
// coordinates without waiting for navigation after each — like accidental double-clicks on
// login / add-to-cart (plain Click() would wait for nav and then fail to find the target).

var clickCount = 10;

if (string.IsNullOrEmpty(This))
{
    Log("Right-click and select Run Script to use this quicktest.");
    return;
}

await RapidClick(RunScriptTarget, clickCount);

Log($"Done: {clickCount} rapid click(s) on Run Script target.");
