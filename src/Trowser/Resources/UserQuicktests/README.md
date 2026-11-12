# Write your own Trowser quicktest

This folder is your personal quicktest library. Any `.csx` file you put here shows up in
Trowser under the **Quicktests** button, inside the **UserScripts** submenu. Subfolders
become nested submenus, so you can organise your scripts however you like.

## Quick start

1. Copy `ExampleQuicktest.csx` (in this folder) to a new name, e.g. `MyCheck.csx`.
2. Edit it. A quicktest is just a normal Trowser C# script — the same API the built-in
   quicktests use is available (see below).
3. In Trowser, click **Quicktests → UserScripts → MyCheck**. The script loads into the
   Script Console; press **Run** (or `Ctrl+Enter`) to execute it against the current page.

The menu rescans this folder every time you open it, so new files appear immediately —
no need to restart Trowser. Use **UserScripts → Open folder…** to jump here from the menu.

## What you can use

Quicktests run with the same globals as any Trowser script. The most common building blocks:

- **Navigation / waiting:** `await Navigate(url)`, `await WaitForElement(selector, ms)`,
  `await WaitForIdle(quietMs, timeoutMs)`
- **Page inspection:** `await GetCurrentUrl()`, `await GetTitle()`, `await GetHeadings()`,
  `await GetLinks()`, `await GetImages()`, `await ExecuteJs(js)`
- **Interaction:** `await Click(selector)`, `await Type(selector, text)`
- **Assertions & output:** `Assert.Section("...")`, `Assert.True(...)`, `Assert.Equal(...)`,
  `Assert.NotEmpty(...)`, `Log("...")`
- **Diagnostics:** `GetPageConsoleErrors()`, `Network.FindPageErrors()`
- **Right-click target:** when a quicktest is launched against an element, `This` holds its
  selector (used by adaptive quicktests such as "Attack this form").

For the complete API, see `trowserkit/scripting-reference.md` in the Trowser kit, or click
**Script Help** in the Script Console.

## Tips

- Keep destructive actions behind an explicit safety check — user quicktests are **not**
  included in the randomized "Surprise Me" pool, but they still run with full script access.
- The file name (without `.csx`) is what appears in the menu, so name them clearly.
- Comment the top of each script with what it does and whether it mutates server state.
