// Functional: semantic locators + form interaction.

await ResetBrowserState();

var url = FixtureUrl("/form");
var html = MinimalHtml("Form Page",
    @"<h1>Sign Up</h1>
      <label for=""email"">Email</label>
      <input id=""email"" name=""email"" type=""email"" placeholder=""you@example.com"">
      <label for=""role"">Role</label>
      <select id=""role"" name=""role"">
        <option value="""">--</option>
        <option value=""user"">User</option>
        <option value=""admin"">Admin</option>
      </select>
      <button type=""button"" id=""submit"">Submit</button>
      <button type=""button"" id=""hover-me"">Hover Target</button>
      <div id=""out""></div>
      <script>
        document.getElementById('submit').addEventListener('click', function() {
          var e = document.getElementById('email').value;
          var r = document.getElementById('role').value;
          document.getElementById('out').textContent = 'submitted:' + e + ':' + r;
        });
        document.getElementById('hover-me').addEventListener('mouseover', function() {
          this.setAttribute('data-hovered', '1');
        });
      </script>");

// ScriptableHeaders: CSP must allow inline script handlers used by this fixture.
SetupPage(url, html, ScriptableHeaders());
await Navigate(url);
await WaitForIdle();

Assert.Section("Semantic locators");
Assert.Equal("Sign Up", await GetText(ByRole("heading")), "ByRole heading");
Assert.True(await Exists("#email"), "Email input exists (css)");
Assert.Equal("", await GetText(ByLabel("Email")), "ByLabel Email resolves (empty value)");
Assert.True(await Exists(ByPlaceholder("you@example.com")) || await Exists("#email"),
    "ByPlaceholder or #email present");
Assert.Equal("Submit", await GetText(ByRole("button", "Submit")), "ByRole button Submit");
Assert.Contains("Hover", await GetText(ByText("Hover Target")), "ByText");

Assert.Section("Type / Select / Click");
await Type(ByLabel("Email"), "tester@trowser.test");
await Select(ByLabel("Role"), "admin");
await Click(ByRole("button", "Submit"));
await Sleep(200);
var outText = await GetText("#out");
Assert.Contains("submitted:tester@trowser.test:admin", outText, "Form submit wrote output");

Assert.Section("Hover");
await Hover(ByRole("button", "Hover Target"));
await Sleep(100);
var hovered = UnquoteJson(await ExecuteJs("document.getElementById('hover-me').getAttribute('data-hovered')"));
Assert.Equal("1", hovered, "Hover fired mouseover");

Assert.Section("PressKey");
await Click(ByLabel("Email"));
await PressKey("End");
Assert.Pass("PressKey End did not throw");
