# Contributing to Trowser

Thanks for looking. Trowser is a Windows desktop app (.NET 8, WPF, WebView2). Issues and pull requests go to [github.com/Trowser/Trowser](https://github.com/Trowser/Trowser).

Please read [VISION.md](VISION.md) first. It says what the project is for. [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) covers how to behave in issues, pull requests, and discussions.

## Before you start

- Use Trowser in your testing so you get a feel for it, and see if you like it.
- Only use Trowser against systems you are authorized to test. Do not file issues that include customer hostnames, session cookies, API keys, or exploit details against a third party. If a report about Trowser itself depends on that material, use the contact in [SECURITY.md](SECURITY.md).
- Small fixes are the best way in: a wrong sentence in the docs, a failing test, a bug you can reproduce.
- For a new scanner, a new API surface, or bigger changes, open an issue before writing the code. Say what a tester can do afterward that they cannot do now.
- Build generic things that benefit many, product-specific things belong in user's own quicktests.
- Quicktest improvement and additions might be the easiest way to contribute in a safe manner.

## Working with an AI assistant

Most contributions here are written with an AI coding assistant, and that is welcome. Point it at [AGENTS.md](AGENTS.md); Cursor, Copilot, Codex, and most other agents read it automatically. [ARCHITECTURE.md](ARCHITECTURE.md) gives it the code map and step-by-step recipes.

You are still the author:

- You are responsible for every line in your pull request, and should be able to explain it in review.
- Run the tests yourself and try the change in the built `Trowser.exe`. "The model said it works" is not a test.
- Keep the diff to what the change needs. Assistants like to reformat, rename, and regenerate files nearby; drop that before you submit.
- Leave secrets, customer hosts, and session data out of prompts as well as out of the code.

## Build

Follow [BUILD.md](BUILD.md). Short version:

```powershell
dotnet build Trowser.sln -c Release
.\scripts\test.ps1 -Level smoke
```

`smoke` matches push CI: unit/contract tests, API smoke (WebView2 + `--serve`), and offline regression `01–07`. Use `.\scripts\test.ps1 -Level quick` when you only changed logic covered by `Trowser.Tests`. Use `-Level full` before large automation changes (ApiTests sweeps and the full regression suite — run locally; not on GitHub nightly).

Automated tests require **Windows** and **WebView2**. Optional: set `TROWSER_EXE` to the `Trowser.exe` you built.

After a change that can affect navigation, scripting, mocks, intercepts, audits, or security scanners, run at least smoke; run full regression when in doubt:

```powershell
.\tests\regression\run-regression.ps1
```

A failure is a signal to investigate. It can be a product bug, or a test that needs to move with the behavior. See [tests/regression/README.md](tests/regression/README.md).

We have no requirements on unit test coverage, use your own judgment.
But it is required to do testing on the built Trowser after your changes. Test that the intended value is there, without negative side-effects. Test yourself and/or with AI.

## Branching & Releasing

Development normally takes place in main, and a new release is complemented with a tag.
For experiments that should be committed, feel free to create a branch.

## Documentation

The map is [DOCUMENTATION.md](DOCUMENTATION.md).

- Behavior, parameters, and examples belong in `trowserkit/trowser-api-reference.md`.
- After you add or rename a REST route or an MCP tool, regenerate the API index and OpenAPI file:

```powershell
.\scripts\regen-docs.ps1
.\scripts\regen-docs.ps1 -Check
```

- Update `trowserkit/SecurityTestingWithTrowser.md` when the testing method changes, not for every new parameter.
- `CHANGELOG.md` is maintained by the maintainer. Leave it out of your pull request unless you were asked to edit it.

## Project layout

[ARCHITECTURE.md](ARCHITECTURE.md) has the detailed map, including the partial-class layout and how to add a route, tool, scanner, Quicktest, or regression test.

| Path | What it is |
|------|------------|
| `src/Trowser/` | The application |
| `src/Trowser.Tests/` | Unit and contract tests |
| `src/Trowser.ApiTests/` | REST/MCP smoke and OpenAPI sweeps (see `tests/README.md`) |
| `tests/regression/` | Black-box regression scripts |
| `trowserkit/` | Product guides and the API reference |
| `securitykit/` | Agent notes, scanner provenance, and the VPX format |
| `licenses/` | Third-party license texts |
| `scripts/` | Build, signing, and doc-generation scripts |

The repository `.gitignore` is a whitelist, so accidental artifacts never land in the repo. A new top-level file is ignored until it is named there. If your change adds a file outside the existing trees, add an exception in the same pull request.

## Code

Match the style of the file you are editing. A few habits that matter here:

- Keep secrets, tokens, and customer data out of source, tests, and fixtures. Canned probe tokens belong in the security payloads and are already obvious as probes.
- Safety modes are part of the contract. A probe that mutates server state stays behind `active` or `aggressive`.
- A new route or tool that runs code, sends raw HTTP, changes session state, or probes actively must be listed in `src/Trowser/Api/SafeModePolicy.cs`. One entry covers REST and MCP; `SafeModePolicyTests` fails if the two drift.
- Page content is untrusted. Anything that reaches generated code, HTML reports, or file paths must be escaped or validated where it is written.
- Prefer extending the existing automation context and API over a second path that only the GUI or only a script can reach.
- Third-party code stays under its own license. Do not strip copyright headers from files in `src/Trowser/Resources/`. If you vendor a library, add it to `licenses/` and to `licenses/THIRD_PARTY_LICENSES.md`.

## Pull requests

- Describe the tester-visible change, and how you tested it.
- Keep the diff focused. Unrelated cleanup belongs in its own change.
- If the API changed, include the regenerated index and OpenAPI file, and the reference-doc edit.

## License of contributions

By submitting a contribution, you agree that it is licensed under the same terms as the project. See [LICENSE](LICENSE).

## Contact

Questions that do not belong in an issue: rikard.edgren@thetesteye.com.
