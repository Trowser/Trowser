# Third-Party Licenses

Trowser bundles the following open-source components. Full license texts are in the adjacent files. Unless noted otherwise, bundled files are redistributed unmodified; versions are pinned in `scripts/vendored-libs.json` and `src/Trowser/Trowser.csproj`.

## JavaScript libraries and data (embedded in `src/Trowser/Resources/`)

| Component | Version | License | File |
|-----------|---------|---------|------|
| gremlins.js | 2.2.0 | MIT | gremlins.js-MIT.txt |
| axe-core | 4.14.0 | Mozilla Public License 2.0 (unmodified; source: https://github.com/dequelabs/axe-core) | axe-core-MPL-2.0.txt |
| html-validate | 11.17.0 | MIT | html-validate-MIT.txt |
| html-validate bundled dependencies (ajv, fast-deep-equal, json-schema-traverse, fast-uri, semver, kleur, @sidvind/better-ajv-errors, jsonpointer, leven, text-table, deepmerge) | as resolved by html-validate 11.17.0 | MIT, ISC, BSD-3-Clause, Apache 2.0 | html-validate-bundled-dependencies.txt |
| web-vitals | 6.2.3 | Apache License 2.0 | web-vitals-Apache-2.0.txt |
| csp-evaluator | 1.1.8 | Apache License 2.0 | csp-evaluator-Apache-2.0.txt |
| tldts | 7.4.19 | MIT | tldts-MIT.txt |
| Public Suffix List (data embedded in tldts) | as shipped with tldts 7.4.19 | Mozilla Public License 2.0 (unmodified; source: https://github.com/publicsuffix/list) | PublicSuffixList-MPL-2.0.txt |
| retire.js (jsrepository.json) | — | Apache License 2.0 | retire.js-Apache-2.0.txt |
| nuclei-templates (curated subset) | — | MIT | nuclei-templates-MIT.txt |

## .NET packages and runtime (release builds)

| Component | Version | License | File |
|-----------|---------|---------|------|
| Markdig | 1.6.0 | BSD-2-Clause | dotnet-packages.txt |
| YamlDotNet | 18.1.0 | MIT | dotnet-packages.txt |
| Microsoft.CodeAnalysis.CSharp.Scripting (Roslyn) | 5.9.0 | MIT | dotnet-packages.txt |
| System.Security.Cryptography.ProtectedData | 10.0.15 | MIT | dotnet-packages.txt |
| .NET runtime (self-contained publish) | 8.0 | MIT | dotnet-packages.txt |
| Microsoft.Web.WebView2 SDK | 1.0.4314.35 | Microsoft license | dotnet-packages.txt |

The `Trowser-<version>-webview2.zip` package also contains the **Microsoft Edge WebView2 Fixed Version runtime** in `WebView2Runtime/`. It is Microsoft software distributed under Microsoft's WebView2 runtime license terms (https://developer.microsoft.com/microsoft-edge/webview2/), not under Trowser's license.

## Optional external corpora

Not bundled; used when `payloadProfile=big` and `corpora/` or `%TROWSER_CORPORA%` is present.

| Corpus | License | File |
|--------|---------|------|
| SecLists | MIT | SecLists-MIT.txt |
| PayloadsAllTheThings | MIT | PayloadsAllTheThings-MIT.txt |

## Summary

- **gremlins.js** – Monkey testing for page robustness. https://github.com/marmelab/gremlins.js
- **axe-core** – WCAG accessibility auditing. https://github.com/dequelabs/axe-core
- **html-validate** – HTML markup validation. https://github.com/html-validate/html-validate
- **retire.js** – Vulnerability database (jsrepository.json) for JavaScript library security scanning. https://github.com/RetireJS/retire.js
- **web-vitals** – Core Web Vitals performance measurement (LCP, CLS, INP, TTFB, FCP). https://github.com/GoogleChrome/web-vitals
- **csp-evaluator** – Content-Security-Policy bypass and hardening analysis. https://github.com/google/csp-evaluator
- **tldts** – Public Suffix List–based domain / eTLD+1 parsing. https://github.com/remusao/tldts
- **nuclei-templates** – Curated HTTP templates for the native Nuclei-compatible runner. https://github.com/projectdiscovery/nuclei-templates
- **SecLists** / **PayloadsAllTheThings** – Optional large payload corpora for `payloadProfile=big`. Fetch via `scripts/fetch-corpora.ps1`.
