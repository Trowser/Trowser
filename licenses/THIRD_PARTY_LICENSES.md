# Third-Party Licenses

Trowser bundles the following open-source libraries. Full license texts are in the adjacent files.

| Library | License | File |
|---------|---------|------|
| gremlins.js | MIT | gremlins.js-MIT.txt |
| axe-core | Mozilla Public License 2.0 | axe-core-MPL-2.0.txt |
| html-validate | MIT | html-validate-MIT.txt |
| retire.js (jsrepository.json) | Apache License 2.0 | retire.js-Apache-2.0.txt |
| web-vitals | Apache License 2.0 | web-vitals-Apache-2.0.txt |
| csp-evaluator | Apache License 2.0 | csp-evaluator-Apache-2.0.txt |
| tldts | MIT | tldts-MIT.txt |
| nuclei-templates (curated subset) | MIT | nuclei-templates-MIT.txt |

Optional external corpora (not bundled; used when `payloadProfile=big` and `corpora/` or `%TROWSER_CORPORA%` is present):

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
