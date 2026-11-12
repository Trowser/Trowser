# Security policy

This file is about vulnerabilities in **Trowser itself**: the Windows application, its localhost API, scripting host, and update/install story.

It is not the place to report vulnerabilities in a site you examined with Trowser. Those belong to that site's owner, and only if you are allowed to test it.

How Trowser's own trust model works (localhost binding, API key, safe mode, what is explicitly not a sandbox) is written up in [trowserkit/SECURITY.md](trowserkit/SECURITY.md).

## Reporting

Email rikard.edgren@thetesteye.com with the subject line `Trowser security`.

Include:

- Trowser version (`About`, or the exe version)
- What you can make Trowser do that a local user should not be able to make it do
- Whether the API key was required, and whether safe mode was on
- A minimal repro that does not depend on a third-party production system

Please do not open a public GitHub issue for an unfixed vulnerability. Do not include live API keys, customer hostnames, session cookies, or a proof that would harm a third party. If the report needs that material, say so in the email and we will arrange a way to share it.

## What helps

The interesting bugs are ones that cross a boundary the product claims to hold:

- Reaching the API from a non-loopback host, or reading API responses from a non-loopback web origin
- Bypassing the API key when the key is required
- A page in the browser reaching the API, or the user's files, beyond what [trowserkit/SECURITY.md](trowserkit/SECURITY.md) already says a local caller can do
- Safe mode failing to block an operation it documents as blocked
- A script, import, or export path that writes outside the location the user chose

## What is in scope to know, and usually out of scope to "fix"

Trowser is a full-trust local tool. Anyone who can call the API with the key can drive the browser, run JavaScript in the page, and run C# in the Trowser process. That is the product. A report that restates this, with the key already in hand, will be closed with a pointer to the threat model.

Also out of scope:

- Vulnerabilities in a target application you tested
- Chromium / WebView2 issues with no Trowser-specific twist (report those to Microsoft)
- SmartScreen warnings on the self-signed build. See [SMARTScreen.md](SMARTScreen.md)
- Missing telemetry, or the absence of an auto-updater

## Response

You should get an acknowledgement within a few days, and a straight answer on whether the report is a product bug. There is no bounty program. There is no private embargo beyond the time needed to ship a fix for a real boundary bug. Credit in the changelog is the default if you want it.
