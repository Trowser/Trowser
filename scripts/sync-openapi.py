#!/usr/bin/env python3
"""Fix HTTP method indentation in openapi paths and add missing index endpoints."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPENAPI = ROOT / "trowserkit" / "swagger" / "openapi.yaml"
INDEX = ROOT / "trowserkit" / "trowser-api-index.md"

METHODS = ("get", "post", "put", "patch", "delete")


def tag_for_path(path: str) -> str:
    rules = [
        (r"^/api/(ping|abort|info|clear-all|clear-session)$", "Health & System"),
        (r"^/api/(state|interactive|screenshot|page-text|source|diff-state|force-navigate)", "Page State"),
        (r"^/api/(console|network)", "Console & Network"),
        (r"^/api/journal", "Journal"),
        (r"^/api/repro", "Repro & Verification"),
        (r"^/api/message$", "Notifications"),
        (r"^/api/(navigate|go-back|go-forward|wait-for|settings/)", "Navigation"),
        (r"^/api/(click|type|upload|find|select|hover|scroll|key)", "Element Interaction"),
        (r"^/api/(text|attribute|property|extract)", "Element Data"),
        (r"^/api/(execute-js|execute-script|batch|test-scenario)$", "Script Execution"),
        (r"^/api/wait($|-for-network)", "Waiting"),
        (r"^/api/assert", "Assertions"),
        (r"^/api/dialog", "Dialogs"),
        (r"^/api/cookies", "Cookies"),
        (r"^/api/storage", "Storage"),
        (r"^/api/(viewport|screen-curtain)", "Viewport"),
        (r"^/api/tabs", "Tabs"),
        (r"^/api/webmcp", "WebMCP"),
        (r"^/api/mock", "Mocking"),
        (r"^/api/intercept", "Interception"),
        (r"^/api/load-test$", "Load Testing"),
        (r"^/api/fetch", "Fetch"),
        (r"^/api/network/throttle", "Throttling"),
        (r"^/api/(accessibility|performance|audit-all|quicktest|validate-html|compatibility|check-links|consistency|third-party|page-text/structured|tab-order|seo|resource|surpriseme)$", "Auditing"),
        (r"^/api/security/(headers|xss|mixed-content|cors|cookies|storage|source-maps|tech-stack|clickjack|firewall-test)$", "Auditing"),
        (r"^/api/security", "Security Testing"),
        (r"^/api/(fuzz|monkey-test|monkey-trowser|interrupter)", "Robustness"),
        (r"^/api/peer", "Peer Management"),
        (r"^/api/authz", "Authorization Testing"),
        (r"^/api/(identity|identities|session/identity)", "Portable Identity"),
        (r"^/api/orchestrate", "Security Orchestration"),
        (r"^/api/vpx", "VPX"),
        (r"^/api/ssl", "Client TLS Certificates"),
        (r"^/api/websocket", "WebSocket"),
        (r"^/api/shadows$", "Shadows"),
        (r"^/api/(inspiration|test-data)$", "Utilities"),
    ]
    for pattern, tag in rules:
        if re.search(pattern, path):
            return tag
    return "Other"


def parse_index() -> list[tuple[str, str, str]]:
    text = INDEX.read_text(encoding="utf-8")
    return [
        (m.group(1).lower(), m.group(2).strip(), re.sub(r"\s+", " ", m.group(3).strip()))
        for m in re.finditer(r"\| (GET|POST|PUT|DELETE|PATCH) \| `(/api/[^`]+)` \| ([^\|]+) \|", text)
    ]


def stub_op(method: str, path: str, summary: str) -> str:
    tag = tag_for_path(path)
    op_id = f"{method}_{path.removeprefix('/api/').replace('/', '_').replace('{', '').replace('}', '').replace('-', '_')}"
    summary_esc = summary.replace('"', '\\"')
    lines = [
        f"    {method}:",
        f"      operationId: {op_id}",
        f"      tags: [{tag}]",
        f'      summary: "{summary_esc}"',
    ]
    params = re.findall(r"\{([^{}]+)\}", path)
    if params:
        lines.append("      parameters:")
        for name in params:
            lines += [
                f"        - name: {name}",
                "          in: path",
                "          required: true",
                "          schema:",
                "            type: string",
            ]
    if method in {"post", "put", "patch", "delete"}:
        lines += [
            "      requestBody:",
            "        content:",
            "          application/json:",
            "            schema:",
            "              type: object",
        ]
    lines += ['      responses:', '        "200":', "          description: Success"]
    return "\n".join(lines)


def main() -> None:
    text = OPENAPI.read_text(encoding="utf-8")
    text = text.replace("required: True", "required: true").replace("required: False", "required: false")

    idx = text.find("\npaths:\n")
    if idx < 0:
        raise SystemExit("paths: not found")
    header, paths_body = text[: idx + len("\npaths:\n")], text[idx + len("\npaths:\n") :]

    # Fix unindented HTTP method lines inside paths
    fixed_lines = []
    in_paths = True
    for line in paths_body.splitlines():
        if in_paths and re.match(r"^(get|post|put|patch|delete):\s*$", line):
            fixed_lines.append(f"    {line.strip()}")
        else:
            fixed_lines.append(line)
    paths_body = "\n".join(fixed_lines)

    # Parse existing operations
    path_ops: dict[str, dict[str, str]] = {}
    path_order: list[str] = []
    current_path = None
    current_method = None
    buf: list[str] = []

    def flush_op() -> None:
        nonlocal current_method, buf
        if current_path and current_method and buf:
            path_ops.setdefault(current_path, {})[current_method] = "\n".join(buf).rstrip()
        current_method = None
        buf = []

    for line in paths_body.splitlines():
        pm = re.match(r"^  (/api/.+):$", line)
        if pm:
            flush_op()
            current_path = pm.group(1)
            if current_path not in path_order:
                path_order.append(current_path)
            continue
        mm = re.match(r"^    (get|post|put|patch|delete):\s*$", line)
        if mm:
            flush_op()
            current_method = mm.group(1)
            buf = [line]
            continue
        if current_method:
            buf.append(line)

    flush_op()

    index_paths = {path for _, path, _ in parse_index()}
    removed = 0
    for path in list(path_ops.keys()):
        if path not in index_paths:
            del path_ops[path]
            if path in path_order:
                path_order.remove(path)
            removed += 1

    # Add missing operations from index
    added = 0
    for method, path, summary in parse_index():
        if path not in path_ops:
            path_ops[path] = {}
            path_order.append(path)
        if method not in path_ops[path]:
            path_ops[path][method] = stub_op(method, path, summary)
            added += 1

    out = []
    for path in path_order:
        if path not in path_ops:
            continue
        out.append(f"  {path}:")
        for method in METHODS:
            if method in path_ops[path]:
                out.append(path_ops[path][method])
                out.append("")
        out.append("")

    OPENAPI.write_text(header + "\n".join(out).rstrip() + "\n", encoding="utf-8", newline="\n")
    print(f"Paths: {len(path_ops)}; operations: {sum(len(v) for v in path_ops.values())}; added: {added}; removed: {removed}")


if __name__ == "__main__":
    main()
