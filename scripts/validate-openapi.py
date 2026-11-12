import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
openapi = (ROOT / "trowserkit/swagger/openapi.yaml").read_text(encoding="utf-8")
index = (ROOT / "trowserkit/trowser-api-index.md").read_text(encoding="utf-8")

index_ops = {
    (m.upper(), p)
    for m, p in re.findall(r"\| (GET|POST|PUT|DELETE|PATCH) \| `(/api/[^`]+)`", index)
}

openapi_ops = set()
for m in re.finditer(r"^  (/api/[^:]+):\s*$", openapi, re.M):
    path = m.group(1)
    start = m.end()
    next_path = re.search(r"^  /api/", openapi[start:], re.M)
    chunk = openapi[start : start + next_path.start()] if next_path else openapi[start:]
    for mm in re.finditer(r"^    (get|post|put|patch|delete):\s*$", chunk, re.M):
        openapi_ops.add((mm.group(1).upper(), path))

paths = re.findall(r"^  (/api/[^:]+):", openapi, re.M)
dupes = [p for p, n in Counter(paths).items() if n > 1]
missing = sorted(index_ops - openapi_ops)

print(f"openapi ops: {len(openapi_ops)}")
print(f"index ops: {len(index_ops)}")
print(f"missing: {len(missing)}")
for x in missing:
    print(" ", x)
print(f"dupes: {len(dupes)}")
print(f"required True: {openapi.count('required: True')}")
