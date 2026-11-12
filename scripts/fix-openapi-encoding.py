from pathlib import Path

p = Path(__file__).resolve().parent.parent / "trowserkit" / "swagger" / "openapi.yaml"
t = p.read_text(encoding="utf-8")
# UTF-8 mojibake sequences (file saved with wrong decoding earlier)
replacements = [
    ("\u00e2\u20ac\u201d", "-"),
    ("\u00e2\u20ac\u201c", "-"),
    ("\u00e2\u20ac\u00a6", "..."),
    ("\u00e2\u20ac\u2122", "'"),
]
for old, new in replacements:
    t = t.replace(old, new)
p.write_text(t, encoding="utf-8", newline="\n")
print("encoding fixed")
