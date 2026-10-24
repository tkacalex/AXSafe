#!/usr/bin/env python3
"""Erzeugt Requirements-Matrix, Quellenregister, Fortschrittsgrafik und den
Statusblock der README aus Spezifikation + docs/status/requirements-status.json.

Nur Python-Standardbibliothek. Aufruf aus dem Repository-Wurzelordner:

    python3 scripts/gen_docs.py          # Dateien schreiben
    python3 scripts/gen_docs.py --check  # nur prüfen (CI), Exit 1 bei Abweichung
"""
from __future__ import annotations

import html
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs/spec/AXSafe_V1_Spezifikation.json"
STATUS = ROOT / "docs/status/requirements-status.json"

ORDER = ["erfuellt", "teilweise", "begonnen", "entwurf", "blockiert", "geplant"]
LABEL = {
    "erfuellt": "✅ erfüllt",
    "teilweise": "🟢 teilweise belegt",
    "begonnen": "🔵 begonnen",
    "entwurf": "📝 Entwurf",
    "blockiert": "⛔ blockiert",
    "geplant": "⚪ geplant",
}
SHORT = {
    "erfuellt": "erfüllt",
    "teilweise": "teilweise belegt",
    "begonnen": "begonnen",
    "entwurf": "Entwurf",
    "blockiert": "blockiert",
    "geplant": "geplant",
}
COLOR = {
    "erfuellt": "#34D399",
    "teilweise": "#22D3EE",
    "begonnen": "#3B82F6",
    "entwurf": "#818CF8",
    "blockiert": "#F87171",
    "geplant": "#2A3B5E",
}


def load():
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    status = json.loads(STATUS.read_text(encoding="utf-8"))
    st = status["requirements"]
    unknown = set(st) - {r["id"] for r in spec["requirements"]}
    if unknown:
        sys.exit(f"Unbekannte IDs im Status: {sorted(unknown)}")
    for rid, v in st.items():
        if v["status"] not in ORDER:
            sys.exit(f"{rid}: ungültiger Status {v['status']}")
    return spec, status


def esc(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def requirements_md(spec, status) -> str:
    st = status["requirements"]
    tests = status.get("tests", {})
    counts = Counter(st.get(r["id"], {}).get("status", "geplant") for r in spec["requirements"])
    out = [
        "# Anforderungen und Abnahmen",
        "",
        "> Automatisch erzeugt von `scripts/gen_docs.py` aus der Spezifikation "
        f"(Revision {spec['revision']}) und `docs/status/requirements-status.json`. Nicht von Hand bearbeiten.",
        "",
        "Gesamtstand: " + " · ".join(f"{LABEL[k]}: **{counts.get(k, 0)}**" for k in ORDER),
        "",
        "Statuswerte: " + "; ".join(f"`{k}` = {v}" for k, v in status["status_values"].items()) + ".",
        "",
        "![Fortschritt je Phase](images/progress.svg)",
        "",
    ]
    reqs = {r["id"]: r for r in spec["requirements"]}
    for ph in spec["phases"]:
        out += [f"## {ph['id']} {ph['title']}", "", f"*Ziel:* {ph['goal']}  ", f"*Gate:* {ph['gate']}", ""]
        out += ["| ID | Anforderung | Status | Abnahme | Ort / Beleg | Offen |", "| --- | --- | --- | --- | --- | --- |"]
        for rid in ph["requirements"]:
            r = reqs[rid]
            s = st.get(rid, {})
            state = s.get("status", "geplant")
            t = r["test"]
            tnames = tests.get(t)
            acc = f"**{t}** {esc(r['acceptance'])}"
            if tnames:
                acc += "<br>Tests: " + ", ".join(f"`{esc(n)}`" for n in tnames)
            where = esc(s.get("where", ""))
            ev = esc(s.get("evidence", ""))
            loc = f"{where}<br>{ev}" if where and ev else where or ev or "–"
            out.append(
                f"| {rid} | **{esc(r['title'])}** – {esc(r['task'])} | {LABEL[state]} | {acc} | {loc} | {esc(s.get('rest', '–'))} |"
            )
        out.append("")
    return "\n".join(out)


def sources_md(spec) -> str:
    out = [
        "# Quellenregister",
        "",
        "> Automatisch erzeugt aus der Spezifikation. Abrufdatum laut Spezifikation. "
        "Aktuelle Regeln, APIs, Lizenzen und Pflichten werden vor der abhängigen Implementierung erneut geprüft.",
        "",
        "| ID | Titel | Abgerufen |",
        "| --- | --- | --- |",
    ]
    for s in spec["sources"]:
        out.append(f"| {s['id']} | [{esc(s['title'])}]({s['url']}) | {s.get('accessed', '')} |")
    return "\n".join(out) + "\n"


def progress_svg(spec, status) -> str:
    st = status["requirements"]
    w, row, top, left, barw = 920, 30, 92, 300, 560
    phases = spec["phases"]
    h = top + row * len(phases) + 70
    total = Counter(st.get(r["id"], {}).get("status", "geplant") for r in spec["requirements"])
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
        'aria-label="AXSafe V1 Fortschritt je Phase">',
        '<style>text{font-family:"Segoe UI",Helvetica,Arial,sans-serif;fill:#E8EEF8}.m{fill:#94A7C6}</style>',
        f'<rect width="{w}" height="{h}" rx="16" fill="#0A1426"/>',
        '<text x="28" y="40" font-size="20" font-weight="600">AXSafe V1 – Fortschritt der 100 Anforderungen</text>',
        f'<text x="28" y="64" font-size="13" class="m">Nur belegter Stand. Erzeugt aus docs/status/requirements-status.json · '
        f'{total.get("erfuellt", 0)} erfüllt, {total.get("teilweise", 0)} teilweise belegt, '
        f'{total.get("begonnen", 0) + total.get("entwurf", 0)} begonnen/Entwurf, {total.get("geplant", 0)} geplant</text>',
    ]
    for i, ph in enumerate(phases):
        y = top + i * row
        ids = ph["requirements"]
        c = Counter(st.get(r, {}).get("status", "geplant") for r in ids)
        title = html.escape(f"{ph['id']}  {ph['title']}")
        parts.append(f'<text x="28" y="{y + 15}" font-size="13">{title}</text>')
        x = left
        for k in ORDER:
            n = c.get(k, 0)
            if not n:
                continue
            seg = barw * n / len(ids)
            parts.append(
                f'<rect x="{x:.1f}" y="{y + 2}" width="{max(seg - 2, 1):.1f}" height="18" rx="4" fill="{COLOR[k]}">'
                f'<title>{n} {SHORT[k]}</title></rect>'
            )
            x += seg
        parts.append(f'<text x="{left + barw + 14}" y="{y + 15}" font-size="12" class="m">{len(ids)}</text>')
    ly = top + row * len(phases) + 30
    lx = 28
    for k in ORDER:
        parts.append(f'<rect x="{lx}" y="{ly - 11}" width="14" height="14" rx="3" fill="{COLOR[k]}"/>')
        parts.append(f'<text x="{lx + 20}" y="{ly}" font-size="12">{SHORT[k]}</text>')
        lx += 145
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def readme_block(spec, status) -> str:
    st = status["requirements"]
    c = Counter(st.get(r["id"], {}).get("status", "geplant") for r in spec["requirements"])
    lines = [
        "<!-- STATUS:START (automatisch erzeugt von scripts/gen_docs.py) -->",
        "| Status | Anzahl |",
        "| --- | ---: |",
    ]
    for k in ORDER:
        lines.append(f"| {LABEL[k]} | {c.get(k, 0)} |")
    lines.append("<!-- STATUS:END -->")
    return "\n".join(lines)


def main() -> int:
    check = "--check" in sys.argv
    spec, status = load()
    targets = {
        ROOT / "docs/REQUIREMENTS.md": requirements_md(spec, status),
        ROOT / "docs/SOURCES.md": sources_md(spec),
        ROOT / "docs/images/progress.svg": progress_svg(spec, status),
    }
    readme = ROOT / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8")
        a = text.find("<!-- STATUS:START")
        b = text.find("<!-- STATUS:END -->")
        if a != -1 and b != -1:
            b += len("<!-- STATUS:END -->")
            targets[readme] = text[:a] + readme_block(spec, status) + text[b:]
    stale = []
    for path, content in targets.items():
        old = path.read_text(encoding="utf-8") if path.exists() else None
        if old != content:
            stale.append(path.relative_to(ROOT))
            if not check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
    if check and stale:
        print("Veraltet (bitte python3 scripts/gen_docs.py ausführen):", *map(str, stale), sep="\n  ")
        return 1
    print("Aktualisiert:" if stale else "Alles aktuell.", *map(str, stale), sep="\n  ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
