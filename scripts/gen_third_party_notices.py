#!/usr/bin/env python3
"""Erzeugt THIRD-PARTY-NOTICES.txt für die ausgelieferte CLI (Befund 8).

Grundlage ist der tatsächliche Abhängigkeitsgraph von `axsafe-cli` für die
Zielplattform (nur normale Abhängigkeiten, keine Test-/Build-only-Crates).
Für jedes Crate werden Lizenzkennung, Quelle, Autoren und die vollständigen
Lizenztexte aufgenommen. Fehlt im Crate eine Lizenzdatei, wird die
versionsgenau bezogene Upstream-Datei aus licenses/upstream verwendet; ist
auch dort nichts vorhanden, wird das offen ausgewiesen.

    python3 scripts/gen_third_party_notices.py <ziel-triple> <ausgabe.txt>

Exit 1, wenn für ein Crate weder Lizenzdatei noch dokumentierte Ausnahme
vorliegt. Nur Python-Standardbibliothek.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UP = ROOT / "licenses" / "upstream"
PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE", "COPYRIGHT")


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    target, out = sys.argv[1], Path(sys.argv[2])
    meta = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", target],
            cwd=ROOT,
        )
    )
    sources = json.loads((UP / "SOURCES.json").read_text(encoding="utf-8"))
    pk = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = next(p["id"] for p in meta["packages"] if p["name"] == "axsafe-cli")
    seen, stack = set(), [root]
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        for d in nodes[i]["deps"]:
            if any(k["kind"] is None for k in d["dep_kinds"]):
                stack.append(d["pkg"])
    third = sorted((pk[i] for i in seen if pk[i]["source"]), key=lambda p: (p["name"], p["version"]))

    printed: dict[str, str] = {}
    missing, upstream_used, documented = [], [], []
    parts = [
        "AXSafe – Hinweise zu Drittkomponenten (THIRD-PARTY-NOTICES)",
        "=" * 64,
        f"Zielplattform: {target}",
        f"Komponente: axsafe (CLI) mit {len(third)} Drittpaketen aus crates.io",
        "Die .NET-Laufzeit (Oberfläche) hat eigene Hinweise in licenses/dotnet/.",
        "ClamAV wird NICHT mitgeliefert. Die Projektlizenz von AXSafe ist noch nicht festgelegt (ADR-0003).",
        "",
    ]
    for p in third:
        d = Path(p["manifest_path"]).parent
        files = sorted(f for f in os.listdir(d) if f.upper().startswith(PREFIXES) and (d / f).is_file())
        texts = [(f, (d / f).read_text(encoding="utf-8", errors="replace")) for f in files]
        note = ""
        if not texts and p["name"] in sources["crates"]:
            texts = [(f"upstream: {sources['files'][f]}", (UP / f).read_text(encoding="utf-8")) for f in sources["crates"][p["name"]]]
            upstream_used.append(p["name"])
        if not texts and p["name"] in sources["no_upstream_notice"]:
            note = sources["no_upstream_notice"][p["name"]]
            texts = [("Standardtext MIT (SPDX)", (ROOT / "licenses" / "spdx" / "MIT.txt").read_text(encoding="utf-8"))]
            documented.append(p["name"])
        if not texts:
            missing.append(f"{p['name']} {p['version']}")
        parts += [
            "-" * 64,
            f"{p['name']} {p['version']}",
            f"Lizenz: {p.get('license') or 'unbekannt'}",
            f"Quelle: {p.get('repository') or 'crates.io'}",
            f"Autoren: {', '.join(p.get('authors') or []) or 'keine Angabe'}",
        ]
        if note:
            parts.append(f"Hinweis: {note}")
        for name, text in texts:
            h = hashlib.sha256(text.encode()).hexdigest()
            if h in printed:
                parts.append(f"[{name}: Text identisch mit dem bei {printed[h]} abgedruckten Text]")
            else:
                printed[h] = f"{p['name']} {p['version']}"
                parts += [f"[{name}]", text.rstrip(), ""]
    out.write_text("\n".join(parts) + "\n", encoding="utf-8")
    print(f"{len(third)} Drittpakete, {len(upstream_used)} mit Upstream-Lizenzdatei, "
          f"{len(documented)} dokumentierte Ausnahme(n), {len(missing)} ohne Lizenztext.")
    if missing:
        print("FEHLEND:", *missing, sep="\n  ")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
