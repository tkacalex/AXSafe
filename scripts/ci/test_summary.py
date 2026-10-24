#!/usr/bin/env python3
"""Fasst die Ausgabe von `cargo test` und `dotnet test` ehrlich zusammen (Befund 8).

Bestandene, fehlgeschlagene und ausgelassene Tests werden GETRENNT gezählt;
jeder ausgelassene Test erscheint mit seinem Grund. Ein Lauf, in dem ein Test
ausgelassen wurde, obwohl `--require-none-ignored` gesetzt ist, scheitert.

    cargo test ... 2>&1 | tee cargo-test.log
    python3 scripts/ci/test_summary.py --cargo cargo-test.log [--dotnet trx-ordner] \
        [--platform "Linux (ubuntu-24.04)"] [--require-none-ignored] [--markdown out.md]

Nur Python-Standardbibliothek.
"""
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LINE = re.compile(r"^test (?P<name>\S+) \.\.\. (?P<res>ok|FAILED|ignored)(?:, (?P<why>.*))?$")
RESULT = re.compile(r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored")


def parse_cargo(text: str):
    passed, failed, ignored = [], [], []
    totals = [0, 0, 0]
    for raw in text.splitlines():
        line = raw.rstrip()
        m = LINE.match(line)
        if m:
            {"ok": passed, "FAILED": failed}.get(m["res"], ignored).append(
                (m["name"], m["why"] or "kein Grund angegeben") if m["res"] == "ignored" else m["name"]
            )
            continue
        r = RESULT.match(line)
        if r:
            for i in range(3):
                totals[i] += int(r.group(i + 1))
    return passed, failed, ignored, totals


def parse_trx(folder: Path):
    passed, failed, skipped = [], [], []
    for trx in sorted(folder.glob("**/*.trx")):
        root = ET.parse(trx).getroot()
        ns = {"t": root.tag.split("}")[0].strip("{")}
        for r in root.iterfind(".//t:UnitTestResult", ns):
            name, outcome = r.get("testName", "?"), r.get("outcome", "?")
            if outcome == "Passed":
                passed.append(name)
            elif outcome == "Failed":
                failed.append(name)
            else:
                msg = r.find(".//t:Message", ns)
                skipped.append((name, (msg.text or "").strip() if msg is not None else outcome))
    return passed, failed, skipped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cargo", type=Path)
    ap.add_argument("--dotnet", type=Path, help="Ordner mit .trx-Dateien")
    ap.add_argument("--platform", default="unbekannt")
    ap.add_argument("--require-none-ignored", action="store_true")
    ap.add_argument("--markdown", type=Path)
    a = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    out = [f"### Testergebnis – {a.platform}", ""]
    bad = False
    rows = []
    if a.cargo:
        p, f, i, totals = parse_cargo(a.cargo.read_text(encoding="utf-8", errors="replace"))
        if (len(p), len(f), len(i)) != tuple(totals):
            out.append(f"⚠️ Zeilen- und Summenzählung weichen ab: {len(p)}/{len(f)}/{len(i)} gegen {totals} (Summen von cargo sind maßgeblich)")
            bad |= totals[1] > 0
        if sum(totals) == 0:
            out.append("❌ Keine Rust-Testergebnisse gefunden – Lauf gescheitert oder Log leer.")
            bad = True
        rows.append(("Rust (cargo test)", p, f, i))
    if a.dotnet:
        dn = parse_trx(a.dotnet)
        if not any(dn):
            out.append("❌ Keine .NET-Testergebnisse (.trx) gefunden.")
            bad = True
        rows.append(("C# (dotnet test)", *dn))
    out += ["| Suite | bestanden | fehlgeschlagen | ausgelassen |", "|---|---:|---:|---:|"]
    for name, p, f, i in rows:
        out.append(f"| {name} | {len(p)} | {len(f)} | {len(i)} |")
        bad |= bool(f)
    for name, _, f, i in rows:
        if f:
            out += ["", f"**Fehlgeschlagen ({name}):**"] + [f"- `{t}`" for t in f]
        if i:
            out += ["", f"**Ausgelassen ({name}) – mit Grund:**"] + [f"- `{t}` – {why}" for t, why in i]
            if a.require_none_ignored:
                out.append("❌ In diesem Lauf darf kein Test ausgelassen werden (Pflichtvoraussetzungen fehlen).")
                bad = True
    text = "\n".join(out) + "\n"
    print(text)
    if a.markdown:
        with a.markdown.open("a", encoding="utf-8") as fh:
            fh.write(text)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
