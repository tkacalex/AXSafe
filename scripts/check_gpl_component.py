#!/usr/bin/env python3
"""Lizenzprüfung für den GPL-Bestandteil axsafe-clamav-worker (B-18).

Der Worker lädt zur Laufzeit libclamav (GPL-2.0-only). Alles, was in sein
Programm hineingebaut wird, muss deshalb unter einer mit GPL-2.0-only
vereinbaren Lizenz nutzbar sein. Apache-2.0 allein ist das NICHT (die FSF
stuft Apache-2.0 als unvereinbar mit GPLv2 ein); bei Doppellizenzen wie
"MIT OR Apache-2.0" genügt es, dass eine vereinbare Wahl existiert (MIT).

Geprüft werden die normalen Abhängigkeiten für alle Zielplattformen
(`cargo tree -e normal --target all`). Testabhängigkeiten gehören nicht zum
ausgelieferten Programm.

Eigene Crates des Projekts haben noch keine Lizenzangabe (Entscheidung D-01
offen). Sie werden aufgelistet und als offen markiert, nicht als vereinbar
gezählt; sie lassen die Prüfung nicht scheitern, weil ihre Lizenz der
Projektinhaber festlegt. Der Bericht sagt das ausdrücklich.

Aufruf: python3 scripts/check_gpl_component.py [--paket axsafe-clamav-worker]
Exitcode 0 = alle fremden Abhängigkeiten vereinbar, 1 = Konflikt.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# Mit GPL-2.0-only vereinbare Lizenzen (FSF-Liste "GPL-compatible", für
# GPLv2). Apache-2.0, MPL-2.0 ohne Sekundärlizenz-Klausel, GPL-3.0-only usw.
# fehlen bewusst.
COMPATIBLE = {
    "MIT",
    "MIT-0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "0BSD",
    "ISC",
    "Zlib",
    "Unlicense",
    "CC0-1.0",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "BSL-1.0",
    "LGPL-2.1-or-later",
    "LGPL-2.1-only",
    "LGPL-2.0-or-later",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
}


def tokens(expr: str) -> list[str]:
    return re.findall(r"\(|\)|[A-Za-z0-9.+\-]+", expr.replace("/", " OR "))


def satisfiable(expr: str) -> bool:
    """Gibt es eine Wahl im SPDX-Ausdruck, die nur vereinbare Lizenzen nutzt?"""
    toks = tokens(expr)
    pos = 0

    def parse_or() -> bool:
        nonlocal pos
        v = parse_and()
        while pos < len(toks) and toks[pos] == "OR":
            pos += 1
            v = parse_and() or v
        return v

    def parse_and() -> bool:
        nonlocal pos
        v = parse_atom()
        while pos < len(toks) and toks[pos] == "AND":
            pos += 1
            v = parse_atom() and v
        return v

    def parse_atom() -> bool:
        nonlocal pos
        if pos >= len(toks):
            return False
        t = toks[pos]
        pos += 1
        if t == "(":
            v = parse_or()
            if pos < len(toks) and toks[pos] == ")":
                pos += 1
            return v
        if pos < len(toks) and toks[pos] == "WITH":
            pos += 2  # Ausnahmen (z. B. LLVM-exception) machen nichts unvereinbar
        return t in COMPATIBLE

    ok = parse_or()
    return ok and pos == len(toks)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--paket", default="axsafe-clamav-worker")
    a = ap.parse_args()
    out = subprocess.run(
        [
            "cargo", "tree", "--locked", "-p", a.paket, "-e", "normal", "--target", "all",
            "--prefix", "none", "-f", "{p}|{l}",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    seen: dict[str, str] = {}
    for line in out.splitlines():
        line = line.replace(" (*)", "").strip()
        if "|" not in line:
            continue
        pkg, lic = line.split("|", 1)
        seen[pkg.strip()] = lic.strip()

    conflicts, own, fine = [], [], []
    for pkg, lic in sorted(seen.items()):
        if "(/" in pkg or "(C:" in pkg or "(\\" in pkg:
            own.append(pkg.split(" (")[0])
        elif lic and satisfiable(lic):
            fine.append(f"{pkg}: {lic}")
        else:
            conflicts.append(f"{pkg}: {lic or 'KEINE LIZENZANGABE'}")

    print(f"Lizenzprüfung {a.paket} (normale Abhängigkeiten, alle Zielplattformen)")
    print(f"  vereinbar mit GPL-2.0-only: {len(fine)}")
    for f in fine:
        print(f"    {f}")
    print(f"  eigene Crates (Lizenz offen, Entscheidung D-01): {', '.join(own)}")
    if conflicts:
        print(f"  KONFLIKT ({len(conflicts)}):")
        for c in conflicts:
            print(f"    {c}")
        return 1
    print("  keine Konflikte")
    # Gegenrichtung: Programme mit Apache-2.0-Anteilen (YARA-X/wasmtime) dürfen
    # den GPL-Worker nicht einbinden; sie starten ihn nur als eigenen Prozess.
    for host in ("axsafe-cli", "axsafe-service", "axsafe-engine-clamav"):
        t = subprocess.run(
            ["cargo", "tree", "--locked", "-p", host, "-e", "normal", "--target", "all",
             "--prefix", "none", "-f", "{p}"],
            check=True, capture_output=True, text=True,
        ).stdout
        if any(l.startswith(a.paket + " ") for l in t.splitlines()):
            print(f"  KONFLIKT: {host} bindet {a.paket} ein (darf ihn nur als Prozess starten)")
            return 1
        print(f"  {host}: bindet {a.paket} nicht ein (startet ihn nur als Prozess)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
