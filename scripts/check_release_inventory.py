#!/usr/bin/env python3
"""Releaseinventar-Prüfung (AXS-012, T-012).

Prüft ein Paketverzeichnis oder ZIP darauf, dass keine Laborproben,
Testschlüssel, EICAR-Dateien, Testdoppel oder Forschungsartefakte enthalten
sind, und schreibt ein Inventar (Pfad, Größe, SHA-256) als JSON.

    python3 scripts/check_release_inventory.py <paketordner|paket.zip> [--inventory out.json]

Exit 0 = sauber, 1 = Verstoß gefunden, 2 = Bedienfehler.
Nur Python-Standardbibliothek.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

# Der EICAR-Teststring wird hier nur aus Teilen zusammengesetzt.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()

FORBIDDEN_PATH = [
    (re.compile(r"(^|/)(lab|research|samples?|malware|testdata)(/|$)", re.I), "Labor-/Forschungsordner"),
    (re.compile(r"\.(pem|key|pfx|p12|snk)$", re.I), "Schlüsselmaterial"),
    (re.compile(r"(^|/)rules/test(/|$)", re.I), "Funktions-Testregeln (nur bewusst freigegeben)"),
    (re.compile(r"fake-clamscan", re.I), "Testdoppel"),
    (re.compile(r"testhelper", re.I), "Testhelfer (nur für Tests)"),
    (re.compile(r"\.hdb$", re.I), "Test-Signaturdatenbank"),
]
# PEM-Kopfzeilen werden zusammengesetzt, damit dieses Prüfskript selbst
# nicht von Geheimnisscannern als Schlüssel gemeldet wird.
_PEM = "-----BEGIN {}PRIVATE " + "KEY-----"
FORBIDDEN_CONTENT = [
    (EICAR, "EICAR-Teststring"),
    (_PEM.format("").encode(), "privater Schlüssel"),
    (_PEM.format("RSA ").encode(), "privater RSA-Schlüssel"),
    (_PEM.format("EC ").encode(), "privater EC-Schlüssel"),
    (_PEM.format("OPENSSH ").encode(), "privater SSH-Schlüssel"),
]


# Pflicht-Hinweisdateien im ausgelieferten Paket (Befund 8): Präfixe, deren
# Datei mindestens einmal mit Inhalt vorhanden sein muss.
REQUIRED_NOTICES = [
    "THIRD-PARTY-NOTICES.txt",
    "licenses/dotnet/Microsoft.NETCore.App/LICENSE",
    "licenses/dotnet/Microsoft.NETCore.App/THIRD-PARTY-NOTICES",
    "licenses/dotnet/Microsoft.WindowsDesktop.App/LICENSE",
]


def entries(target: Path):
    if target.is_dir():
        for p in sorted(target.rglob("*")):
            if p.is_file():
                yield p.relative_to(target).as_posix(), p.read_bytes()
    elif zipfile.is_zipfile(target):
        with zipfile.ZipFile(target) as z:
            for info in sorted(z.infolist(), key=lambda i: i.filename):
                if not info.is_dir():
                    yield info.filename, z.read(info)
    else:
        raise SystemExit(2)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="AXSafe Releaseinventar-Prüfung (T-012)")
    ap.add_argument("package", type=Path, help="Paketordner oder ZIP")
    ap.add_argument("--inventory", type=Path, help="Inventar als JSON schreiben")
    ap.add_argument(
        "--allow-test-rules",
        action="store_true",
        help="Funktions-Testregeln (rules/test) bewusst für eine Vorversion freigeben",
    )
    ap.add_argument(
        "--require-notices",
        action="store_true",
        help="Drittanbieter-Lizenzhinweise müssen im Paket liegen (Release)",
    )
    a = ap.parse_args()
    target, inv_path, allow_test_rules = a.package, a.inventory, a.allow_test_rules
    if not target.exists():
        print(f"Nicht gefunden: {target}")
        return 2

    inventory, problems = [], []
    present: dict[str, bytes] = {}
    for name, data in entries(target):
        present[name] = data
        inventory.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        for rx, why in FORBIDDEN_PATH:
            if rx.search(name) and not (allow_test_rules and "Testregeln" in why):
                problems.append(f"{name}: {why}")
        for needle, why in FORBIDDEN_CONTENT:
            if needle in data:
                problems.append(f"{name}: enthält {why}")
    if a.require_notices:
        for req in REQUIRED_NOTICES:
            hits = [d for n, d in present.items() if n.upper().startswith(req.upper()) and len(d) >= 200]
            if not hits:
                problems.append(f"{req}: Pflicht-Lizenzhinweis fehlt oder ist leer")
        tp = present.get("THIRD-PARTY-NOTICES.txt", b"")
        if tp and b"Drittpaketen" not in tp[:2000]:
            problems.append("THIRD-PARTY-NOTICES.txt: unerwartetes Format (nicht vom Generator)")
    if inv_path:
        inv_path.write_text(json.dumps({"package": target.name, "files": inventory}, indent=2), encoding="utf-8")
    print(f"{len(inventory)} Dateien geprüft.")
    if problems:
        print("VERSTÖSSE:")
        for p in problems:
            print("  -", p)
        return 1
    print("Keine Laborprobe, kein Testschlüssel, keine EICAR-Datei gefunden.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
