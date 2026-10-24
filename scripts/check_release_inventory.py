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
    (re.compile(r"\.hdb$", re.I), "Test-Signaturdatenbank"),
]
FORBIDDEN_CONTENT = [
    (EICAR, "EICAR-Teststring"),
    (b"-----BEGIN PRIVATE KEY-----", "privater Schlüssel"),
    (b"-----BEGIN RSA PRIVATE KEY-----", "privater RSA-Schlüssel"),
    (b"-----BEGIN OPENSSH PRIVATE KEY-----", "privater SSH-Schlüssel"),
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
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print(__doc__)
        return 2
    target = Path(args[0])
    inv_path = None
    if "--inventory" in sys.argv:
        inv_path = Path(sys.argv[sys.argv.index("--inventory") + 1])
    allow_test_rules = "--allow-test-rules" in sys.argv

    inventory, problems = [], []
    for name, data in entries(target):
        inventory.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        for rx, why in FORBIDDEN_PATH:
            if rx.search(name) and not (allow_test_rules and "Testregeln" in why):
                problems.append(f"{name}: {why}")
        for needle, why in FORBIDDEN_CONTENT:
            if needle in data:
                problems.append(f"{name}: enthält {why}")
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
