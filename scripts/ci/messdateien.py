#!/usr/bin/env python3
"""Erzeugt zur Laufzeit die Dateimenge für die ClamAV-Messung (B-18).

Deterministisch (fester Startwert), damit jede Messung dieselben Dateien
prüft: 30 harmlose Dateien (Text, HTML, JSON, ZIP, Binärdaten; 1 KiB bis
2 MiB) und eine EICAR-Testdatei, die erst hier aus zwei Teilen
zusammengesetzt wird. Nur für Wegwerf-Testsysteme (CI), nicht für
Alltagsrechner. Aufruf: python3 scripts/ci/messdateien.py <zielordner>
"""
import io
import json
import os
import random
import sys
import zipfile


def main() -> int:
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    rnd = random.Random(20261025)
    sizes = [1024 * (2 ** (i % 12)) for i in range(30)]  # 1 KiB … 2 MiB
    for i, size in enumerate(sizes):
        kind = i % 5
        name = os.path.join(out, f"{i:02d}")
        if kind == 0:
            text = " ".join(rnd.choice(["Rechnung", "Brief", "Termin", "AXSafe", "Messung"]) for _ in range(size // 8))
            open(name + ".txt", "w", encoding="utf-8").write(text[:size])
        elif kind == 1:
            body = "".join(f"<p>Absatz {n}</p>" for n in range(size // 16))
            open(name + ".html", "w", encoding="utf-8").write(f"<html><body>{body}</body></html>")
        elif kind == 2:
            json.dump({"werte": [rnd.random() for _ in range(size // 20)]}, open(name + ".json", "w"))
        elif kind == 3:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("inhalt.txt", ("harmlos " * (size // 8)).encode())
                z.writestr("daten.bin", rnd.randbytes(size // 4))
            open(name + ".zip", "wb").write(buf.getvalue())
        else:
            open(name + ".bin", "wb").write(rnd.randbytes(size))
    a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    open(os.path.join(out, "99-eicar.com"), "w").write(a + b)
    print(f"{len(sizes) + 1} Messdateien in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
