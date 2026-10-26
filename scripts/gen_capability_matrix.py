#!/usr/bin/env python3
"""Erzeugt die Formattabelle der Fähigkeitsmatrix aus `axsafe faehigkeiten --json`.

Die Tabelle trennt „erkannt“ (Typerkennung nach Inhalt, mit Testbeleg) und
„Inhalt geprüft“ (welche bereite Engine das Format nachweislich inhaltlich
prüft). Grundlage ist die laufende CLI mit YARA-X und ClamAV (Testdatenbank
genügt: die Fähigkeiten hängen am Engine-Adapter, nicht am Signaturstand).

    python3 scripts/gen_capability_matrix.py <faehigkeiten.json> [--check]
"""
import json
import sys
from pathlib import Path

DOC = Path(__file__).resolve().parent.parent / "docs" / "CAPABILITY-MATRIX.md"
START = "<!-- FORMATE:START (automatisch erzeugt von scripts/gen_capability_matrix.py) -->"
END = "<!-- FORMATE:END -->"

# Belege der INHALTSprüfung durch ClamAV (echte Engine, Testsignatur im Inhalt).
CONTENT_TEST = "`content_formats_are_backed_by_real_clamav`"


def table(rows):
    out = [
        "| Format | erkannt (Beleg) | Container | Inhalt geprüft durch | Inhaltsbeleg | ohne fähige Engine |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        by = r["inhalt_geprueft_durch"]
        if r["container"]:
            beleg = CONTENT_TEST if by else "– (kein Engine-Beleg)"
            ohne = "Lücke `content_not_inspected`"
            insp = ", ".join(by) if by else "**niemand – immer Lücke**"
        else:
            beleg = "Dateibytes = Inhalt"
            ohne = "–"
            insp = ", ".join(by)
        out.append(
            f"| {r['format']} | ✅ `{r['erkennung_beleg']}` | {'ja' if r['container'] else 'nein'} "
            f"| {insp} | {beleg} | {ohne} |"
        )
    return "\n".join(out)


def main() -> int:
    rows = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    text = DOC.read_text(encoding="utf-8")
    a, b = text.index(START), text.index(END)
    new = text[: a + len(START)] + "\n" + table(rows) + "\n" + text[b:]
    if "--check" in sys.argv:
        if new != text:
            print("CAPABILITY-MATRIX.md ist nicht synchron mit `axsafe faehigkeiten`", file=sys.stderr)
            return 1
        print("Fähigkeitsmatrix synchron.")
        return 0
    DOC.write_text(new, encoding="utf-8")
    print("CAPABILITY-MATRIX.md aktualisiert.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
