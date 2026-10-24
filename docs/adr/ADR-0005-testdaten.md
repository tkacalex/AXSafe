# ADR-0005: Testdaten ohne Gefahr für den Alltagsrechner

* Status: **angenommen** (AXS-009, AXS-012)
* Datum: 2026-10-24

## Entscheidung

* Das Repository enthält **keine** Schadsoftware und **keine** EICAR-Datei.
* Die EICAR-Teststring-Erkennung steht in `rules/test/eicar.yar` nur als **Hex-Folge**. Tests setzen den String **zur Laufzeit** aus zwei Hälften in temporären Ordnern zusammen. So meldet Microsoft Defender auf dem Entwicklungsrechner weder Quelltext noch Repository.
* ClamAV-Tests verwenden eine zur Laufzeit erzeugte Hashsignatur (`.hdb`), weil die offiziellen Signaturserver aus der Build-Umgebung nicht erreichbar sind. Das prüft den echten ClamAV-Pfad, misst aber **keine** Erkennungsleistung.
* Fehlerpfade (Absturz, Hänger) werden mit kleinen **Testdoppeln nur in Tests** geprüft. Sie sind nie Teil eines Pakets (Inventarprüfung `scripts/check_release_inventory.py`).
* Reale Proben nur im getrennten Labor nach [`lab/LAB-RULES.md`](../../lab/LAB-RULES.md).
