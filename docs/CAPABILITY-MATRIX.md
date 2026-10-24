# Fähigkeitsmatrix

Was AXSafe heute **tatsächlich** kann, je Format und Schutzfunktion. Unbekannte Kombinationen gelten **nicht** als geschützt.

## Dateiformate (AXS-023, AXS-024)

Typerkennung erfolgt nach Inhalt (`axsafe filetype`), nie nach Endung.

| Format | Typerkennung | YARA-X (eigene Regeln) | ClamAV | Container rekursiv | Hinweis |
| --- | --- | --- | --- | --- | --- |
| PE32 / PE64 (EXE, DLL, SYS) | ✅ inkl. Architektur, DLL, .NET | ✅ Rohbytes | ✅ | – | PE-Modul von YARA-X noch nicht aktiviert |
| .NET-Assemblies | ✅ (CLR-Header) | ✅ Rohbytes | ✅ | – | |
| Skripte (PowerShell, JS, VBS, Batch) | 🟡 nur „Text“/„Script“ (Shebang) | ✅ Rohbytes | ✅ | – | Sprache nicht unterschieden; AMSI fehlt (P07) |
| Office OOXML (docx/xlsx/pptx) | ✅ | 🟡 nur Containerbytes | ✅ entpackt | ClamAV | |
| Office 97–2003 / MSI (OLE CFB) | 🟡 nicht unterschieden | 🟡 Containerbytes | ✅ | ClamAV | |
| PDF | ✅ | ✅ Rohbytes | ✅ | ClamAV | |
| RTF | ✅ | ✅ | ✅ | – | |
| LNK | ✅ | ✅ | ✅ | – | |
| ZIP | ✅ | 🟡 Containerbytes | ✅ | ClamAV (Limits) | Passwortschutz → `Encrypted` (getestet) |
| 7z, RAR, GZIP, CAB | ✅ | 🟡 Containerbytes | ✅ | ClamAV (Limits) | |
| ISO 9660 | ✅ | 🟡 | 🟡 | ClamAV | nicht getestet |
| VHDX | ✅ | 🟡 | ⛔ unbekannt | – | Lücke |
| Dateien > 256 MB (Standard) | – | – | – | – | `Unsupported`, nie sauber |
| Links, Junctions, Reparsepunkte | – | – | – | – | werden nicht verfolgt → `Unsupported` |
| Alternate Data Streams | ⛔ | ⛔ | ⛔ | – | Lücke (AXS-018) |

## Schutzfunktionen

| Funktion | Stand | Anforderung |
| --- | --- | --- |
| Scan auf Anforderung (Dateien/Ordner) | ✅ CLI + UI | AXS-026 |
| Abbruch | ✅ UI beendet Prozess, Bericht als unvollständig | AXS-026 |
| Schnell-/Vollscan, Kontextmenü, Zeitplan | ⛔ | AXS-026 |
| Echtzeitschutz | ⛔ | AXS-053 ff. |
| Quarantäne | ⛔ (nur Meldung) | AXS-035 ff. |
| AMSI / Skriptschutz | ⛔ | AXS-047 ff. |
| Verhaltenserkennung | ⛔ | AXS-041 ff. |
| Ransomware-Schutz | ⛔ | AXS-061 ff. |
| Web, Netzwerk, E-Mail, USB | ⛔ (USB-Laufwerk manuell scanbar) | AXS-067 ff. |
| Updates | ⛔ | AXS-029 ff. |
| Cloud | ⛔ bewusst aus | AXS-079 ff. |
