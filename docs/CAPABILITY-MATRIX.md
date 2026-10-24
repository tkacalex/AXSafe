# Fähigkeitsmatrix

Was AXSafe heute **tatsächlich** kann, je Format und Schutzfunktion. Unbekannte Kombinationen gelten **nicht** als geschützt.

## Dateiformate (AXS-023, AXS-024)

Typerkennung erfolgt nach Inhalt (`axsafe filetype`), nie nach Endung.

**Rohbytes ≠ Inhaltsprüfung (Befund 3).** YARA-X prüft nur die Bytes der Datei, wie sie auf der Platte liegen; Inhalte von Containern werden nicht entpackt. Ein Container gilt nur dann als vollständig geprüft, wenn eine **bereite** Engine das Format **nachweislich** inhaltlich prüft und dabei weder Fehler noch Zeitüberschreitung hatte. Sonst trägt das Objekt die Lücke `content_not_inspected` (Zustand `Unsupported`). `Encrypted` wird nur gemeldet, wenn die Engine es zuverlässig feststellt (ClamAV `Heuristics.Encrypted.*`). AXSafe entpackt selbst nichts.

| Format | Typerkennung | YARA-X | ClamAV-Inhaltsprüfung | Beleg | Ohne fähige Engine |
| --- | --- | --- | --- | --- | --- |
| PE32 / PE64 (EXE, DLL, SYS), .NET | ✅ inkl. Architektur, DLL, CLR | ✅ Rohbytes | ✅ (kein Container) | `positive_benign_and_test_only_content` | vollständig mit YARA-X |
| Skripte (PowerShell, JS, VBS, Batch) | 🟡 nur „Text“/„Script“ (Shebang) | ✅ Rohbytes | ✅ (kein Container) | – | AMSI fehlt (P07) |
| ZIP | ✅ | 🟡 nur Rohbytes | ✅ belegt | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| ZIP mit Passwort | ✅ | 🟡 nur Rohbytes | ✅ → Lücke `encrypted` | `harmless_archives_normal_encrypted_nested` | Lücke `content_not_inspected` |
| Verschachtelte Archive | – | – | ✅ bis zur Grenze; darüber Lücke `engine_limit_exceeded` | `recursion_limit_is_reported_as_gap` | Lücke |
| Office OOXML (docx/xlsx/pptx) | ✅ | 🟡 nur Rohbytes | ✅ belegt | `content_formats_are_backed_by_real_clamav` | Lücke |
| Office 97–2003 / MSI (OLE CFB) | 🟡 nicht unterschieden | 🟡 nur Rohbytes | ✅ belegt | `content_formats_are_backed_by_real_clamav` | Lücke |
| 7z | ✅ | 🟡 nur Rohbytes | ✅ belegt | `content_formats_are_backed_by_real_clamav` | Lücke |
| GZIP | ✅ | 🟡 nur Rohbytes | ✅ belegt | `content_formats_are_backed_by_real_clamav` | Lücke |
| CAB | ✅ | 🟡 nur Rohbytes | ✅ belegt | `content_formats_are_backed_by_real_clamav` | Lücke |
| PDF | ✅ | 🟡 nur Rohbytes | ✅ belegt (Stream-Inhalte) | `content_formats_are_backed_by_real_clamav` | Lücke |
| RAR | ✅ | 🟡 nur Rohbytes | ⛔ nicht belegt (abhängig von unrar in der Installation) | – | immer Lücke |
| RTF | ✅ | 🟡 nur Rohbytes | ⛔ nicht belegt | – | immer Lücke |
| ISO 9660 | ✅ | 🟡 nur Rohbytes | ⛔ nicht belegt | – | immer Lücke |
| VHDX | ✅ | 🟡 nur Rohbytes | ⛔ nicht belegt | – | immer Lücke |
| LNK | ✅ | ✅ Rohbytes | ✅ (kein Container) | – | vollständig mit YARA-X |
| Dateien > 256 MB (Standard) | – | – | – | `size_limit_is_reported_not_clean` | Lücke `size_limit`, nie sauber |
| Links, Junctions, Reparsepunkte | – | – | – | `symlink_is_not_followed` | Lücke `link_not_followed` |
| Alternate Data Streams | ⛔ | ⛔ | ⛔ | – | Lücke (AXS-018) |

Belegt = Test mit echtem ClamAV 1.5.4 unter Linux; unter Windows und LTSC noch nicht ausgeführt (B-03).

## Regelbestand (Befund 7)

`axsafe engines` und die Oberfläche zeigen **Bereitschaft**, **Regelbestand** und **Containerfähigkeit** getrennt:

| Regelbestand | Bedeutung |
| --- | --- |
| `test_only` | nur Funktionstest-Regeln/Signaturen (z. B. EICAR). **Keine Erkennung echter Schadsoftware.** UI zeigt „NUR FUNKTIONSTEST-REGELN GELADEN“. |
| `production` | eigene YARA-X-Regeln über den Testsatz hinaus (Qualität nicht gemessen) |
| `official_signatures` | offizielle ClamAV-Datenbank (`daily`-Stand wird angezeigt); Updatepfad separat nachgewiesen (CI-Job `clamav-signatures`) |
| `custom_signatures` | eigene ClamAV-Datenbank |

Aus einem EICAR-Fund wird **keine** Erkennungsleistung abgeleitet.

## Schutzfunktionen

| Funktion | Stand | Anforderung |
| --- | --- | --- |
| Scan auf Anforderung (Dateien/Ordner) | ✅ CLI + UI | AXS-026 |
| Abbruch | ✅ UI beendet Prozess; es wird kein Ergebnis angezeigt | AXS-026 |
| Leerer Auftrag | ✅ „Keine prüfbaren Objekte“ (`nothing_scanned`, Exit 5) | AXS-026 |
| Schnell-/Vollscan, Kontextmenü, Zeitplan | ⛔ | AXS-026 |
| Echtzeitschutz | ⛔ | AXS-053 ff. |
| Quarantäne | ⛔ (nur Meldung) | AXS-035 ff. |
| AMSI / Skriptschutz | ⛔ | AXS-047 ff. |
| Verhaltenserkennung | ⛔ | AXS-041 ff. |
| Ransomware-Schutz | ⛔ | AXS-061 ff. |
| Web, Netzwerk, E-Mail, USB | ⛔ (USB-Laufwerk manuell scanbar) | AXS-067 ff. |
| Updates | ⛔ | AXS-029 ff. |
| Cloud | ⛔ bewusst aus | AXS-079 ff. |
