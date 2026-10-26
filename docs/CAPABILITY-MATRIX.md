# Fähigkeitsmatrix

Was AXSafe heute **tatsächlich** kann, je Format und Schutzfunktion. Unbekannte Kombinationen gelten **nicht** als geschützt.

## Dateiformate (AXS-023, AXS-024)

Typerkennung erfolgt nach Inhalt (`axsafe filetype`), nie nach Endung.

**Rohbytes ≠ Inhaltsprüfung (Befund 3).** YARA-X prüft nur die Bytes der Datei, wie sie auf der Platte liegen; Inhalte von Containern werden nicht entpackt. Ein Container gilt nur dann als vollständig geprüft, wenn eine **bereite** Engine das Format **nachweislich** inhaltlich prüft und dabei weder Fehler noch Zeitüberschreitung hatte. Sonst trägt das Objekt die Lücke `content_not_inspected` (Zustand `Unsupported`). `Encrypted` wird nur gemeldet, wenn die Engine es zuverlässig feststellt (ClamAV `Heuristics.Encrypted.*`). AXSafe entpackt selbst nichts.

Die folgende Tabelle wird aus der laufenden CLI erzeugt (`axsafe faehigkeiten --json`, CI prüft den Gleichstand). **Erkannt** heißt: Der Typ wird nach Inhalt bestimmt (Testbeleg). **Inhalt geprüft** heißt: Eine bereite Engine prüft den Inhalt dieses Formats nachweislich. Bei Containern ohne solche Engine entsteht immer die Lücke `content_not_inspected`.

<!-- FORMATE:START (automatisch erzeugt von scripts/gen_capability_matrix.py) -->
| Format | erkannt (Beleg) | Container | Inhalt geprüft durch | Inhaltsbeleg | ohne fähige Engine |
| --- | --- | --- | --- | --- | --- |
| PE32/PE64 (EXE) | ✅ `filetype::tests::pe_variants` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| PE DLL | ✅ `filetype::tests::pe_variants` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| .NET-Assembly | ✅ `filetype::tests::pe_variants` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| PE beschädigt | ✅ `filetype::tests::truncated_or_hostile_pe_is_malformed_not_panic` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| ELF | ✅ `filetype::tests::common_signatures` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| ZIP | ✅ `filetype::tests::common_signatures` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| Office OOXML | ✅ `filetype::tests::common_signatures` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| MSI | ✅ `filetype::tests::ole_subtypes_msi_vs_office` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| Word 97–2003 | ✅ `filetype::tests::ole_subtypes_msi_vs_office` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| Excel 97–2003 | ✅ `filetype::tests::ole_subtypes_msi_vs_office` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| PowerPoint 97–2003 | ✅ `filetype::tests::ole_subtypes_msi_vs_office` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| OLE sonstige (MSP, MST, MSG …) | ✅ `filetype::tests::ole_subtypes_msi_vs_office` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| PDF | ✅ `filetype::tests::common_signatures` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| RTF | ✅ `filetype::tests::common_signatures` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| LNK | ✅ `filetype::tests::common_signatures` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| 7z | ✅ `filetype::tests::common_signatures` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| RAR | ✅ `filetype::tests::common_signatures` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| GZIP | ✅ `filetype::tests::common_signatures` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| BZIP2 | ✅ `filetype::tests::disk_and_archive_containers` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| XZ | ✅ `filetype::tests::disk_and_archive_containers` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| TAR | ✅ `filetype::tests::disk_and_archive_containers` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| CAB | ✅ `filetype::tests::common_signatures` | ja | clamav | `content_formats_are_backed_by_real_clamav` | Lücke `content_not_inspected` |
| WIM | ✅ `filetype::tests::disk_and_archive_containers` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| ISO 9660 | ✅ `filetype::tests::common_signatures` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| UDF | ✅ `filetype::tests::disk_and_archive_containers` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| VHD | ✅ `filetype::tests::disk_and_archive_containers` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| VHDX | ✅ `filetype::tests::common_signatures` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| VMDK | ✅ `filetype::tests::disk_and_archive_containers` | ja | **niemand – immer Lücke** | – (kein Engine-Beleg) | Lücke `content_not_inspected` |
| PowerShell | ✅ `filetype::tests::script_languages_by_content` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| Batch | ✅ `filetype::tests::script_languages_by_content` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| VBScript | ✅ `filetype::tests::script_languages_by_content` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| JavaScript/JScript | ✅ `filetype::tests::script_languages_by_content` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| HTA | ✅ `filetype::tests::script_languages_by_content` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| Python | ✅ `filetype::tests::script_languages_by_content` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| Shell | ✅ `filetype::tests::common_signatures` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
| Text | ✅ `filetype::tests::common_signatures` | nein | yara-x, clamav | Dateibytes = Inhalt | – |
<!-- FORMATE:END -->

Weitere Fälle:

| Fall | Verhalten | Beleg |
| --- | --- | --- |
| Datei größer als das Limit (Standard 256 MB) | Lücke `size_limit`, nie sauber | `size_limit_is_reported_not_clean` |
| Links, Junctions, Reparsepunkte | nicht verfolgt, Lücke `link_not_followed` | `symlink_is_not_followed`, `junction_is_not_followed` (Windows) |
| Alternate Data Streams | jeder Strom einzeln als `Datei:Strom` geprüft | `alternate_data_streams_are_scanned_separately` (Windows) |
| Verschlüsselte Archive | Lücke `encrypted` (nur wenn die Engine es sicher feststellt) | `harmless_archives_normal_encrypted_nested` |
| Verschachtelung über die Grenze | Lücke `engine_limit_exceeded` | `recursion_limit_is_reported_as_gap` |

Belege: Linux-CI und Windows-CI mit echtem ClamAV 1.5.4; Rust-Testsuite zusätzlich auf dem Zielrechner LTSC (ohne die EICAR-auf-Platte-Tests).

## Statische Merkmale und Heuristik (AXS-025)

| Merkmal | Wo bestimmt | Wirkung |
| --- | --- | --- |
| SHA-256 | Host | Identität im Bericht |
| SHA-1, MD5 | Host | nur Abgleich mit externen Listen, nie Identitätsnachweis |
| PE-Struktur (Sektionen, Entropie, Rechte, Importe, Overlay, Einsprungpunkt) | abgeschotteter Worker (Dienst/CLI mit Worker), sonst im Prozess | nur Hinweise |
| Mark of the Web (`Zone.Identifier`) | Host, unter dem Zugriffswächter | Zone + Rechnername im Bericht; Hinweis bei Internet-Herkunft |
| Authenticode (eingebettet) | Host, `WinVerifyTrust` auf dem geöffneten Handle, ohne Netz | Status + Unterzeichner im Bericht; Hinweis wenn nicht gültig. Katalogsignaturen nicht geprüft, Widerruf offline nicht erkennbar. Gültige Signatur ≠ harmlos |
| AXS-HEUR-0001 Richtungssteuerzeichen im Namen + ausführbarer Inhalt | Host | Fund „Verdächtig“ mit Belegen |
| AXS-HEUR-0002 Dokument-Endung vor Programm-Endung + ausführbarer Inhalt | Host | Fund „Verdächtig“ mit Belegen |
| AXS-HEUR-0003 Dokument-/Medien-Endung, Inhalt Windows-Programm | Host | Fund „Verdächtig“ mit Belegen |
| Hohe Entropie, fehlende Signatur, Packer-Abschnitte, keine Importe, Overlay | – | **nie ein Fund**, nur Hinweis |

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
