# P03 – Dateiprüfung und Erkennungskern: Bestandsaufnahme und Etappen

Stand: 26.10.2026, vor Beginn der Umsetzung. Quelle der Anforderungen: `docs/spec` (AXS-021 … AXS-028).

**Gate P03:** Erkennung, Negativfälle, verschachtelte Container und alle Scanfehler sind nachvollziehbar getestet; keine Probe wird auf dem Host ausgeführt.

**Grundsätze:** Bestehende, belegte Komponenten werden erhalten und gezielt ergänzt. Gefährliche Laborprüfungen gehören nicht auf den Alltagsrechner (B-02). Testdaten entstehen nur zur Laufzeit. Defender bleibt aktiv.

## Bestandsaufnahme je Anforderung

| ID | Bereits belegt (Test/Nachweis) | Fehlt | Etappe |
| --- | --- | --- | --- |
| AXS-021 Engineadapter | YARA-X-Worker (AppContainer/Landlock) und ClamAV-Worker (libclamav dauerhaft, eingeschränktes Token) mit echten Ergebnissen; Versionen je Ergebnis; Absturz, Hänger und Protokollbruch werden zur Lücke; Neustart; Windows-, Linux- und LTSC-Läufe | schriftlicher **Engine-Vertrag** für weitere Anbieter; **gemeinsame Vertragstests**, die jede Engine bestehen muss | E7 |
| AXS-022 Eigene Regeln | Pflichtmetadaten (id, verdict, severity, confidence, author, license, source, min_engine), Mindestversion, Zeitlimit, Speichergrenze des Workers, `test_only` unübersehbar | **Versionsfeld** je Regel; **Positiv- und Gegenbeispiel je Regel** als Pflicht (Regeltest-Harness, CI scheitert ohne); Regelsatz-Manifest mit Prüfsumme; **Signierung → P04 (offene Abnahme)** | E6 |
| AXS-023 Typerkennung | Inhalt statt Endung; PE32/64, DLL, .NET, ZIP, OOXML, OLE, PDF, RTF, LNK, 7z, RAR, GZIP, CAB, ISO, VHDX; gekürzte PE ohne Panic | **Skriptsprachen** (PowerShell, JavaScript, VBScript, Batch, HTA/HTML, Python, Shell); **MSI vs. Office 97–2003** (Word/Excel/PowerPoint); **VHD, VMDK, UDF**; Matrix „erkannt“ vs. „inhaltlich geprüft“ getrennt | E1 |
| AXS-024 Container | ZIP, OOXML, OLE, 7z, GZIP, CAB, PDF mit echtem ClamAV inhaltlich geprüft; Passwort-ZIP → `encrypted`; Rekursionsgrenze → Lücke; ohne fähige Engine `content_not_inspected` | **Archivbombe** (Größen-/Mengengrenze) mit echter Engine; **Pfadausbruch** (`../`-Einträge) ohne Hostschaden; **beschädigte Archive** → Lücke statt „sauber“; ISO/RAR/VHDX-Belege oder begründete Lücke; Windows-Nachweise | E5 |
| AXS-025 Statische Merkmale | nur SHA-256 und Typ | Hashes (SHA-256/SHA-1/MD5 für Abgleich), **Authenticode** (Windows `WinVerifyTrust`), **Mark of the Web** (`Zone.Identifier`), PE-Struktur (Sektionen, Entropie, Importe) im abgeschotteten Worker; **Heuristik nur mit Belegen** und gutartigen Gegenfällen; Entropie oder fehlende Signatur allein nie ein Fund | E2 |
| AXS-026 Scanarten | eigener Scan, Abbruch, leerer Auftrag = `nothing_scanned` | **Schnellscan, Vollscan, Wechselmedienscan, Kontextmenü, Zeitplan**; Fortschritt (Objekte/Bytes); **Fortsetzen** mit Neuprüfung geänderter Dateien und bei geändertem Engine-/Regel-/Richtlinienstand; Manifest stimmt mit Zählungen überein; „keine Quarantäneaktion verloren“ erst mit P05 prüfbar | E3 |
| AXS-027 Cache | – | **Sicherer Cache** im Dienst (geschützter Ordner): Schlüssel = Inhalt (SHA-256) + Engine-, Regel- und Richtlinienstand; schneller Pfad nur mit verlässlichem Dateizustand; Wechselmedien/neu eingebundene Datenträger nie aus dem Zustand; nur vollständige Ergebnisse | E4 |
| AXS-028 Robustheit | Scanner liest nur; PE-Parser übersteht Kürzungen; Rahmengrößen vor Allokation geprüft; Typerkennung im Worker; FIFO blockiert nicht | **Fuzzing** (libFuzzer-Ziele für Typerkennung, Worker-Protokoll, Richtlinie, PE-Merkmale; CI-Lauf); **Mutationstests** im normalen Testlauf; Nachweis „geprüfte Programme starten nie“; temporäre Dateien begrenzt und aufgeräumt (auch nach Absturz) | E1 (Grundlage), E8 |

## Etappen

| Etappe | Inhalt | Abnahme in dieser Etappe |
| --- | --- | --- |
| **E1** | Typerkennung erweitern (Skripte, MSI/Office, VHD/VMDK/UDF), Fähigkeitsmatrix trennt „erkannt“ und „inhaltlich geprüft“; Mutationstests der Parser | T-023 vollständig; T-028 Teil |
| **E2** | Statische Merkmale im Worker, Authenticode und MotW mit Benutzerrechten, Heuristik mit Belegen | T-025 (umgesetzt; Windows-Belege über CI) |
| **E3** | Scanarten, Fortschritt, Fortsetzen | T-026 (ohne Quarantäne-Teil → P05; umgesetzt, Windows-Belege über CI) |
| **E4** | Sicherer Cache im Dienst | T-027 (umgesetzt; Dienst-Belege über CI) |
| **E5** | Container-Härtetests mit echter Engine | T-024 (umgesetzt; ISO belegt, RAR mit unrar) |
| **E6** | Regel-Harness, Regelmanifest | T-022 (umgesetzt; Signierung → P04) |
| **E7** | Engine-Vertrag und Vertragstests | T-021 |
| **E8** | Fuzzing-Ziele und CI-Lauf, „nie ausführen“-Nachweis, Temporärdateien | T-028 |

Nach jeder Etappe: Tests (Linux, Windows-CI, bei Bedarf LTSC-Testpaket), Fähigkeitsmatrix, Anforderungsstatus, CHANGELOG.
