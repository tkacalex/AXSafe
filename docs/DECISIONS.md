# Entscheidungsprotokoll

## Getroffen

| Datum | ID | Entscheidung | Beleg |
| --- | --- | --- | --- |
| 2026-10-24 | E-01 | Hauptziel Windows 10 Enterprise LTSC 2021, x64 (gemessen bestätigt) | [PLATFORM.md](PLATFORM.md) |
| 2026-10-24 | E-02 | Eigener Kern + Engineadapter, Start mit YARA-X und ClamAV | [ADR-0001](adr/ADR-0001-engine-strategie.md) |
| 2026-10-24 | E-03 | Stack Rust 1.97.0 / .NET 10 WPF, exakte Pins | [ADR-0002](adr/ADR-0002-technologie-stack.md) |
| 2026-10-24 | E-04 | Zehn ehrliche Ergebniszustände | [ADR-0004](adr/ADR-0004-ergebnismodell.md) |
| 2026-10-24 | E-05 | Keine Schadsoftware/EICAR-Datei im Repo, Tests erzeugen Daten zur Laufzeit | [ADR-0005](adr/ADR-0005-testdaten.md) |
| 2026-10-24 | E-06 | Code öffentlich auf GitHub `tkacalex/AXSafe` (Wunsch des Inhabers) | Auftrag vom 24.10.2026 |
| 2026-10-24 | E-07 | Defender bleibt aktiv; AXSafe ist bis zur geprüften Primärschutzfreigabe ein ergänzender Scanner | Spezifikation AXS-076 |
| 2026-10-25 | E-08 | Dienstkonto **LocalService** statt LocalSystem: Der Dienst braucht nur `SeImpersonatePrivilege` (Dateien mit den Rechten des Auftraggebers lesen) und `SeChangeNotifyPrivilege`; alles andere wird über `sc privs` entzogen. Eigene Dienst-SID für die Ordner-ACLs | [ADR-0006](adr/ADR-0006-worker-isolation.md) |
| 2026-10-25 | E-09 | Identität eines Pipe-Clients nur aus dem Token (Impersonation → Thread-Token → RevertToSelf), nie aus Nachrichtenfeldern; Eigentum = Benutzer-SID + Anmeldesitzung | ADR-0006 |
| 2026-10-25 | E-10 | ClamAV unter Windows nur mit Rechtebeschränkung: eingeschränktes Token (Integrität Niedrig) plus ausgehende Firewall-Sperrregel, weil ClamAV 1.5 im AppContainer nicht startet (Pfadauflösung dort verweigert, gemessen). Ohne Abschottung „nicht verfügbar“; ungeschützter Betrieb nur per ausdrücklichem CLI-Schalter mit sichtbarem Hinweis, nie automatisch | ADR-0006, Test `appcontainer_path_resolution_is_measured` |
| 2026-10-25 | E-11 | ClamAV wird **nicht mitgeliefert**, sondern vom Einrichtungsskript aus der offiziellen Quelle installiert – gilt, bis Alex D-07 entscheidet; AXSafe-Pakete enthalten damit keinen GPL-Code (der eigene `axsafe-clamav-worker` enthält keinen ClamAV-Code, lädt libclamav aber zur Laufzeit – siehe E-12) | `scripts/windows/setup-clamav.ps1` |
| 2026-10-25 | E-13 | Richtlinie mit Ausnahmen nur als Datei unter `%ProgramData%\AXSafe\Policy`; angewandt nur, wenn Datei und Ordner ausschließlich von Administratoren/SYSTEM änderbar sind (sonst sichere Vorgabe ohne Ausnahmen, sichtbar). Keine Pipe-Nachricht zum Setzen von Ausnahmen | ADR-0006 Schritt 4, `crates/axsafe-core/src/policy.rs` |
| 2026-10-25 | E-12 | B-18: libclamav wird **dauerhaft in einem eigenen, abgeschotteten Worker** (`axsafe-clamav-worker`) geladen (Wahl von Alex, Option 2) statt clamd. Kein TCP-Port, nur eine anonyme Pipe zum startenden Prozess; dieselbe Abschottung wie clamscan (eingeschränktes Token, Integrität Niedrig, Job Object, Firewall-Sperrregel; Linux Landlock). Der Worker enthält nur GPL-2.0-verträgliche Abhängigkeiten, CI-geprüft. clamscan bleibt als Vergleichs- und Ausweichweg (`--clamav-modus clamscan`) | [LICENSE-REVIEW-libclamav.md](LICENSE-REVIEW-libclamav.md), ADR-0006 |
| 2026-10-26 | E-14 | AXS-025: Heuristik meldet „Verdächtig“ nur bei eindeutigen Täuschungsmustern (Richtungssteuerzeichen, doppelte Endung, Programm mit Dokument-Endung) und nennt Belege. Entropie, fehlende Signatur, Packer und Internet-Herkunft sind nur Hinweise. Authenticode läuft im Host über `WinVerifyTrust` auf dem geöffneten Handle ohne Netz; Katalogsignaturen werden nicht geprüft und so ausgewiesen | `crates/axsafe-core/src/heuristics.rs`, `trust.rs` |
| 2026-10-27 | E-15 | AXS-026: Fortsetzen über eine Fortsetzungsdatei (JSON-Zeilen, Kopf mit Versionsschlüssel). Übernommen wird ein Ergebnis nur bei gleichem Inhalt (SHA-256 nach erneutem Lesen), gleichem Versionsschlüssel (Programm, Engines, Regel-/Signaturstand, Heuristik, Richtlinie, Grenzen) und früher vollständigem Ergebnis. Die Datei liegt beim Benutzer; wer sie ändern kann, hat ohnehin dessen Rechte. Zeitplan über die Windows-Aufgabenplanung mit Benutzerrechten (keine Erhöhung), Kontextmenü nur unter HKCU | `crates/axsafe-core/src/resume.rs`, `scripts/windows/zeitplan.ps1`, `kontextmenue.ps1` |

## Offen (Entscheidung durch Alex)

| ID | Frage | Optionen | Blockiert |
| --- | --- | --- | --- |
| D-01 | Welche Projektlizenz? | Apache-2.0 · MIT · GPL · keine | Beiträge Dritter, Paketierung (B-08). **Neu (B-18):** Die Crates im ClamAV-Worker (`axsafe-clamav-worker`, `axsafe-workerproto`, `axsafe-core`) brauchen vor einer Weitergabe eine GPL-2.0-verträgliche Lizenz (z. B. GPL-2.0-only oder zusätzlich MIT); reines Apache-2.0 genügt dort nicht ([LICENSE-REVIEW-libclamav.md](LICENSE-REVIEW-libclamav.md)) |
| D-02 | Privatprojekt oder öffentliche/kommerzielle Bereitstellung? | privat · kostenlos öffentlich · kommerziell | CRA-Pfad, Signierung, Budget |
| D-03 | Laborhost? | zweites Gerät · VMs auf dem Alltagsrechner (nur ohne reale Proben) · Cloud-VM | AXS-008 (B-02) |
| D-04 | Secure Boot auf dem Alltagsrechner aktivieren? | ja · nein | nur Empfehlung, AXSafe ändert nichts selbst |
| D-05 | Akzeptierte Cloudstufen? | keine · nur Hash-Reputation · Upload nach Einzelfreigabe | P12 |
| D-06 | Leistungsbudgets (CPU/RAM/IO)? | nach Baseline-Messung festlegen | T-094 |
| D-07 | ClamAV später mitliefern? | ja (GPL-Pflichten) · nein (separat installieren) | Paketierung |
