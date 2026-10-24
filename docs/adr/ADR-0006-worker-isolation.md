# ADR-0006: Isolierter Scanworker und Broker-IPC (P02)

* Status: **teilweise umgesetzt** – Schritt 1 (Scanworker) umgesetzt und auf Windows Server sowie Linux getestet; Schritt 2 (Dienst + Named Pipe) offen. Windows 10 LTSC: nicht getestet (B-02).
* Datum: 2026-10-24
* Anforderungen: AXS-013, AXS-014, AXS-020, AXS-021, AXS-022, AXS-028

## Problem

Heute laufen YARA-X und die Typerkennung im selben Prozess wie die CLI; ClamAV läuft als Kindprozess mit denselben Rechten. Ein Parserfehler in untrusted Dateien könnte damit alles erreichen, was der aufrufende Benutzer darf. Außerdem fehlen ein hartes Speicherlimit und das sichere Beenden ganzer Prozessbäume.

## Entscheidung (geplant)

```
AXSafe Desktop (Benutzer) ──Named Pipe v1 (ACL)──► axsafe-service (LocalSystem, minimal)
                                                      │ öffnet Datei selbst (Handle, Identität)
                                                      │ übergibt NUR Bytes/Section, keinen Pfad
                                                      ▼
                                       axsafe-worker.exe (pro Auftrag)
                                       · Restricted Token / AppContainer ohne Fähigkeiten
                                       · Job Object: Speicherlimit, CPU-Zeit, KILL_ON_JOB_CLOSE,
                                         ActiveProcessLimit, keine UI-Handles
                                       · Process Mitigations: kein dynamischer Code (außer
                                         YARA-X/wasmtime – zu prüfen), Image-Load nur signiert,
                                         Child-Process-Policy (ClamAV-Ausnahme dokumentiert)
                                       · kein Netzwerk (AppContainer ohne internetClient)
```

### IPC-Vertrag `axsafe.ipc/1`

* Named Pipe `\\.\pipe\AXSafe.v1`, `PIPE_REJECT_REMOTE_CLIENTS`, DACL: SYSTEM + interaktive Benutzer nur Lesen/Schreiben auf die Pipe.
* Clientidentität über `GetNamedPipeClientProcessId` + Token-SID, Sitzungs-ID muss zur Sitzung des Aufrufers passen.
* Nachrichten: Längenpräfix, Höchstgröße 64 KiB, JSON mit Schema-Version, Nonce + monoton steigende Sequenz gegen Replay mutierender Anfragen.
* Erlaubte Aufträge: `ScanPaths`, `CancelJob`, `GetHealth`, `GetReport`. **Keine** freien Lösch-, Kopier- oder Shell-Befehle.
* Rollen: Standardbenutzer darf scannen und eigene Berichte lesen; Policies/Ausnahmen nur Administrator (AXS-017).

## Tests, die vor „erfüllt“ bestehen müssen

| Abnahme | Test |
| --- | --- |
| T-013 | Testworker versucht `C:\Windows\System32\drivers\etc\hosts` zu schreiben und `example.com:443` zu verbinden → beides scheitert, Job wird beendet, Status `Error` |
| T-014 | Fremde Sitzung, anderer Benutzer, 1-MiB-Nachricht, wiederholte Nonce → abgewiesen und protokolliert |
| T-021 | Worker-Absturz (Testmodus) → `Error`, Dienst läuft weiter |
| T-022 | Regel mit hohem Speicherbedarf → Job-Speicherlimit greift → `Error`/`Timeout`, Host bleibt bedienbar |
| B-11 | Hängende Engine mit Enkelprozess → gesamter Baum über Job Object beendet |

## Offene Fragen

* Verträgt sich wasmtime (YARA-X) mit `ProhibitDynamicCode`? Falls nein: eigene Ausnahme nur für den YARA-Worker, dokumentiert.
* ClamAV unter AppContainer: Zugriff auf Signaturdatenbank über explizite ACL.
* Alles muss auf Windows 10 LTSC 19044 im Labor (B-02) nachgewiesen werden.

## Umsetzungsstand (2026-10-24)

### Schritt 1 – Scanworker: umgesetzt

| Teil | Umsetzung | Nachweis |
| --- | --- | --- |
| Worker-Prozess | `axsafe-worker[.exe]` (Crate `axsafe-worker`), bekommt Regeltexte und Bytes über stdin, **nie Pfade**; Protokoll `axsafe.worker/1` mit Höchstgrößen vor dem Allokieren | `protocol::tests`, `real_worker_is_isolated_and_scans` |
| Windows-Abschottung | **AppContainer ohne Fähigkeiten** (eigenes `CreateProcessW` mit `SECURITY_CAPABILITIES`, `HANDLE_LIST` nur für die drei Pipes, Arbeitsordner System32) + **Job Object** (1 aktiver Prozess, Commit-Grenze, Kill-on-close, kein Breakaway); Worker prüft sein Token und verweigert ohne AppContainer | CI Windows Server: `compromised_worker_cannot_touch_system_files_or_network`, `unsandboxed_worker_is_refused_on_windows`, CLI-Rauchtest `isolation.enforced = true` |
| Linux-Abschottung (Entwicklung) | Selbstbeschränkung mit **Landlock** vor jeder Eingabe: kein Dateizugriff, kein `exec`, kein TCP (ABI ≥ 4), `PDEATHSIG`. **Grenze:** UDP wird von Landlock nicht erfasst | CI Linux und lokal (ABI 7) |
| Nachweis statt Annahme | Beim Start Probe: Lesen und Öffnen-zum-Schreiben einer Benutzerdatei, Anlegen im Temp-Ordner, TCP zu lokalem Lauscher, Programmstart – alles muss scheitern; der Lauscher darf keine Verbindung sehen. Ohne Nachweis ist die Engine unter Windows **nicht verfügbar** | `real_worker_is_isolated_and_scans` |
| Grenzen je Anfrage | Ablaufdatum = Objektbudget + Zuschlag; Zeitüberschreitung, Absturz, Protokollbruch → Lücke, Worker wird beendet und beim nächsten Objekt neu gestartet; nach `max_restarts` Abschaltung | `hanging_worker_is_timeout_and_killed_within_budget`, `crash_is_error_gap_and_worker_restarts`, `repeated_crashes_disable_engine_instead_of_looping`, `protocol_violations_are_errors` |
| Speicher | 512 MiB + 2 × größte Nutzlast (Windows: Commit im Job; Linux: `RLIMIT_AS`) | `memory_hungry_worker_is_stopped_by_limit` |
| Sichtbarkeit | `EngineInfo.isolation` (Art, nachgewiesen, Detail) in CLI, JSON, Client und WPF | `Engines_report_test_only_rules` (C#) |

Gefundene und behobene Windows-Probleme (nur durch echte Windows-Läufe sichtbar): `conhost.exe` zählte im Job als Nachkomme (jetzt `DETACHED_PROCESS`); parallele erste AppContainer-Profilanlage ließ `CreateProcessW` mit „Datei nicht gefunden“ scheitern (jetzt prozessübergreifendes Mutex + kurzer Wiederholversuch); Kollision der Probeordner paralleler Engines (jetzt Zähler).

### Noch offen

* **Schritt 2 – Dienst `axsafe-service` mit Named Pipe `axsafe.ipc/1`** (AXS-014): ACL, Prüfung von Client-SID und Sitzung, Nachrichtenlimits, Nonce/Sequenz gegen Wiederholung, Zugriff auf Dateien nur mit den Rechten des Auftraggebers (Impersonation). Bis dahin öffnet die CLI die Dateien mit den Rechten des Benutzers – der Dienst existiert noch nicht, also gibt es auch keine Rechteausweitung.
* **Typerkennung** läuft noch im Host-Prozess (kleiner, gefuzzter Parser; kein Allokieren nach Eingabelänge). Verlagerung in den Worker geplant.
* **ClamAV** läuft als Kindprozess mit Grenzen, aber ohne AppContainer (Signaturdatenbank bräuchte eine ACL-Freigabe).
* Alles muss auf **Windows 10 LTSC 19044** im Labor wiederholt werden (B-02).
