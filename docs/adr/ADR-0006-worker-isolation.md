# ADR-0006: Isolierter Scanworker und Broker-IPC (P02)

* Status: **teilweise umgesetzt** – Schritt 1 (Scanworker) und Schritt 2 (Dienst + Named Pipe, ClamAV im AppContainer, Typerkennung im Worker) umgesetzt; Nachweise siehe „Umsetzungsstand“. Windows 10 LTSC: nicht getestet (B-02).
* Datum: 2026-10-24, fortgeschrieben 2026-10-25
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

### Schritt 2 – Dienst, Named Pipe, ClamAV-Abschottung (2026-10-25)

Abweichung vom Entwurf: Der Dienst läuft als **LocalService**, nicht als LocalSystem (E-08). Er braucht keine Systemrechte, weil er Dateien ausschließlich **unter Impersonation des Auftraggebers** öffnet.

| Teil | Umsetzung | Nachweis |
| --- | --- | --- |
| Dienstkonto | `NT AUTHORITY\LocalService`, Dienst-SID `unrestricted`, erforderliche Privilegien nur `SeImpersonatePrivilege`, `SeChangeNotifyPrivilege` (`sc privs`); Neustart nach Absturz (5 s / 30 s) | `service_e2e.ps1`: `installiert_konto`, `privilegien_minimal` |
| Ordner | Programm `%ProgramFiles%\AXSafe\service` (erbt: Benutzer nur Lesen/Ausführen); Daten `%ProgramData%\AXSafe\Service` nur SYSTEM, Administratoren, `NT SERVICE\AXSafeService` – Benutzer kein Zugriff | `install-service.ps1` prüft die ACLs |
| Pipe | `\\.\pipe\AXSafe.v1`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`; SDDL `D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;0x0012018b;;;IU)` – Netzwerkanmeldungen verweigert, interaktive Benutzer lesen/schreiben, **ohne** `FILE_APPEND_DATA` (= keine eigene Pipe-Instanz) | `client_absturz`, `status`, C# `Status_scan_and_report_through_real_service` |
| Identität | `ImpersonateNamedPipeClient` → `OpenThreadToken` → `RevertToSelf` (scheitert das Zurückkehren, endet der Dienst). Aus dem Token: Benutzer-SID, `AuthenticationId` (Anmeldesitzung), `TokenSessionId`, Impersonationsstufe ≥ `SecurityImpersonation`. Abgewiesen: Sitzung 0, Dienst- und Systemkonten, alles außer `S-1-5-21-…` und `S-1-12-1-…`. Nachrichten enthalten **keine** Identitätsfelder | `identity::tests`, `service_accounts_and_session_zero_are_refused` |
| Eigentum | Auftrag und Bericht gehören Benutzer-SID **und** Anmeldesitzung; Fremdzugriff → `not_found` (verrät keine Existenz) | `owner_can_scan_and_read_report_other_user_cannot`, `jobs::other_owner_cannot_see_cancel_or_read`, e2e mit zweitem lokalen Benutzer |
| Nachrichten | Längenpräfix (u32 LE), Anfrage ≤ 64 KiB, Antwort ≤ 16 MiB, `deny_unknown_fields`, Typ/Werte geprüft (≤ 64 Pfade, nur absolute lokale Laufwerkspfade, keine UNC-, Geräte- oder `\\?\`-Pfade, kein NUL), `seq` streng steigend, Nonce (32 Hex) je Benutzer+Sitzung gegen Wiederholung (4096 gemerkt), Token-Bucket 20/s, Spitze 40 | `ipc::tests`, `replayed_and_non_increasing_requests_are_rejected`, `oversized_malformed_and_slow_messages_end_the_connection`, `rate_and_job_limits_bound_overload` |
| Befehle | nur `status`, `scan_start`, `scan_cancel` (eigener Auftrag), `job`, `report` (eigene). Kein Löschen, Kopieren, keine Shell | `only_listed_commands_and_fields_are_accepted` |
| Dateizugriff | `FileAccess`-Wächter: vor jedem `symlink_metadata`/`read_dir`/`open`/`read` wird das Client-Token gesetzt (`SetThreadToken`), danach zurückgesetzt. Scheitert der Wechsel, wird **nicht** mit Dienstrechten gelesen, sondern eine Lücke `AccessDenied` gemeldet. Dateiidentität, Link-Regeln und Austauscherkennung bleiben wie in P01; an den Worker gehen nur Bytes | `failed_identity_switch_never_reads_with_own_rights`, e2e `unberechtigter_dateizugriff` |
| Aufträge | 2 gleichzeitig, 8 wartend, 4 je Eigentümer, 200 Berichte behalten; Bericht exklusiv neu angelegt | `limits_bound_queue_and_parallelism`, `reports_are_never_overwritten` |
| Zustände | Oberfläche: *Dienst fehlt / startet / bereit / gestört / nicht erreichbar*; „bereit“ nur, wenn der Dienst `service = bereit` und geprüfte Engines meldet | C#-Client, UI-Prüfung (`Dienst fehlt` ohne Dienst) |
| Typerkennung | im Worker (Antwort `ScanReply.file_kind`); Ausfall → Lücke | `classification_in_engine_drives_container_logic`, `classification_failure_or_missing_classifier_is_gap` |
| ClamAV | Windows: AppContainer `AXSafe.ClamAV.v1` ohne Fähigkeiten im Job Object; Token vor `ResumeThread` geprüft (`TokenIsAppContainer`, keine Fähigkeiten); Signaturordner per ACE gezielt **nur lesbar** für die AppContainer-SID (das Einrichtungsskript setzt sie, weil Benutzer den Ordner nicht ändern dürfen); `--tempdir` im AppContainer-Ordner; minimale Umgebung. Programm (`Program Files\ClamAV`) und Signaturen (`ProgramData\AXSafe\ClamAV\database`) getrennt. Ohne Abschottung: „nicht verfügbar“ | Windows-CI `windows-clamav` |

**Grenzen und Zeitlimits**

| Stelle | Grenze |
| --- | --- |
| Pipe-Verbindung | Leerlauf 120 s, je Nachricht 5 s ab erstem Byte, Schreiben 10 s (überlappende E/A mit `CancelIoEx`) |
| Worker | Start 60 s, je Anfrage Objektbudget + 5 s, Speicher 512 MiB + 2 × Nutzlast, 3 Neustarts, dann abgeschaltet |
| ClamAV | gemeinsames Ablaufdatum je Aufruf inkl. Nachkommen und Pipes, Ausgabe begrenzt, Funktionstest beim Laden 120 s |
| Enginezustand im Dienst | Hintergrundprüfung beim Start, danach alle 600 s; bis dahin „wird geprüft“ |

**Grenzen unter Linux (nur Entwicklung):** Landlock erfasst kein UDP und keine abstrakten Unix-Sockets älterer ABIs; ClamAV läuft unter Linux ohne Rechtebeschränkung (nur Prozessgruppe, Zeit, Speicher). Der Dienst existiert nur unter Windows; die Handler-Tests laufen unter Linux über Unix-Sockets mit fest vorgegebener Identität.

### Noch offen

* Alles muss auf **Windows 10 LTSC 19044** im Labor wiederholt werden (B-02). Windows Server (CI) ist kein LTSC-Nachweis.
* Process-Mitigation-Policies (dynamischer Code, signierte Images) sind noch nicht gesetzt.
* Die Verhaltensprobe gilt nur für den eigenen Worker; für `clamscan` (fremdes Programm) ist die Abschottung über Token-Prüfung belegt, nicht über eine Probe.
