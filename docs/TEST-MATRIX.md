# Testmatrix

Jeder Test nennt Ausgangszustand, Eingabe, Erwartung, tatsächliches Ergebnis, Version und Umgebung. **Keine Erfolgsmeldung ohne ausgeführten Nachweis.**

Zählregeln (Befund 8):

* **Bestanden, fehlgeschlagen und ausgelassen werden getrennt gezählt.** Tests mit externer Vorbedingung tragen `#[ignore = "Grund"]`; sie scheitern laut, wenn die Vorbedingung fehlt, statt still zu bestehen.
* **Linux-CI:** ClamAV und Nicht-root sind Pflicht; alle Tests laufen mit `--include-ignored`. Ein ausgelassener Test lässt den Lauf scheitern (`scripts/ci/test_summary.py --require-none-ignored`).
* **Windows Server (CI, `windows-latest`) ist kein Nachweis für Windows 10 Enterprise LTSC.** LTSC bleibt offen, bis ein Lauf auf LTSC belegt ist (B-02, B-03).
* **Screenshots ersetzen keine Assertions.** Die Oberfläche wird per UI Automation gegen ein unabhängiges CLI-Ergebnis geprüft (`scripts/ci/ui_check.ps1`).

## Letzte belegte Läufe

| Umgebung | Ergebnis | Beleg |
| --- | --- | --- |
| Linux-CI ubuntu-24.04, Nicht-root, ClamAV 1.5.4 (Commit 3e0a9e0) | Rust **98 bestanden / 0 fehlgeschlagen / 0 ausgelassen**; C# **16 / 0 / 0** | CI-Lauf 40129436428 |
| Linux lokal (Entwicklungscontainer), Nicht-root (Stand vor P02) | Rust 89 / 0 / 0; C# 16 / 0 / 0 | [`evidence/2026-10-24-linux-testlauf-befunde.txt`](evidence/2026-10-24-linux-testlauf-befunde.txt) |
| **Windows Server** (CI `windows-latest`, Commit 3e0a9e0) | Rust **90 / 0 / 6** (6 ausgelassen: kein ClamAV im Runner, mit Grund); C# **16 / 0 / 0**; UI-Prüfung 9/9; Worker im AppContainer nachweislich abgeschottet | [`evidence/2026-10-24-windows-server-ci.txt`](evidence/2026-10-24-windows-server-ci.txt) |
| ClamAV offizielle Signaturen (CI-Job, Linux) | FreshClam: daily 28163, main 63, bytecode 339; `official_signatures`; Laufzeit-EICAR als `Eicar-Test-Signature` erkannt, harmlose Datei ohne Fund | CI-Job `clamav-signatures` |
| Reproduktion Befunde 1–6, vorher (491956e) / nachher | siehe Dateien | [`vorher`](evidence/2026-10-24-befunde-vorher-491956e.txt) · [`nachher`](evidence/2026-10-24-befunde-nachher.txt) |
| **Windows Server – Dienst-Systemtest** (CI `windows-service`, Commit 4185958, Lauf 40174054483) | **22 / 0** Prüfungen (Installation, Pipe, zweiter Benutzer, Abstürze, C#-Client gegen echten Dienst, Deinstallation) | [`evidence/2026-10-25-windows-dienst-systemtest.txt`](evidence/2026-10-25-windows-dienst-systemtest.txt) |
| Windows Server – ClamAV im AppContainer (Messung) | ClamAV 1.5 dort **nicht lauffähig** (Pfadauflösung verweigert) → eingeschränktes Token | [`evidence/2026-10-25-clamav-appcontainer-messung.txt`](evidence/2026-10-25-clamav-appcontainer-messung.txt) |
| Windows 10 Enterprise LTSC 21H2 | **nicht ausgeführt** | B-02, B-03 |

## Zuordnung zu Abnahmen und Befunden

Spalten: **Linux** = lokal und Linux-CI · **Win Server** = `windows-latest` in der CI · **LTSC** = Zielsystem.
`n/a` = Test ist plattformspezifisch und dort nicht vorhanden (mit Grund).

| Abnahme / Befund | Test (Crate · Name) | Ausgang → Eingabe → Erwartung | Linux | Win Server | LTSC |
| --- | --- | --- | --- | --- | --- |
| Befund 1 / T-018 | cli · `report_target_equal_to_scan_object_is_refused_and_unchanged` | Berichtsziel = Scanobjekt → Exit 3, Inhalt und SHA-256 unverändert | ✅ | ✅ | offen |
| Befund 1 / T-018 | cli · `report_target_hardlink_to_scan_object_is_refused` | Hardlink auf Scanobjekt als Ziel → Exit 3, unverändert | ✅ | ✅ | offen |
| Befund 1 / T-018 | cli · `report_target_symlink_and_dangling_symlink_are_refused` | Symlink und verwaister Symlink → Exit 3, Ziel unverändert/nicht angelegt | ✅ | n/a (Unix-Symlink) | offen |
| Befund 1 / T-018 | cli · `report_target_windows_symlink_is_refused` | Windows-Symlink → Exit 3 (benötigt Administrator) | n/a | ✅ (ausdrücklich ausgeführt) | offen |
| Befund 1 / T-018 | cli · `report_via_junction_into_scan_root_is_excluded_and_junction_target_refused` | Junction (Reparsepunkt) als Ziel → Exit 3; Bericht über Junction in den Scanbereich → per Datei-ID ausgeschlossen | n/a | ✅ | offen |
| Befund 1 | cli · `report_target_directory_is_refused`, `new_report_inside_scan_root_is_excluded_by_identity` | Ordner als Ziel → Exit 3; neues Ziel im Scanbereich → per Datei-ID ausgeschlossen und im Bericht genannt | ✅ | ✅ | offen |
| Befund 2 / T-015 | core · `report::tests::combinations_keep_invariant`, `outcome_table`, `detection_with_gap_is_both_counted_and_not_complete` | alle Kombinationen Fund × Lücke → Zählinvariante, Ergebnis, Exitcode | ✅ | ✅ | offen |
| Befund 2 / T-015 | core · `scan::tests::detection_and_engine_gap_are_both_visible` | Fund + Engine-Fehler → `detection_incomplete`, beides sichtbar | ✅ | ✅ | offen |
| Befund 2 / T-015 | cli · `detection_plus_engine_error_is_exit_4_and_visible` | YARA-X Fund + ClamAV-Testdoppel mit Fehler → Exit 4 | ✅ | n/a (Shell-Testdoppel) | offen |
| Befund 2 / UI | C# · `Real_report_json_roundtrips_into_model` | Bericht v2 → Text „Fund vorhanden; zusätzliche Prüflücke“ | ✅ | ✅ | offen |
| Befund 3 / T-024 | core · `container_without_capable_engine_is_content_gap`, `container_with_capable_engine_is_complete`, `capable_engine_that_fails_does_not_count_as_inspected` | Container ohne fähige Engine → Lücke `content_not_inspected`; fähige, aber fehlerhafte Engine zählt nicht | ✅ | ✅ | offen |
| Befund 3 / T-024 | cli · `archives_without_container_engine_are_incomplete` | ZIP und Passwort-ZIP nur mit YARA-X → `incomplete`, kein „sauber“ | ✅ | ✅ | offen |
| Befund 3 / T-024 | clamav · `content_formats_are_backed_by_real_clamav` | Testsignatur in ZIP, OOXML, OLE/CFB, 7z, GZIP, CAB, PDF → echter ClamAV findet sie im Inhalt | ✅ (echter ClamAV) | ausgelassen: kein ClamAV im Runner | offen |
| Befund 3 / T-024 | clamav · `harmless_archives_normal_encrypted_nested` | normales, verschlüsseltes, verschachteltes harmloses Archiv → sauber / `Encrypted`-Lücke / sauber | ✅ (echter ClamAV) | ausgelassen: kein ClamAV | offen |
| Befund 3 / T-024 | clamav · `recursion_limit_is_reported_as_gap` | Verschachtelung über Grenze → Lücke `engine_limit_exceeded` | ✅ (echter ClamAV) | ausgelassen: kein ClamAV | offen |
| Befund 4 / T-021 | proc · `parent_exits_but_descendant_holds_pipes`, `hanging_process_hits_shared_deadline`, `child_that_ignores_stdin_cannot_block_past_deadline`, `output_flood_is_cut_off`, `memory_limit_*`, `crash_is_not_success` | Elternprozess endet, Nachkomme hält Pipes → Ende innerhalb Ablaufdatum, Nachkomme beendet; Hänger, Ausgabeflut, Speicher, Absturz begrenzt | ✅ | ✅ (Job Object) | offen |
| Befund 4 / T-021 | proc · `escaped_descendant_on_linux_is_bounded_by_deadline` / `breakaway_from_job_is_denied_and_tree_is_killed` | Nachkomme verlässt Prozessgruppe (Linux) → Ablaufdatum greift; Breakaway aus dem Job (Windows) → verweigert | ✅ | ✅ | offen |
| Befund 4 / T-021 | clamav · `orphan_holding_pipes_does_not_extend_call_and_is_flagged`, `hang_is_timeout_within_budget`, `crash_is_error_gap`, `engine_error_is_error_gap`, `output_flood_is_output_limit_gap` | Testdoppel im clamscan-Stil → Lücke statt „sauber“ | ✅ | ✅ | offen |
| Befund 5 | C# · `Two_parallel_jobs_get_distinct_ids_and_own_reports` | zwei Client-Instanzen parallel, gemeinsamer Berichtsordner → eigene ID, eigener Bericht | ✅ | ✅ | offen |
| Befund 5 | C# · `Failure_before_report_never_shows_old_report`, `Reports_folder_that_is_a_file_is_a_controlled_error`, `Cli_refusal_exit_3_is_error_without_report`, `Validator_rejects_foreign_or_inconsistent_report` (7 Fälle) | Fehler vor Berichtserzeugung, Ordnerfehler, fremdes Schema/ID/Pfade/Exitcode/Zähler → kein Ergebnis angezeigt | ✅ | ✅ | offen |
| Befund 5 / T-016 | cli · `job_id_is_taken_over_and_invalid_id_is_refused`; core · `scan::tests::job_id_is_kept` | übergebene UUID im Bericht; ungültige ID → Exit 3 | ✅ | ✅ | offen |
| Befund 6 / T-026 | core · `empty_scope_is_nothing_scanned_even_with_engine_failure`; cli · `empty_folder_is_nothing_scanned_exit_5`; C# · `Empty_folder_is_nothing_scanned_and_valid` | leerer Ordner → `nothing_scanned`, Exit 5; Engine-Ausfall bleibt Auftragslücke | ✅ | ✅ | offen |
| Befund 7 / T-022 | yarax · `repo_rules_are_marked_test_only`, `mixed_rules_are_production`; cli · `test_only_rules_are_flagged_loudly`, `engines_json_reports_health_content_and_capabilities`; C# · `Engines_report_test_only_rules` | nur Testregeln → `test_only`, Warnung in CLI und UI | ✅ | ✅ | offen |
| Befund 7 / T-030 | clamav · `tests::database_classification`; CI-Job `clamav-signatures` | Test-hdb → `test_only`; offizielle Datenbank per FreshClam → `official_signatures`, Laufzeit-EICAR erkannt | ✅ Klassifikation; offizielle DB im CI-Job: daily 28163, EICAR erkannt, kein Fehlalarm | n/a (Linux-Job) | offen |
| Befund 7 / UI | `scripts/ci/ui_check.ps1` | Übersicht: „Eingeschränkt“, Hinweis „NUR FUNKTIONSTEST-REGELN“; Direktscan: Ergebnistext, Listenlänge und Zähler = CLI-Bericht | n/a | ✅ | offen |
| P02 / T-013 | cli · `real_worker_is_isolated_and_scans` | echter Worker: Probe (Lesen, Schreiben, Anlegen, TCP, Programmstart) vollständig verweigert; EICAR erkannt, Text ohne Fund | ✅ (Landlock) | ✅ (AppContainer + Job) | offen |
| P02 / T-013 | cli · `compromised_worker_cannot_touch_system_files_or_network` | Worker versucht Systemdatei (`hosts`) zu öffnen-zum-Schreiben, im Benutzerordner anzulegen, ins Netz (lokal und 1.1.1.1:443) zu verbinden, ein Programm zu starten → alles verweigert (Lesen der Systemdatei ist im AppContainer erlaubt) | ✅ | ✅ | offen |
| P02 | cli · `unsandboxed_worker_is_refused_on_windows` | Worker ohne AppContainer → verweigert selbst, Engine nicht verfügbar | n/a | ✅ | offen |
| P02 / T-021 | cli · `crash_is_error_gap_and_worker_restarts`, `repeated_crashes_disable_engine_instead_of_looping` | Absturz im Worker → Lücke, Host läuft weiter, Neustart beim nächsten Objekt; wiederholte Abstürze → Abschaltung | ✅ | ✅ | offen |
| P02 / T-021 | cli · `hanging_worker_is_timeout_and_killed_within_budget`, `protocol_violations_are_errors` | Hänger → Zeitlimit < 3 s, Worker beendet; unbekannter Antworttyp / übergroße Länge → Fehler | ✅ | ✅ | offen |
| P02 / T-022 / B-12 | cli · `memory_hungry_worker_is_stopped_by_limit` | Worker fordert 2 GiB bei Grenze 512 MiB → gestoppt, Lücke | ✅ (RLIMIT_AS) | ✅ (Job-Commit) | offen |
| P02 | cli · `missing_worker_and_bad_rules_are_unavailable`; worker · `protocol::tests::roundtrip_and_limits` | fehlender Worker, kaputte Regeln → nicht verfügbar; Rahmengrößen vor dem Allokieren geprüft | ✅ | ✅ | offen |
| P02 / T-014 | service · `ipc::tests::only_listed_commands_and_fields_are_accepted`, `values_are_validated` | unbekannte Befehle/Felder, falsche Werte → abgewiesen | ✅ | ✅ | offen |
| P02 / T-014 | service · `ipc::tests::oversized_and_slow_frames_are_rejected` | > 64 KiB, langsames Senden → abgewiesen | ✅ | n/a (Unix-Testpipe; Windows-Pipe nutzt dieselbe Rahmenlogik mit `CancelIoEx`-Fristen) | offen |
| P02 / T-014 | service · `replayed_and_non_increasing_requests_are_rejected`, `oversized_malformed_and_slow_messages_end_the_connection`, `rate_and_job_limits_bound_overload` (Integration über Unix-Socket) | Wiederholte Nonce, fallende Sequenz, übergroße/kaputte/langsame Nachricht, Überlast → abgewiesen und begrenzt | ✅ | n/a (Unix-Socket; Windows über Systemtest) | offen |
| P02 / T-014 | service · `jobs::other_owner_cannot_see_cancel_or_read`, `identity::tests::session_zero_and_service_accounts_are_rejected` | fremder Benutzer oder andere Anmeldesitzung → nicht sichtbar; Sitzung 0, Dienstkonten → abgewiesen | ✅ | ✅ | offen |
| P02 / T-014 | service · `owner_can_scan_and_read_report_other_user_cannot`, `service_accounts_and_session_zero_are_refused` (Integration) | wie oben, über den Verbindungshandler | ✅ | n/a (Unix-Socket; Windows im Systemtest mit echtem zweiten Benutzer) | offen |
| P02 | service · `jobs::reports_are_never_overwritten`, `limits_bound_queue_and_parallelism`; Integration `cancel_running_job_and_service_restart_keeps_report` | Bericht nie überschrieben, Grenzen für Warteschlange/Parallelität; Abbruch, Bericht nach Neustart | ✅ | ✅ (Unit); Integration n/a → Systemtest | offen |
| P02 | core · `failed_identity_switch_never_reads_with_own_rights`, `classification_in_engine_drives_container_logic`, `classification_failure_or_missing_classifier_is_gap` | gescheiterter Identitätswechsel → kein Lesen, Lücke; Typerkennung im Worker; Ausfall = Lücke | ✅ | ✅ | offen |
| P02 | cli · `restart_with_rejected_rules_is_refused_and_state_updated`, `restart_with_changed_content_version_is_refused`, `restart_without_isolation_receives_no_scan_data`, `isolation_is_reprobed_after_every_restart`, `worker_gets_only_explicit_environment` | Neustart mit abgelehnten Regeln / anderer Inhaltsversion / ohne Abschottung → keine Scandaten; Probe nach jedem Neustart; Umgebung nur ausdrücklich (künstlicher Testwert) | ✅ | ✅ | offen |
| **P02 System** | `scripts/ci/service_e2e.ps1` (Windows-Systemtest, Administrator, Wegwerf-Runner) | Installation (LocalService, 2 Privilegien), Status, Worker isoliert, Scan **Ende-zu-Ende über den Dienst**, Abbruch, Client-Absturz, **zweiter lokaler Benutzer**: fremder Bericht/Auftrag/Abbruch → `not_found`, nicht lesbarer Ordner → `AccessDenied`, `sc stop/delete` → verweigert; Dienstabsturz → Wiederanlauf, Bericht lesbar, Nutzdateien unverändert; C#-Client gegen echten Dienst; Stopp → nicht erreichbar; Deinstallation | n/a | siehe „Letzte belegte Läufe“ | offen |
| UI | `scripts/ci/ui_check.ps1` | ohne Dienst zeigt die Statuszeile „Dienst fehlt“ | n/a | ✅ | offen |
| P02 / AXS-013 | cli · `restricted_token_denies_user_files_and_writes` | eingeschränktes Token (für ClamAV): Datei im Benutzerprofil lesen → verweigert, Anlegen im Benutzer-Temp → verweigert | n/a | siehe CI | offen |
| P02 (Messung) | cli · `appcontainer_path_resolution_is_measured` | Pfadauflösung im AppContainer (Grund für das eingeschränkte Token) und mit eingeschränktem Token (muss gelingen) | n/a | ✅ gemessen | offen |
| T-015 | core · `verdict::tests::*` (6), `scan::tests::unavailable_engine_never_yields_clean_and_is_job_gap`, `no_engine_is_gap`, `missing_path_is_gap` | keine Lücke wird „sauber“ | ✅ | ✅ | offen |
| T-018 | core · `identity::tests::*` (4), `scan::tests::symlink_is_not_followed` | Austausch/Änderung erkannt; Link nicht verfolgt | ✅ | ✅ | offen |
| T-020 (Teil) | core · `scan::tests::access_denied_is_reported` | Datei ohne Leserechte → `AccessDenied` (benötigt Nicht-root) | ✅ (Nicht-root) | n/a (Unix-Rechte) | offen |
| T-021 | clamav · `positive_benign_and_test_only_content`, `without_database_is_unavailable`; cli · `both_engines_detect_eicar_with_real_clamav` | echter ClamAV: Fund, gutartig, leere DB → nicht verfügbar | ✅ (echter ClamAV) | ausgelassen: kein ClamAV | offen |
| T-022 | yarax · `eicar_positive`, `benign_counterexamples`, `timeout_is_reported_as_timeout`, Regelvalidierung (4) | EICAR (Funktionstest), Gegenbeispiele, Zeitlimit | ✅ | ✅ | offen |
| T-023 / T-028 | core · `filetype::tests::*` (5); cli · `filetype_uses_content_not_extension` | Typ nach Inhalt; gekürzte PE ohne Panic | ✅ | ✅ | offen |
| T-026 | core · `positive_benign_and_counts`, `cancel_marks_incomplete`, `size_limit_is_reported_not_clean` | Zählungen, Abbruch, Größenlimit | ✅ | ✅ | offen |
| T-028 | core · `scan::tests::fifo_does_not_block_and_is_gap` | Named Pipe → kein Hängen, Lücke | ✅ | n/a (FIFO) | offen |
| T-010 | `scripts/ci/selftest_supply_chain.sh` (5 Selbsttests) | Testgeheimnis, manipulierte Prüfsumme, EICAR, künstliches Schlüsselmaterial (Inhalt, `.pem`), fehlende Lizenzhinweise → jeweils Ablehnung | ✅ CI (alle 5) | n/a (Linux-Job) | – |
| T-012 | `scripts/check_release_inventory.py --require-notices` | Paket ohne Lizenzhinweise/mit Testhelfer/Schlüssel → Verstoß | ✅ | ✅ CI-Paket | – |

## Noch ohne Test (Auszug)

T-024 (Archivbomben gegen eigene Extraktion – AXSafe entpackt nicht selbst), T-027 (Cache) und alle Abnahmen ab P04. Siehe [`REQUIREMENTS.md`](REQUIREMENTS.md).
