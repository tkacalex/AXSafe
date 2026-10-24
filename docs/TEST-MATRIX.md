# Testmatrix

Jeder Test nennt Ausgangszustand, Eingabe, Erwartung, tatsächliches Ergebnis, Version und Umgebung. **Keine Erfolgsmeldung ohne ausgeführten Nachweis.**

## Letzter belegter Lauf

| Feld | Wert |
| --- | --- |
| Datum | 2026-10-24 |
| Umgebung | Linux x86_64 (Ubuntu 24.04, Entwicklungscontainer) – **nicht** das Zielsystem |
| Versionen | Rust 1.97.0 · YARA-X 1.22.0 · ClamAV 1.5.4 · AXSafe 0.1.0 |
| Ergebnis | **45 / 45 bestanden**, Clippy ohne Warnungen, `cargo deny`: alles ok |
| Beleg | [`evidence/2026-10-24-linux-testlauf.txt`](evidence/2026-10-24-linux-testlauf.txt) |
| Windows | CI-Lauf [40101883430](https://github.com/tkacalex/AXSafe/actions/runs/40101883430) auf `windows-latest` (Windows Server, x64): **39 / 39 bestanden** (Unix-spezifische Tests entfallen dort; ClamAV dort nicht installiert → echte ClamAV-Tests übersprungen). **Windows 10 LTSC: offen (B-02, B-03).** |

## Zuordnung zu Abnahmen

| Abnahme | Test (Crate · Name) | Ausgang → Eingabe → Erwartung | Linux | Windows LTSC |
| --- | --- | --- | --- | --- |
| T-015 | core · `verdict::no_incomplete_state_becomes_clean` | jede Lücke + „nichts erkannt“ → Lücke bleibt | ✅ | offen |
| T-015 | core · `verdict::empty_is_error_not_clean` | keine Teilbewertung → `Error` | ✅ | offen |
| T-015/T-019 | core · `scan::unavailable_engine_never_yields_clean` | Engine ausgefallen → `Error`, Auftrag unvollständig | ✅ | offen |
| T-015 | cli · `clean_scan_exit_zero_and_broken_rules_exit_two` | defekter Regelsatz → Exit 2, „NICHT VERFÜGBAR“ | ✅ | offen |
| T-015 | cli · `missing_clamav_makes_scan_incomplete_not_clean` | clamscan fehlt → Exit 2 | ✅ | offen |
| T-018 | core · `identity::swapped_file_with_same_name_is_detected` | Datei unter gleichem Namen getauscht → andere Identität | ✅ | offen |
| T-018 | core · `identity::appended_file_is_changed` | Datei verlängert → geändert | ✅ | offen |
| T-018 | core · `scan::symlink_is_not_followed` | Symlink → `Unsupported`, Ziel nicht gelesen | ✅ | offen (Junction/Reparsepunkt) |
| T-021 | clamav · `real_clamav_positive_and_benign` | echter ClamAV, Test-hdb → EICAR `Malicious`, Text `NoDetection` | ✅ | offen |
| T-021 | clamav · `real_clamav_without_database_is_unavailable` | leere DB → `Unavailable` | ✅ | offen |
| T-021 | clamav · `engine_crash_is_error_not_clean` | Engine stürzt ab (SIGSEGV) → `Error` | ✅ | n/a (Unix-Testdoppel) |
| T-021 | clamav · `hanging_engine_is_timeout` | Engine hängt 30 s, Budget 0,5 s → `Timeout` in < 10 s | ✅ | n/a |
| T-021 | clamav · `status_zero_without_ok_line_is_error` | Status 0 ohne „OK“ → `Error` | ✅ | n/a |
| T-021 | cli · `both_engines_detect_eicar_when_clamav_present` | Ordner mit EICAR + Text → beide Engines melden Fund | ✅ | offen |
| T-022 | yarax · `eicar_positive`, `eicar_with_trailing_whitespace_positive` | EICAR → Fund mit Offset-Beleg | ✅ | offen |
| T-022 | yarax · `benign_counterexamples` | zitierter String, große Datei, Text → kein Fund | ✅ | offen |
| T-022 | yarax · `timeout_is_reported_as_timeout` | teure Regel, 1 s → `Timeout` | ✅ | offen |
| T-022 | yarax · `rule_without_required_meta_is_rejected`, `too_new_min_engine_is_rejected`, `syntax_error_and_empty_dir_are_unavailable` | ungültige Regeln → ganzer Satz abgelehnt | ✅ | offen |
| T-022 | cli · `yara_only_detects_eicar_and_ignores_names` | `eicar.com` mit harmlosem Inhalt → kein Fund | ✅ | offen |
| T-023 | core · `filetype::renaming_does_not_change_type`, cli · `filetype_uses_content_not_extension` | `rechnung.txt` mit PDF-Inhalt → `pdf` | ✅ | offen |
| T-023/T-028 | core · `filetype::truncated_or_hostile_pe_is_malformed_not_panic` | jede Kürzung, Offset-Überlauf → kein Panic | ✅ | offen |
| T-026 | core · `scan::positive_benign_and_counts`, `cancel_marks_incomplete`, `size_limit_is_reported_not_clean` | Zählungen = Manifest; Abbruch/Limit → unvollständig | ✅ | offen |
| T-028 | core · `scan::fifo_does_not_block_and_is_unsupported` | Named Pipe → kein Hängen, `Unsupported` | ✅ | n/a |
| T-020 (Teil) | core · `scan::access_denied_is_reported_when_enforced` | Datei ohne Leserechte → `AccessDenied` | ⚠️ übersprungen als root, läuft in CI als Nicht-root | offen |
| T-010 | CI · `scripts/ci/selftest_supply_chain.sh` | Testgeheimnis → Gitleaks schlägt an; manipulierte Prüfsumme → Build bricht ab | ✅ lokal (Gitleaks 8.28.0) | – |
| T-010 | CI · Gitleaks über gesamten Verlauf | erster CI-Lauf fand einen **Fehlalarm** (PEM-Suchmuster im Prüfskript) → behoben und begründet in `.gitleaksignore` | ✅ | – |
| T-012 | `scripts/check_release_inventory.py` + Selbsttest 3 | Paket mit EICAR oder privatem Schlüssel → Verstoß; sauberes Paket → ok; Testregeln nur mit `--allow-test-rules` | ✅ | CI-Paket |

## Noch ohne Test (Auszug)

T-013 (kompromittierter Worker), T-014 (IPC), T-016 (Korrelation), T-024 (Archivbomben, Pfadausbruch), T-027 (Cache) und alle Abnahmen ab P04. Siehe [`REQUIREMENTS.md`](REQUIREMENTS.md).
