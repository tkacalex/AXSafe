# Arbeitsanweisungen für Entwicklungsagenten

Verbindliche Quelle ist die Spezifikation in `docs/spec/` (Masterprompt, Plan, JSON). Kurzfassung der Regeln:

1. Kein Fake: keine Mockwerte, Scheinbuttons, erfundenen APIs oder stillen V2-Verschiebungen im Produkt.
2. Ergebnisse ehrlich: Lücken (Unsupported, Encrypted, AccessDenied, Timeout, Error, ChangedDuringScan) nie zu „sauber“ machen.
3. Keine Schadsoftware, keine EICAR-Datei, keine Schlüssel im Repo. Testdaten nur zur Laufzeit erzeugen.
4. Vor jedem Commit: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, bei UI-Änderungen `dotnet build ui/AXSafe.Desktop -c Release`.
5. Stand pflegen: `docs/status/requirements-status.json` ändern, dann `python3 scripts/gen_docs.py`. Blocker in `docs/BLOCKERS.md`, Entscheidungen in `docs/DECISIONS.md`, Änderungen in `CHANGELOG.md`.
6. README aktuell halten (Funktionstabelle, Testzahl-Badge, Screenshots). Kundenfreundlich, Deutsch, mit kurzer englischer Zusammenfassung.
7. Keine Erfolgsmeldung ohne ausgeführten Nachweis; Belege nach `docs/evidence/`.
