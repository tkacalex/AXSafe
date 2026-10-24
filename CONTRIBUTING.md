# Mitmachen bei AXSafe

Schön, dass du helfen möchtest! AXSafe folgt einem verbindlichen Plan mit 16 Phasen und 100 Anforderungen ([`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md)). Jede Änderung braucht einen **echten Nachweis**.

> **Lizenzhinweis:** Die Projektlizenz ist noch nicht festgelegt ([ADR-0003](docs/adr/ADR-0003-lizenzen.md)). Bis dahin können Beiträge Dritter nur nach Rücksprache übernommen werden. Issues, Fehlalarm-Meldungen und Ideen sind jederzeit willkommen.

## Entwicklungsumgebung

```bash
# Rust (Version wird über rust-toolchain.toml automatisch gewählt)
cargo build --workspace
cargo test --workspace          # ClamAV-Tests laufen, wenn clamscan installiert ist
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# Oberfläche (Windows, .NET SDK 10)
dotnet build ui/AXSafe.Desktop -c Release

# Doku-Generator nach Statusänderungen
python3 scripts/gen_docs.py
```

## Regeln

1. **Kein Fake.** Keine Mockwerte, Scheinbuttons oder erfundenen APIs im Produkt. Fehlendes wird sichtbar deaktiviert und erklärt.
2. **Ehrliche Ergebnisse.** Fehler, Zeitüberschreitung, fehlende Rechte und verschlüsselte Inhalte dürfen nie „sauber“ ergeben ([ADR-0004](docs/adr/ADR-0004-ergebnismodell.md)).
3. **Tests ab dem ersten Schritt.** Jeder Schutzpfad braucht einen positiven Fall, gutartige Gegenfälle und einen Ausfallfall.
4. **Sicher testen.** Keine Malware, keine EICAR-Datei im Repo; Tests erzeugen Testdaten zur Laufzeit ([Laborregeln](lab/LAB-RULES.md)).
5. **Blocker statt Abkürzung.** Was nicht geht, kommt mit Ursache und nächstem Schritt ins [Blockerregister](docs/BLOCKERS.md).
6. **Status pflegen.** `docs/status/requirements-status.json` anpassen und `scripts/gen_docs.py` laufen lassen; die CI prüft das.
