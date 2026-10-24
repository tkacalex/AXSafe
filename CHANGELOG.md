# Änderungsprotokoll

Alle nennenswerten Änderungen an AXSafe. Format angelehnt an [Keep a Changelog](https://keepachangelog.com/de/1.1.0/); Versionen nach SemVer. Vorversionen (`0.x`) sind **kein Echtzeitschutz**.

## [Unveröffentlicht]

### Behoben
- Paket: `axsafe.exe` (CLI) überschrieb unter Windows `AXSafe.exe` (Oberfläche), weil Windows Groß-/Kleinschreibung nicht unterscheidet. CLI liegt jetzt in `cli\`; die Oberfläche schließt sich bei der CLI-Suche selbst aus. Paketbau prüft, dass die Oberfläche enthalten ist.
- Oberfläche stürzte beim Start ab: einer `Background`-Eigenschaft wurde eine Farbe statt eines Pinsels zugewiesen (vom Windows-CI-Screenshot-Schritt aufgedeckt).
- Absturzprotokoll nach `%LOCALAPPDATA%\AXSafe\logs` mit verständlicher Meldung statt stillem Beenden.
- Inventarprüfung las den Wert von `--inventory` als zweiten Paketpfad (erster Windows-CI-Lauf schlug deshalb fehl); jetzt argparse, UTF-8-Ausgabe unter Windows.
- Gitleaks-Fehlalarm auf die PEM-Suchmuster im Inventarskript: Muster werden zur Laufzeit gebildet, alter Fund begründet in `.gitleaksignore`.

### Neu
- README zeigt echte Screenshots der Oberfläche, automatisch auf dem Windows-Runner aufgenommen.
- Oberfläche wählt ClamAV automatisch ab, wenn es nicht installiert ist, und erklärt den kleineren Prüfumfang.
- Selbsttest 3 in der CI: Inventarprüfung muss EICAR erkennen und saubere Pakete durchlassen (T-012).
- ADR-0006 (Entwurf): isolierter Scanworker mit Job Object/AppContainer und Named-Pipe-IPC `axsafe.ipc/1` als Plan für Phase P02.

## [0.1.0] – 2026-10-24 · erste Vorversion

### Neu
- **Kern (`axsafe-core`)**: ehrliches Ergebnismodell mit zehn Zuständen; Aggregation, bei der Lücken nie zu „sauber“ werden; Dateiidentität über das geöffnete Handle (Windows: `GetFileInformationByHandle`) mit Änderungserkennung; Typerkennung nach Inhalt (PE32/PE64/DLL/.NET, ZIP, OOXML, OLE, PDF, RTF, LNK, 7z, RAR, GZIP, CAB, ISO, VHDX); Scan-Orchestrierung mit Größen-, Tiefen- und Zeitlimits, Abbruch und JSON-Bericht.
- **YARA-X-Adapter**: Regeln mit Pflichtmetadaten und Mindestversion, Zeitbudget, abgefangene Panics.
- **ClamAV-Adapter**: `clamscan` als getrennter Prozess über stdin, ohne TCP; Absturz → Fehler, Hänger → Zeitlimit; verschlüsselte Archive → `Encrypted`.
- **CLI `axsafe`**: `scan`, `engines [--json]`, `filetype`; stabile Exitcodes 0/1/2/3.
- **Oberfläche (WPF, .NET 10)**: dunkelblaues Design, Übersicht mit echtem Engine-Status, Virenscan mit Abbruch, Berichte; nicht vorhandene Funktionen sind deaktiviert und erklärt; `--scan <Pfad>`.
- **Projektgrundlagen (P00/P01)**: Plattformmatrix (gemessen), Bedrohungsmatrix, Bedrohungsmodell, ADRs, Rechtsprüfakte, Budgetmatrix, Blockerregister, Laborregeln, Testdatenmanifest, Requirements-Matrix mit Generator.
- **CI**: Linux und Windows, Clippy/Format, Tests mit echtem ClamAV, cargo-deny, Gitleaks, Selbsttests der Lieferkettenprüfung, SBOM, Paketinventar, Screenshots.

### Behoben (während der Entwicklung durch Tests gefunden)
- Eine hängende Engine mit Kindprozessen blockierte AXSafe bis zu 30 s über das Zeitbudget hinaus. Jetzt endet die Prüfung nach dem Zeitbudget (Test `hanging_engine_is_timeout`).

### Sicherheit
- cargo-deny-Befund RUSTSEC-2025-0141 (`bincode` nicht gepflegt, transitiv über yara-x): begründete, befristete Ausnahme in `deny.toml`, Blocker B-13.

### Bekannte Grenzen
- Kein Echtzeitschutz, keine Quarantäne, keine Updates, kein Dienst. Siehe [`docs/BLOCKERS.md`](docs/BLOCKERS.md).
