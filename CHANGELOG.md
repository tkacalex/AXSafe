# Änderungsprotokoll

Alle nennenswerten Änderungen an AXSafe. Format angelehnt an [Keep a Changelog](https://keepachangelog.com/de/1.1.0/); Versionen nach SemVer. Vorversionen (`0.x`) sind **kein Echtzeitschutz**.

## [Unveröffentlicht]

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
