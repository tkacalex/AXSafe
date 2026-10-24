<p align="center">
  <img src="docs/images/banner.svg" alt="AXSafe – ehrlicher, mehrschichtiger Windows-Schutz" width="100%">
</p>

<p align="center">
  <a href="https://github.com/tkacalex/AXSafe/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/tkacalex/AXSafe/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Status" src="https://img.shields.io/badge/Status-Vorversion%200.1-FBBF24">
  <img alt="Plattform" src="https://img.shields.io/badge/Windows%2010%20LTSC%20%2F%2011-x64-3B82F6">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-1.97-22D3EE">
  <img alt=".NET" src="https://img.shields.io/badge/.NET-10%20WPF-818CF8">
  <img alt="Tests" src="https://img.shields.io/badge/Tests-45%20gr%C3%BCn-34D399">
</p>

<p align="center">
  <b>Ein Windows-Virenschutz, der dir nie etwas vormacht.</b><br>
  Jeder grüne Haken ist belegt. Jede Lücke wird benannt. Jeder Fortschritt ist öffentlich nachvollziehbar.
</p>

---

> [!WARNING]
> **AXSafe ist eine Vorversion und noch kein Echtzeitschutz.** Es prüft Dateien, wenn *du* einen Scan startest – mehr nicht.
> Lass **Microsoft Defender** (oder deinen bisherigen Schutz) unbedingt aktiv. Kein Antivirus erkennt jede Schadsoftware.

## Inhalt

- [Warum AXSafe?](#warum-axsafe)
- [Was AXSafe heute kann – und was nicht](#was-axsafe-heute-kann--und-was-nicht)
- [So sieht es aus](#so-sieht-es-aus)
- [Schnellstart](#schnellstart)
- [Ergebnisse richtig lesen](#ergebnisse-richtig-lesen)
- [Architektur](#architektur)
- [Fahrplan und Fortschritt](#fahrplan-und-fortschritt)
- [Dokumentation](#dokumentation)
- [Mitmachen](#mitmachen) · [Sicherheit](#sicherheit) · [English summary](#english-summary)

## Warum AXSafe?

Viele Sicherheitsprogramme zeigen große grüne Schilde, egal was im Hintergrund wirklich passiert. AXSafe geht den umgekehrten Weg:

| Grundsatz | Was das konkret heißt |
| --- | --- |
| 🟢 **Grün nur mit Beleg** | Die Oberfläche zeigt nie „Geschützt“, solange kein Echtzeitschutz existiert. Heute steht dort ehrlich *Eingeschränkt*. |
| 🔍 **Lücken sind sichtbar** | Verschlüsselt, zu groß, kein Zugriff, Zeitlimit, Engine-Fehler – all das ist **nie** „sauber“, sondern wird einzeln gemeldet. |
| 🧩 **Mehrere Engines, ein Vertrag** | Eigene Regeln mit [YARA-X](https://github.com/VirusTotal/yara-x), Signaturen mit [ClamAV](https://www.clamav.net/) – austauschbar, einzeln messbar. |
| 🔐 **Sicher gebaut** | Rust-Kern, Typerkennung nach Inhalt, Dateiidentität über das Handle, kein Ausführen, kein Löschen, keine Cloud, keine Telemetrie. |
| 📋 **Öffentlicher Plan** | 16 Phasen, **100 Anforderungen, 100 Abnahmen**. Der Stand jeder einzelnen steht in [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md). |

## Was AXSafe heute kann – und was nicht

| ✅ Heute vorhanden (getestet) | ⛔ Noch nicht vorhanden (geplant) |
| --- | --- |
| Dateien und Ordner auf Anforderung prüfen (CLI + Oberfläche) | Echtzeitschutz beim Öffnen/Ausführen (Phase P08) |
| Eigene YARA-X-Regeln mit Pflichtmetadaten und Zeitlimit | Quarantäne und Wiederherstellung (P05) |
| ClamAV als getrennter Prozess, ohne Netzwerkschnittstelle | Skript- und Speicherschutz über AMSI (P07) |
| Typerkennung nach Inhalt (EXE/DLL/.NET, Office, PDF, Archive, LNK, ISO …) | Verhaltens- und Ransomware-Schutz (P06, P09) |
| Ehrliche Ergebnisse mit 10 Zuständen und JSON-Bericht | Sichere automatische Updates (P04) |
| Erkennt verschlüsselte Archive als *nicht vollständig geprüft* | Web-, Phishing- und Netzwerkschutz (P10) |
| Deutsche Oberfläche im dunklen Design, kein Konto nötig | Selbstschutz und Windows-Sicherheitscenter (P11) |

Die vollständige Liste je Dateiformat steht in der [Fähigkeitsmatrix](docs/CAPABILITY-MATRIX.md).

## So sieht es aus

**Kommandozeile – ein echter Lauf** (keine Montage; EICAR ist eine ungefährliche Testdatei):

<p align="center"><img src="docs/images/cli-demo.png" alt="Echte Ausgabe von axsafe scan: EICAR-Testdatei von YARA-X und ClamAV erkannt, verschlüsseltes ZIP als Lücke gemeldet, Link nicht verfolgt" width="900"></p>

Was du hier siehst: Die Testdatei wird von **beiden** Engines erkannt. Das passwortgeschützte ZIP wird nicht still als „sauber“ gezählt, sondern als **verschlüsselt** gemeldet. Die Verknüpfung wird bewusst **nicht** verfolgt. Und AXSafe sagt klar: *keine Aktion – Vorversion meldet nur.*

**Oberfläche (WPF, .NET 10):**

<!-- UI-SCREENSHOTS:START -->
<p align="center"><i>Die Screenshots der Oberfläche werden automatisch auf einem Windows-Runner der CI erzeugt und hier ergänzt.</i></p>
<!-- UI-SCREENSHOTS:END -->

## Schnellstart

### Variante A – fertiges Windows-Paket (Vorversion)

1. Öffne die [neueste erfolgreiche CI-Ausführung](https://github.com/tkacalex/AXSafe/actions/workflows/ci.yml?query=branch%3Amain+is%3Asuccess) und lade das Artefakt **`axsafe-windows-x64-preview`** herunter (GitHub-Anmeldung nötig).
2. Entpacken, `AXSafe.exe` starten. Die .NET-Laufzeit ist enthalten. Die Kommandozeile liegt in `cli\axsafe.exe`.
3. Optional: [ClamAV für Windows](https://www.clamav.net/downloads) installieren und `freshclam` ausführen – AXSafe nutzt es dann automatisch zusätzlich.

> Die Pakete sind noch **nicht signiert**. Windows SmartScreen kann deshalb warnen.

### Variante B – aus dem Quellcode

```bash
git clone https://github.com/tkacalex/AXSafe.git
cd AXSafe
cargo build --release                       # Rust-Version wird automatisch gewählt
./target/release/axsafe scan C:\Users\du\Downloads
dotnet build ui/AXSafe.Desktop -c Release   # Oberfläche (Windows, .NET SDK 10)
```

### Die wichtigsten Befehle

```text
axsafe scan <Pfad>... [--json bericht.json] [--no-clamav] [--verbose]
axsafe engines [--json]          Zustand und Versionen der Engines
axsafe filetype <Datei>...       Dateityp nach Inhalt (ohne Engine)
AXSafe.exe --scan <Pfad>         Oberfläche öffnen und sofort prüfen
```

Exitcodes für Skripte: `0` vollständig ohne Fund · `1` Fund · `2` unvollständig · `3` Bedienfehler.

## Ergebnisse richtig lesen

| Ergebnis | Bedeutung |
| --- | --- |
| **Schädlich** / **Verdächtig** / **PUA** | Fund mit Belegen (Regel, Engine, Offset). Getrennt von Schweregrad und Konfidenz. |
| **Ohne Fund** | Im angegebenen Umfang, mit den genannten Engines und Regeln nichts erkannt. **Kein Beweis für Harmlosigkeit.** |
| **Verschlüsselt** | Inhalt nicht einsehbar, z. B. Passwort-ZIP. Nicht geprüft. |
| **Nicht geprüft** | Format, Größe oder Objektart (Link, Gerät) nicht unterstützt. |
| **Kein Zugriff** | Fehlende Rechte oder Sperre. Nicht geprüft. |
| **Zeitlimit** / **Fehler** | Engine zu langsam, abgestürzt oder nicht verfügbar. Nicht geprüft. |
| **Geändert** | Datei hat sich während der Prüfung verändert – Ergebnis verworfen, neu prüfen. |

Warum so streng? Siehe [ADR-0004: Ehrliches Ergebnismodell](docs/adr/ADR-0004-ergebnismodell.md).

## Architektur

<p align="center"><img src="docs/images/architecture.png" alt="Architektur: Desktop und CLI rufen den Rust-Kern, der YARA-X und ClamAV nutzt; gestrichelt die geplanten Teile Dienst, Worker, Quarantäne, Updates, Minifilter und AMSI" width="900"></p>

Durchgezogen = vorhanden, gestrichelt = geplant. Details: [Bedrohungsmodell](docs/THREAT-MODEL.md) · [ADR-0001 Engine-Strategie](docs/adr/ADR-0001-engine-strategie.md) · [ADR-0002 Stack](docs/adr/ADR-0002-technologie-stack.md)

```
crates/axsafe-core           Ergebnismodell, Dateiidentität, Typerkennung, Scan, Bericht
crates/axsafe-engine-yarax   YARA-X-Adapter (eigene Regeln in rules/)
crates/axsafe-engine-clamav  ClamAV-Adapter (clamscan, stdin, ohne TCP)
crates/axsafe-cli            Kommandozeile axsafe
ui/AXSafe.Desktop            WPF-Oberfläche (.NET 10)
service/ driver/ backend/ research/   geplante Komponenten (bewusst noch ohne Code)
docs/                        Plan, Matrizen, ADRs, Blocker, Quellen
```

## Fahrplan und Fortschritt

<p align="center"><img src="docs/images/progress.svg" alt="Fortschritt der 100 Anforderungen je Phase" width="900"></p>

<!-- STATUS:START (automatisch erzeugt von scripts/gen_docs.py) -->
| Status | Anzahl |
| --- | ---: |
| ✅ erfüllt | 0 |
| 🟢 teilweise belegt | 9 |
| 🔵 begonnen | 14 |
| 📝 Entwurf | 5 |
| ⛔ blockiert | 1 |
| ⚪ geplant | 71 |
<!-- STATUS:END -->

**Ehrlich gezählt:** „erfüllt“ heißt, die Abnahme ist vollständig mit echten Belegen bestanden. Das ist bisher bei **keiner** der 100 Anforderungen der Fall – auch wenn viele Teile schon funktionieren und getestet sind. Was fehlt und warum, steht im [Blockerregister](docs/BLOCKERS.md).

| Phase | Inhalt | Stand |
| --- | --- | --- |
| P00–P01 | Ziele, Plattform, Labor, Build, CI | 🔵 in Arbeit |
| P02–P03 | Dienst, IPC, Erkennungskern | 🔵 Kern und Adapter begonnen |
| P04–P05 | Updates, Quarantäne | ⚪ geplant |
| P06–P10 | Sensorik, AMSI, Echtzeit, Ransomware, Web | ⚪ geplant |
| P11–P15 | Selbstschutz, Cloud, UI, Nachweise, Release | 🔵 UI begonnen, Rest geplant |

## Dokumentation

| Thema | Dokument |
| --- | --- |
| Produktauftrag und V1-Definition | [docs/PRODUKTAUFTRAG.md](docs/PRODUKTAUFTRAG.md) |
| Alle 100 Anforderungen mit Status | [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) |
| Zielplattform (gemessen) | [docs/PLATFORM.md](docs/PLATFORM.md) |
| Bedrohungsmatrix (33 Klassen) | [docs/THREAT-COVERAGE.md](docs/THREAT-COVERAGE.md) |
| Bedrohungsmodell | [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) |
| Fähigkeitsmatrix | [docs/CAPABILITY-MATRIX.md](docs/CAPABILITY-MATRIX.md) |
| Testmatrix und Belege | [docs/TEST-MATRIX.md](docs/TEST-MATRIX.md) |
| Blocker und offene Entscheidungen | [docs/BLOCKERS.md](docs/BLOCKERS.md) · [docs/DECISIONS.md](docs/DECISIONS.md) |
| Entscheidungsprotokolle (ADR) | [docs/adr/](docs/adr/) |
| Recht, Lizenzen, Budget | [docs/LEGAL-REVIEW.md](docs/LEGAL-REVIEW.md) · [ADR-0003](docs/adr/ADR-0003-lizenzen.md) · [docs/BUDGET.md](docs/BUDGET.md) |
| Laborregeln | [lab/LAB-RULES.md](lab/LAB-RULES.md) |
| Quellen (60 geprüfte Primärquellen) | [docs/SOURCES.md](docs/SOURCES.md) |
| Ursprüngliche Spezifikation | [docs/spec/](docs/spec/) |

## Mitmachen

Ideen, Fehlerberichte und **Fehlalarm-Meldungen** sind sehr willkommen – nutze die [Issue-Vorlagen](https://github.com/tkacalex/AXSafe/issues/new/choose). Wie entwickelt wird, steht in [CONTRIBUTING.md](CONTRIBUTING.md).

⭐ **Wenn dir der Ansatz „ehrlich statt grün“ gefällt, gib dem Projekt einen Stern** – das hilft, AXSafe sichtbar zu machen.

## Sicherheit

Schwachstellen bitte **privat** melden: [SECURITY.md](SECURITY.md). Das Repository enthält **keine Schadsoftware und keine EICAR-Datei**; Tests erzeugen ungefährliche Testdaten nur zur Laufzeit ([ADR-0005](docs/adr/ADR-0005-testdaten.md)).

## Lizenz

Die Projektlizenz ist **noch nicht festgelegt** ([ADR-0003](docs/adr/ADR-0003-lizenzen.md)). Bis dahin gilt: Code lesen und lernen ja, Weiterverwendung nur nach Rücksprache. Drittkomponenten behalten ihre Lizenzen (YARA-X: BSD-3-Clause, ClamAV: GPL-2.0 – wird nicht mitgeliefert).

---

## English summary

**AXSafe** is an open-development, multi-layer endpoint protection project for **Windows 10 Enterprise LTSC 2021 / Windows 11 (x64)**, built with a Rust core and a German WPF (.NET 10) desktop UI.

Its core idea is **honesty**: no green shield without evidence, every gap (encrypted, unsupported, access denied, timeout, engine error, changed during scan) is reported explicitly and never counted as "clean". The current **preview 0.1** is an *on-demand scanner* with YARA-X and ClamAV adapters, content-based file type detection, handle-based file identity and machine-readable JSON reports. **It is not real-time protection – keep Microsoft Defender enabled.** The full plan (16 phases, 100 requirements with acceptance tests) and its live status are in [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md).
