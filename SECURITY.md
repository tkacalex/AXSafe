# Sicherheitsrichtlinie

## Schwachstellen in AXSafe melden

Bitte **nicht** über öffentliche Issues. Nutze stattdessen
[GitHub Security Advisories](https://github.com/tkacalex/AXSafe/security/advisories/new) (privat).

Bitte angeben: betroffene Version (`axsafe --version`), Windows-Version, Schritte zum Nachstellen, erwartetes und tatsächliches Verhalten. **Keine echten Malwareproben anhängen.**

Wir bestätigen den Eingang so bald wie möglich. Da AXSafe ein Einzelprojekt in der Vorversion ist, gibt es **noch keine zugesicherten Reaktionszeiten** (AXS-098 ist geplant).

## Unterstützte Versionen

| Version | Status |
| --- | --- |
| 0.1.x (Vorversion) | Fehlerbehebungen im Hauptzweig, keine Sicherheitszusagen |

## Wichtig für Nutzer

AXSafe 0.x ist **kein Echtzeitschutz** und **kein Ersatz** für einen aktiven Virenschutz. Lass Microsoft Defender oder dein bisheriges Schutzprogramm aktiv. Kein Antivirus erkennt jede Schadsoftware.

## Grundsätze im Projekt

* Keine Schadsoftware, keine EICAR-Datei und keine Schlüssel im Repository ([ADR-0005](docs/adr/ADR-0005-testdaten.md)).
* Scans lesen nur; Proben werden nie auf Endgeräten ausgeführt ([Laborregeln](lab/LAB-RULES.md)).
* Keine Telemetrie, keine Cloud, keine Uploads in der Vorversion.
