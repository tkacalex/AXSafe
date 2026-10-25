# ADR-0003: Lizenzen von Code, Werkzeugen, Regeln, Daten, Modellen und Marken

* Status: **Entwurf – Entscheidung der Produktverantwortung offen** (AXS-003, AXS-005)
* Datum: 2026-10-24

Fremder Code, Regeln, Daten, Modelle und Marken werden **getrennt** erfasst.

## 1. Projektlizenz von AXSafe

**Noch nicht festgelegt.** Ohne Lizenzdatei gilt „alle Rechte vorbehalten“; der Code ist öffentlich lesbar, darf aber nicht weiterverwendet werden. Optionen:

| Option | Folge |
| --- | --- |
| Apache-2.0 | permissiv, Patentklausel, verträglich mit allen aktuellen Rust-Abhängigkeiten |
| MIT | permissiv, sehr verbreitet |
| GPL-2.0-only / GPL-2.0-or-later / GPL-3.0 | Copyleft; kommerzielle Nutzung und Verkauf sind erlaubt, Weitergabe aber nur mit Quelltext unter derselben Lizenz (keine geschlossene Software). GPL-3.0 und Apache-2.0 sind vereinbar, GPL-2.0-only und Apache-2.0 nicht |
| keine (Status quo) | maximale Kontrolle, aber keine Beiträge Dritter rechtssicher möglich |

Die Wahl einer offenen Lizenz ist für veröffentlichte Stände **nicht rückholbar**. Sie wird daher bewusst vom Inhaber getroffen ([`DECISIONS.md`](../DECISIONS.md), D-01).

## 2. Werkzeuge und Engines

| Komponente | Lizenz | Nutzung heute | Pflicht vor Weitergabe |
| --- | --- | --- | --- |
| YARA-X 1.22.0 | BSD-3-Clause | statisch eingebunden | Lizenztext + Copyright mitliefern |
| ClamAV 1.5.4 / libclamav | GPL-2.0-only (OpenSSL-Ausnahme) | **separat installiert, nicht mitgeliefert**; libclamav wird im eigenen Programm `axsafe-clamav-worker` geladen (B-18), clamscan bleibt als Vergleichsweg | Der Worker darf nur GPL-2.0-verträgliche Abhängigkeiten enthalten (CI: `scripts/check_gpl_component.py`); vor Weitergabe des Workers Lizenz der Worker-Crates festlegen (D-01). Siehe [`LICENSE-REVIEW-libclamav.md`](../LICENSE-REVIEW-libclamav.md). *Ein separater Prozess ist keine pauschale Freistellung.* |
| Rust-Abhängigkeiten (209 Pakete) | MIT/Apache-2.0/BSD/Zlib/Unicode-3.0 u. a. | statisch eingebunden | Automatisch geprüft mit `cargo-deny` (`deny.toml`), SBOM je Release |
| .NET 10 / WPF | MIT | Laufzeit | Hinweise mitliefern |

## 3. Regeln und Signaturen

| Bestand | Lizenz | Hinweis |
| --- | --- | --- |
| `rules/test/eicar.yar` (eigene Regel) | CC0-1.0 | Pflichtfeld `license` in jeder Regel |
| ClamAV-Signaturen (main/daily/bytecode) | eigene Nutzungsbedingungen von Cisco Talos | Vor Mitlieferung/Spiegelung prüfen; FreshClam-Lastregeln beachten (AXS-030) |
| Fremde YARA-Regelsammlungen | je Sammlung verschieden | Nur nach Einzelprüfung übernehmen |

## 4. Daten und Modelle

Noch keine. EMBER2024 und SOREL-20M haben eigene Bedingungen und sind **nur Forschung** (P12).

## 5. Name und Marke

„AXSafe“: Marken- und Domainverfügbarkeit **nicht geprüft** (Blocker B-07). Kein öffentlicher Vertrieb vor Prüfung.
