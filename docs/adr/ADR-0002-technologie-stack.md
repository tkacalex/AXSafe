# ADR-0002: Technologie-Stack und gepinnte Versionen

* Status: **angenommen** (Default-Stack der Spezifikation, AXS-007)
* Datum: 2026-10-24

## Entscheidung

| Bereich | Technologie | Gepinnt auf | Pin-Ort |
| --- | --- | --- | --- |
| Kern, Engines, CLI, später Dienst | Rust | 1.97.0 | `rust-toolchain.toml` |
| Rust-Abhängigkeiten | crates.io | exakte Versionen (`=x.y.z`) | `Cargo.toml`, `Cargo.lock` |
| YARA-X | Rust-Crate | 1.22.0 | `Cargo.toml` (+ Test gegen `Cargo.lock`) |
| Desktop-Oberfläche | C# / WPF | .NET SDK 10.0.402, `net10.0-windows` | `ui/global.json`, `.csproj` |
| ClamAV | externes Programm | Entwicklung: 1.5.4 (Ubuntu-Paket) | CI-Installationsschritt |
| COM/WDK-Teile | C/C++ | noch nicht begonnen (P07/P08) | – |
| Forschung, Testhilfen | Python 3 (nur stdlib) | 3.13 in Entwicklung | `scripts/` |

## Begründung

* Rust reduziert bestimmte Speicherfehler im eigenen Code. Es macht **nicht** automatisch FFI, native Fremdbibliotheken oder die Architektur sicher.
* .NET 10 führt Windows 10 21H2 Enterprise LTSC in der Unterstützungsliste [Q03]; WPF ist nativ und gut bedienbar.
* Python bleibt im Labor; der Desktopschutz hängt nicht von Python ab.

## Regeln

* Versionsänderungen nur per Pull Request mit Begründung im `CHANGELOG.md`.
* Keine unreviewte Komplettumstellung des Stacks.
* Dependabot schlägt Updates vor; `cargo-deny` prüft Lizenzen, Quellen und bekannte Schwachstellen.
