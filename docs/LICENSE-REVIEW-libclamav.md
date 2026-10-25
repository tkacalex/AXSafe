# Lizenzprüfung: libclamav im AXSafe-ClamAV-Worker (B-18)

* Stand: 25.10.2026
* Status: technische Lizenzprüfung abgeschlossen; **Projektlizenz bleibt offen (D-01)**
* Keine Rechtsberatung. Vor einer öffentlichen Weitergabe sollte eine fachkundige Person die Prüfung bestätigen (siehe [`LEGAL-REVIEW.md`](LEGAL-REVIEW.md)).

## 1. Ausgangslage

B-18 verlangt eine dauerhaft geladene ClamAV-Engine. Alex hat dafür Option 2 gewählt: libclamav dauerhaft in einem abgeschotteten Worker-Prozess laden. Vorher war die Lizenzlage zu klären, ausdrücklich auch mögliche Konflikte zwischen GPL-2.0-only und Apache-2.0.

## 2. Fakten

| Komponente | Lizenz | Quelle |
| --- | --- | --- |
| libclamav (ClamAV 1.5.4) | GPL-2.0 (only) mit OpenSSL-Ausnahme | `COPYING.txt` im ClamAV-Repository; Debian `/usr/share/doc/libclamav12/copyright` („Files: * License: GPL-2“) |
| Hinweis des Herstellers | „Libclamav is licensed under the GNU GPL v2 license“, und: „All software using libclamav must be GPL compliant.“ | docs.clamav.net, *libclamav* |
| Signaturen (main/daily/bytecode) | eigene Nutzungsbedingungen von Cisco Talos | ADR-0003 §3; werden nicht mitgeliefert |
| libclamunrar (nur Windows-Paket) | UnRAR-Lizenz, wird von libclamav als eigenes Modul nachgeladen | Teil der separat installierten ClamAV-Installation, nicht von AXSafe |
| YARA-X / wasmtime (im CLI, im Dienst und im YARA-Worker) | BSD-3-Clause bzw. Apache-2.0 WITH LLVM-exception | `cargo tree` |
| Rust-Abhängigkeiten des ClamAV-Workers | ausschließlich MIT, „MIT OR Apache-2.0“, Unlicense/MIT, Unicode-3.0 | `scripts/check_gpl_component.py` |

## 3. Bewertung

1. **Apache-2.0 und GPL-2.0-only sind nicht vereinbar.** Die FSF stuft Apache-2.0 nur als vereinbar mit GPLv3 ein, nicht mit GPLv2. Code, der nur unter Apache-2.0 steht, darf daher nicht in ein Programm, das libclamav lädt. Deshalb bekommt libclamav ein **eigenes Programm** (`axsafe-clamav-worker`). Es enthält kein YARA-X und kein wasmtime.
2. **Der Worker wird mit libclamav zu einem Gesamtwerk.** Das gilt nach FSF-Auffassung auch beim dynamischen Laden zur Laufzeit. Alles, was in den Worker hineingebaut wird, muss deshalb mit GPL-2.0-only vereinbar sein. Heute erfüllt jede fremde Abhängigkeit das; bei „MIT OR Apache-2.0“ wird MIT gewählt. Die CI prüft das bei jedem Lauf (`check_gpl_component.py`, Job `linux`).
3. **Die Hostprogramme bleiben getrennt.** CLI, Dienst und Oberfläche starten den Worker nur als eigenen Prozess. Sie tauschen über eine Pipe einfache Datenrahmen aus: Bytes hin, Ergebnis zurück. Nach der FSF-FAQ gelten getrennte Programme, die über Pipes kommunizieren, in der Regel als getrennte Werke, solange die Kommunikation nicht so eng ist, dass sie faktisch ein Programm bilden. Das Skript prüft außerdem, dass `axsafe-cli`, `axsafe-service` und `axsafe-engine-clamav` den Worker **nicht** als Bibliothek einbinden.
4. **libclamav wird nicht mitgeliefert.** Sie stammt aus der offiziellen ClamAV-Installation, die `setup-clamav.ps1` mit Prüfsumme und Signaturprüfung einrichtet. Unter Linux kommt sie aus dem Distributionspaket.
5. **Eigene Crates im Worker** (`axsafe-clamav-worker`, `axsafe-workerproto`, `axsafe-core`) haben noch **keine Lizenzangabe**, weil D-01 offen ist. Wer ein Worker-Programm weitergibt, muss es unter GPL-2.0-only oder einer damit vereinbaren Lizenz (z. B. MIT) samt Quelltext bereitstellen. Wird für das Gesamtprojekt Apache-2.0 gewählt, bräuchten mindestens diese drei Crates eine zusätzliche, GPL-2.0-verträgliche Lizenz (etwa „MIT OR Apache-2.0“). **Diese Entscheidung trifft Alex (D-01); sie wurde hier bewusst nicht vorweggenommen.**

## 4. Richtigstellung: GPL und kommerzielle Nutzung

Eine frühere Aussage von mir war falsch: „keine kommerzielle Version“ bzw. „kein Einbinden in geschlossene oder kommerzielle Software“. Richtig ist:

* Die GPL **erlaubt kommerzielle Nutzung und den Verkauf**, auch eines Programms, das libclamav nutzt.
* Bedingung bei Weitergabe: Das Gesamtwerk steht unter der GPL. Empfänger erhalten den Quelltext und dieselben Rechte (Weitergabe, Änderung), und es gibt keine zusätzlichen Einschränkungen.
* Ausgeschlossen ist nur **geschlossene (proprietäre) Software**, die libclamav einbindet. Genau das meint der ClamAV-Hinweis „not allowed to link commercial, closed-source software“.

## 5. Ergebnis

* Kein konkreter Lizenzkonflikt beim gewählten Aufbau: eigener GPL-verträglicher Worker, Hosts als getrennte Programme, libclamav nicht mitgeliefert.
* Offene Voraussetzung **vor jeder Weitergabe** des Worker-Programms: D-01 (Lizenz der Worker-Crates) und die rechtliche Bestätigung (LEGAL-REVIEW).
* Die ClamAV-Signaturen werden weiterhin nur über FreshClam bezogen, nicht gespiegelt.

## Quellen

* ClamAV-Dokumentation, *libclamav*: https://docs.clamav.net/manual/Development/libclamav.html
* ClamAV `COPYING.txt` (GPLv2 mit OpenSSL-Ausnahme): https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt
* FSF, *Various Licenses and Comments about Them* (Apache-2.0 und GPLv2): https://www.gnu.org/licenses/license-list.html#apache2
* FSF, *GPL FAQ* („aggregate“ und Kommunikation über Pipes; dynamisches Linken): https://www.gnu.org/licenses/gpl-faq.html#MereAggregation
