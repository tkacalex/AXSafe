# ADR-0004: Ehrliches Ergebnismodell

* Status: **angenommen und umgesetzt** (AXS-015) – Code: `crates/axsafe-core/src/verdict.rs`
* Datum: 2026-10-24 · **Nachtrag 2026-10-24: Berichtsschema v2** (Befunde 2, 3, 5, 6)

## Entscheidung

Zehn getrennte Zustände: `Malicious`, `Suspicious`, `PUA`, `NoDetection`, `Unsupported`, `Encrypted`, `AccessDenied`, `Timeout`, `Error`, `ChangedDuringScan`.

Regeln (durch Tests abgesichert):

1. Nur `NoDetection` bedeutet „im angegebenen Umfang nichts erkannt“.
2. Beim Zusammenfassen mehrerer Engines hat `NoDetection` den **niedrigsten** Rang. Eine einzige Lücke oder ein einziger Fund kann nie durch ein „nichts gefunden“ einer anderen Engine überdeckt werden (`no_incomplete_state_becomes_clean`).
3. Eine leere Ergebnisliste ist `Error`, nicht „sauber“ (`empty_is_error_not_clean`).
4. `ChangedDuringScan` verwirft jede Teilbewertung eines Objekts: neu prüfen.
5. Für einen ganzen Auftrag gilt: Funde vor Lücken vor „nichts erkannt“ (`overall_verdict`).
6. Schweregrad, Konfidenz und Aktion sind getrennte Felder. Konfidenz ist **kein** kalibrierter Wahrscheinlichkeitswert.
7. Die Vorversion führt nur `Action::ReportOnly` aus.

## Folgen

UI und Berichte können Lücken nie versehentlich grün darstellen. Der CLI-Exitcode trennt Fund (1), Lücke (2) und vollständige Prüfung ohne Fund (0); ab Schema v2 zusätzlich Fund mit Lücke (4) und leeren Auftrag (5).

## Nachtrag: Berichtsschema `axsafe.scan-report/2`

Ein unabhängiger Befund zeigte, dass ein einziger Zustand je Objekt einen Fund und eine gleichzeitige Prüflücke nicht gemeinsam darstellen kann (Fund + ClamAV-Fehler ergab nur „Fund“). Deshalb trennt v2 **Fund** und **Prüfabdeckung**:

* Je Objekt: `detection` (höchster Fund oder `NoDetection`) **und** `gaps[]` (Zustand, Grund, Quelle, Detail) **und** daraus `status`:
  `detection` · `detection_incomplete` · `no_detection` · `incomplete`.
* Je Auftrag: `outcome` (zusätzlich `nothing_scanned`), `complete`, `job_gaps` (z. B. nicht verfügbare Engine, Abbruch), `job_id`, `scope` mit Ausschlüssen.
* Zähler mit dokumentierter Überlappung: `with_detection + incomplete − detection_and_incomplete + no_detection_complete = objects_total`.
* `ChangedDuringScan` ist jetzt eine Lücke; ein bereits erkannter Fund bleibt sichtbar (Regel 4 gilt für „sauber“: eine Änderung macht nie „sauber“).
* Containerinhalt gilt nur als geprüft, wenn eine bereite Engine das Format nachweislich inspiziert (`content_not_inspected` sonst).

Exitcodes: 0 ohne Fund vollständig · 1 Fund vollständig · 2 unvollständig ohne Fund · 3 Bedienfehler (u. a. Berichtsziel existiert) · 4 Fund und unvollständig · 5 keine prüfbaren Objekte.

CLI (`report.rs`), Client (`ui/AXSafe.Client/Models.cs`, `ReportValidator.cs`) und WPF zeigen dieselben Zustände; der Client lehnt Berichte mit anderem Schema, anderer Auftrags-ID, anderen Pfaden, unpassendem Exitcode oder widersprüchlichen Zählern ab.
