# ADR-0004: Ehrliches Ergebnismodell

* Status: **angenommen und umgesetzt** (AXS-015) – Code: `crates/axsafe-core/src/verdict.rs`
* Datum: 2026-10-24

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

UI und Berichte können Lücken nie versehentlich grün darstellen. Der CLI-Exitcode trennt Fund (1), Lücke (2) und vollständige Prüfung ohne Fund (0).
