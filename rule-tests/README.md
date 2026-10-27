# Regeltests (AXS-022)

Zu **jeder** Regel unter `rules/` gehört hier genau eine Datei `<id>.json` mit
mindestens einem Positivbeispiel und mindestens einem gutartigen Gegenbeispiel.
Der Test `rule_harness` (Crate `axsafe-engine-yarax`) prüft in jedem CI-Lauf:

* jede Regel hat eine Testdatei, jede Testdatei gehört zu einer Regel;
* Regel-ID und Regelversion stimmen überein (neue Regelversion ⇒ Tests prüfen);
* Positivbeispiele lösen genau diese Regel aus, Gegenbeispiele nicht;
* jede Regel bleibt auf 8 MiB Zufallsdaten und 8 MiB Wiederholungsdaten unter
  der Laufzeitgrenze (kein Zeitlimit-Abbruch, unter 2 s).

Beispiele werden zur Laufzeit erzeugt. Schadsoftware und die EICAR-Datei
liegen nie im Repository; EICAR entsteht über `"generator": "eicar"`.

Felder eines Beispiels (`sample`), in dieser Reihenfolge zusammengesetzt:
`prefix_text`, `prefix_hex`, `generator` (`eicar`), `text`, `hex`,
`suffix_text`/`suffix_hex` (wiederholt `repeat_suffix`-mal, höchstens 1 MiB).
