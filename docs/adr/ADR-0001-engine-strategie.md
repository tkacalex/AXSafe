# ADR-0001: Eigener Kern mit austauschbaren Engineadaptern

* Status: **angenommen** (Vorgabe aus Spezifikation 1.0, AXS-003)
* Datum: 2026-10-24

## Kontext

Ein vollständiger Endpoint-Schutz braucht Erkennungsinhalte, Parser, Sensorik, Durchsetzung, Updates und Betrieb. Optionen laut Konzept Abschnitt 6: alles selbst entwickeln, Open Source kombinieren, kommerzielles SDK lizenzieren, OEM-Produkt anpassen.

## Entscheidung

AXSafe entwickelt einen **eigenen Kern** (Ergebnismodell, Dateiidentität, Orchestrierung, Policies, Quarantäne, Updates, Sensorik, UI) und bindet Erkennungs-Engines über einen **Adaptervertrag** (`axsafe_core::engine::Engine`) an.

* Start mit **YARA-X** (eigene, nachvollziehbare Regeln) und **ClamAV** (Signaturen, Archivbehandlung).
* Jede Engine erhält denselben, bereits gehashten Inhaltsschnappschuss.
* Ein kommerzieller SDK-Adapter ist eine bewertete Option, wird aber **nur mit dokumentierter technischer Eignung und Vertrag** aktiviert. Es werden keine kostenpflichtigen Dienste ohne Auftrag beschafft.
* Die öffentliche **VirusTotal API ist kein zulässiger Ersatz** für eine Engine [Q23, Q24].

## Folgen

* + Engines sind austauschbar und einzeln testbar; Ausfälle bleiben sichtbar (`Unavailable` → `Error`, nie „sauber“).
* + Schutzwirkung jeder Engine kann getrennt gemessen werden (AXS-091).
* − ClamAV und YARA-X liefern **keinen** Windows-Echtzeitschutz. Dieser bleibt eigene Arbeit (P08).
* − Erkennungsqualität hängt an Regel- und Signaturbeständen, die gepflegt werden müssen (P04).
