# Engine-Vertrag (AXS-021)

Jede Erkennungs-Engine in AXSafe ist ein Adapter hinter dem Rust-Trait
`axsafe_core::engine::Engine`. Dieser Vertrag gilt für alle Adapter – heute
YARA-X (im Prozess und im abgeschotteten Worker) und ClamAV (clamscan je Objekt
und dauerhaft geladener `axsafe-clamav-worker`). Er wird für jeden Adapter mit
derselben Prüfreihe `axsafe_core::conformance` getestet.

## 1. Angaben über sich selbst (`info()`)

| Feld | Pflicht |
| --- | --- |
| `name` | stabil, nicht leer, gleich `Engine::name()` |
| `engine_version` | echte Version der Engine (z. B. `ClamAV 1.5.4`, `1.22.0`) |
| `content_version` | Stand des Erkennungsinhalts (Regel-Hash, ClamAV `daily`-Stand). **Ändert sich bei jedem neuen Regel- oder Signaturstand** – Grundlage für Cache und Fortsetzen (AXS-026/027) |
| `health` | `Ready` nur nach erfolgreichem Laden **und** geprüfter Abschottung; sonst `Unavailable` mit Grund |
| `license` | Lizenz der Engine |
| `content_kind` | `test_only`, wenn nur Testinhalt (z. B. EICAR) geladen ist – darf nie als Schutz dargestellt werden |
| `inspects_contents_of` | nur Containerformate, deren Inhaltsprüfung **durch einen Test mit der echten Engine belegt** ist |
| `isolation` | wo die Engine läuft; `enforced = true` nur mit Nachweis (Probe beim Start) |

## 2. Ergebnisse (`scan()`)

* Die Engine bekommt einen unveränderlichen Inhaltsschnappschuss (Bytes), nie
  einen Pfad. Sie führt nichts aus und schreibt nichts außerhalb ihres
  eigenen Arbeitsordners.
* Sie darf **nie paniken**; Fehler werden `Error`, Zeitüberschreitungen
  `Timeout`.
* `NoDetection` heißt: vollständig geprüft, nichts gefunden – **nie mit
  Lücke**. Was nicht vollständig geprüft wurde, ist eine Lücke mit Zustand
  (`Unsupported`, `Encrypted`, `AccessDenied`, `Timeout`, `Error`,
  `ChangedDuringScan`) und verständlicher Erklärung.
* Ein Fundzustand (`Malicious`, `Suspicious`, `PUA`) hat immer mindestens
  einen Fund; jeder Fund hat Name, Belege, Schweregrad, Konfidenz und – wo
  bekannt – Regel-ID und Regelversion.
* Jedes Ergebnis nennt Engine-Name, Engine- und Inhaltsversion.
* Gleiche Eingabe, gleicher Stand ⇒ gleiches Ergebnis.
* Eine **nicht bereite** Engine meldet nie „ohne Fund“.

## 3. Ausfälle bleiben isoliert

* Absturz, Hänger, Protokollbruch oder Speicherüberschreitung eines Workers
  werden zur Lücke des betroffenen Objekts; der Worker wird ersetzt. Nach
  wiederholten Ausfällen ist die Engine „nicht verfügbar“, nie „sauber“.
* Der Ausfall einer Engine verändert die Ergebnisse der anderen nicht; der
  Bericht zeigt je Engine ihr eigenes Ergebnis.

## 4. Prüfung

| Adapter | Prüfreihe | Test |
| --- | --- | --- |
| YARA-X im Prozess | bereit + nicht bereit | `axsafe-engine-yarax`: `conformance_in_process` |
| YARA-X im Worker | bereit + nicht bereit | `axsafe-worker`: `conformance_sandboxed_worker` |
| ClamAV (clamscan) | bereit + nicht bereit | `axsafe-engine-clamav`: `conformance_clamscan` (echtes ClamAV) |
| ClamAV (dauerhafter Worker) | bereit + nicht bereit | `axsafe-clamav-worker`: `conformance_persistent_worker` (echte libclamav) |
| Prüfreihe selbst | erkennt eine absichtlich fehlerhafte Engine | `conformance::tests::broken_engine_is_caught` |

Ausfalltests (Absturz, Hänger, volle Warteschlange, Speichergrenze,
kaputte Datenbank, Signaturupdate) stehen in den Tests der Worker
(`persistent.rs`, `worker.rs`).

## 5. Neue Engine aufnehmen

1. Adapter implementiert `Engine`; nur belegte Formate in `inspects_contents_of`.
2. Prüfreihe `check_ready` mit einer Testprobe des eigenen Testinhalts und
   `check_unavailable` mit absichtlich fehlender Datenbank/Regel bestehen.
3. Ausfalltests (Absturz, Zeitlimit) und Abschottungsnachweis ergänzen.
4. Fähigkeitsmatrix (`axsafe faehigkeiten`) aktualisieren.
