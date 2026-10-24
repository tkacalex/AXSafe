# driver/ – Windows-Minifilter (Phase P08)

**Noch kein Code. Absichtlich.**

Hier entsteht ein minimaler Dateisystem-Minifilter (Windows Filter Manager) mit User-Mode-Scanworker (AXS-053 bis AXS-060). Bevor hier Code landet, müssen erfüllt sein:

* getrenntes Labor (Blocker B-02) – Treiber laufen **nie** auf dem Alltagsrechner
* Microsoft-Beispiele *Scanner* / *AvScan* im Labor gebaut und das Datei-I/O-Zustandsmodell reviewt [Q26, Q27]
* Altitude-Antrag und Signierweg geklärt (Blocker B-06) [Q28, Q29]

Regeln: Keine Parser, Modelle oder Regelinterpreter im Kernel. Kein SSDT-Hooking, kein PatchGuard-Eingriff. Testsignierung nur im Labor. Kein Bootloop gilt als akzeptabler Restfehler.
