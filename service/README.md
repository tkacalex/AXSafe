# service/ – AXSafe Broker-Dienst (Phase P02)

**Noch kein Code.**

Geplant: kleiner privilegierter Windows-Dienst in Rust mit versionierter Named-Pipe-IPC (restriktive ACL, Clientidentität, Rollen, Nachrichtenlimits, Replay-Schutz), der Scanaufträge typisiert an eingeschränkte Worker-Prozesse ohne Netzzugang vergibt (AXS-013, AXS-014, AXS-017, AXS-020).

Bis dahin startet die Oberfläche die CLI `axsafe.exe` mit normalen Benutzerrechten. Der Dienst wird **kein** beliebiger Dateileser oder Löschdienst.
