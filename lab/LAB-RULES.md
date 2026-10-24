# Laborregeln (AXS-008, AXS-009, AXS-081)

Diese Regeln sind verbindlich. Sie schützen deinen Alltagsrechner, deine Daten und andere Menschen.

## Auf dem Alltagsrechner (Entwicklungsgerät) ist erlaubt

* Bauen, Unit-Tests, Scans **eigener, gutartiger Dateien**
* EICAR **nur zur Laufzeit** in temporären Ordnern (Tests erledigen das automatisch)
* AMTSO-Funktionsprüfungen im Browser [Q14]

## Auf dem Alltagsrechner ist verboten

* Ausführbare verdächtige Inhalte starten oder „detonieren“
* Reale Malwareproben herunterladen, entpacken oder aufbewahren
* Testsignierung aktivieren, Secure Boot oder Speicherintegrität für AXSafe abschalten
* Eigene Treiber laden (auch keine Testtreiber)
* Bank-, Kunden- oder Arbeitgeberdaten als Testmaterial verwenden

## Labor (noch nicht vorhanden – Blocker B-02)

| Regel | Umsetzung |
| --- | --- |
| Getrennte VMs | Windows 10 Enterprise LTSC 2021 x64 und Windows 11 x64, je mit sauberem Snapshot |
| Keine Verbindung zu Alltagsdaten | keine geteilten Ordner, keine Zwischenablage, keine privaten Konten, kein Cloud-Sync |
| Eigenes Netz | internes/isoliertes virtuelles Netz; Internet nur bewusst und protokolliert |
| Zurücksetzen | nach jedem Probenlauf Snapshot zurücksetzen |
| Isolationstest (T-008) | aus der VM: kein Zugriff auf Host-Freigaben, kein Ping ins Heimnetz, Snapshot-Wiederherstellung funktioniert |
| Reale Proben | nur rechtmäßig beschafft, mit Herkunft, Hash, Lizenz/Bedingungen im Manifest, nur auf getrenntem Host |

Ein Container oder eine Sandbox auf dem Alltagsrechner ist **kein** gleichwertiger Ersatz für ein getrenntes Labor [Q53, Q54].
