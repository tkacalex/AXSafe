# Bedrohungsmodell AXSafe (AXS-004, T-004)

Status: **Entwurf – Review offen.** Wird mit jeder neuen Komponente fortgeschrieben.

## Schutzgüter

1. Nutzerdaten auf dem Gerät (Dokumente, Zugangsdaten im Browser, Bankdaten)
2. Integrität und Verfügbarkeit des Betriebssystems (kein Bootloop, keine gelöschten Systemdateien)
3. Integrität von AXSafe selbst (Regeln, Policies, Quarantäne, Updatevertrauen)
4. Vertraulichkeit von Scaninhalten (Skripte, Dokumente) und Berichten
5. Signier- und Updateschlüssel

## Angreiferklassen (getrennt modelliert)

| Klasse | Fähigkeit | Was AXSafe leisten soll | Was AXSafe **nicht** verspricht |
| --- | --- | --- | --- |
| A1 Normale Rechte | Dateien im Benutzerprofil, Prozesse starten | erkennen, blockieren (später), Manipulation von AXSafe verhindern | – |
| A2 Lokaler Administrator | Dienste stoppen, Treiber laden | Manipulation erkennen und melden, Selbstschutz über ELAM/PPL (P11) | vollständigen Schutz gegen Admin |
| A3 Kernelzugriff | beliebiger Kernelcode | Hinweise sammeln, Offlineprüfung (P09) | Selbstprüfung eines kompromittierten Kernels |
| A4 Kompromittierte Updateinfrastruktur | Pakete/Metadaten fälschen, alte Stände anbieten | TUF: Rollen, Ablauf, Antirollback, Rotation (P04) | Schutz bei gleichzeitigem Verlust aller Schlüssel |
| A5 Bösartiger Dateiinhalt | Parser-Exploits, Archivbomben | Isolation, Limits, Fuzzing | fehlerfreie Fremdparser |

## Vertrauensgrenzen

```
Benutzer ──► AXSafe Desktop (Benutzerrechte)
               │  heute: startet axsafe.exe als Kindprozess (gleiche Rechte)
               │  später: versionierte Named Pipe mit ACL, Rollenprüfung (P02)
               ▼
           AXSafe Broker/Dienst (privilegiert, minimal) ──► Quarantäne, Policies
               │
               ▼
           Scanworker (eingeschränkt, ohne Netz)  ◄── untrusted Dateiinhalt
               │  YARA-X im Prozess, ClamAV als Kindprozess über stdin
               ▼
           Minifilter (Kernel, nur Entscheidung)  (P08)
```

## Angriffsflächen (Mindestumfang laut T-004)

| Fläche | Risiko | Maßnahme heute | Offen |
| --- | --- | --- | --- |
| **Dateiparser** (PE-Header, Typerkennung, YARA-X, ClamAV) | Speicherfehler, Endlosschleifen, Archivbomben | eigener Parser in sicherem Rust mit Grenzprüfung + Test auf jede Kürzung; YARA-X-Zeitlimit; ClamAV-Limits + `--alert-exceeds-max`; Panic wird abgefangen | Worker-Prozess mit eingeschränktem Token/Job Object (P02), Fuzzing (P14) |
| **IPC** | Fremde Sitzung, falscher Benutzer, Replay | noch keine IPC; UI startet CLI ohne Shell mit Einzelargumenten | Named Pipes mit ACL, Clientprüfung, Nachrichtenlimits (AXS-014) |
| **Quarantäne** | Dateiverwechslung, Löschen fremder Dateien, Rechteausweitung | Scanner verändert nichts | AES-GCM, Journal, Identitätsprüfung vor Aktion (P05) |
| **Updater** | gefälschte/alte Pakete | noch kein Updater | TUF (P04) |
| **Treiber** | Bootloop, Kernel-Angriffsfläche | kein Treiber | Labor, HLK, Recovery (P08) |
| **Cloud** | Datenabfluss, Mandantenvermischung | keine Cloud, keine Telemetrie | Freigabepflicht, Backendrollen (P12) |
| **UI** | Täuschung des Nutzers durch falschen Status | nie grün ohne belegte Pipeline; Lücken farbunabhängig benannt | Barrierefreiheitstests (P13) |
| **Prüf-/Nutzungs-Rennen (TOCTOU)** | Datei wird zwischen Scan und Aktion getauscht | Identität über Handle vor/nach dem Lesen; Pfad erneut aufgelöst; Links nicht verfolgt; alle Engines prüfen denselben Schnappschuss | Windows-Tests (T-018), Minifilter-Lesesicht (T-055) |
| **Lieferkette** | manipulierte Abhängigkeit, Geheimnis im Repo | gepinnte Versionen, `Cargo.lock`, `cargo-deny`, Gitleaks, SBOM, getrennter Release-Job | Signierung, Reproduzierbarkeit (P15) |
