# Änderungsprotokoll

Alle nennenswerten Änderungen an AXSafe. Format angelehnt an [Keep a Changelog](https://keepachangelog.com/de/1.1.0/); Versionen nach SemVer. Vorversionen (`0.x`) sind **kein Echtzeitschutz**.

## [Unveröffentlicht]

### Neu – Phase P03, Etappe 8: Robuste Verarbeitung
- **Fuzzing**: sechs libFuzzer-Ziele (Typerkennung und Merkmale, Worker-Rahmen und -Antworten, Richtlinie, Herkunftsangabe, Fortsetzungs- und Cache-Datei) laufen in einem eigenen CI-Job; dieselben Einstiegspunkte laufen als Mutationstest in jedem normalen Testlauf.
- **Nachweis „nie ausführen“**: Ein Testprogramm und Skripte, die beim Start sofort eine Markerdatei anlegen würden, werden mit allen Prüfwegen gescannt – es entsteht kein Marker. Eine Gegenprobe zeigt, dass der Marker beim echten Ausführen entsteht.
- Arbeitsordner von ClamAV, die nach einem Absturz liegen geblieben sind, werden beim nächsten Start entfernt (nur von nachweislich beendeten Prozessen).

### Neu – Phase P03, Etappe 7: Engine-Vertrag
- [`docs/ENGINE-CONTRACT.md`](docs/ENGINE-CONTRACT.md) legt fest, was jede Engine liefern muss (Versionen, Bereitschaft, belegte Containerformate, Ergebnisregeln, isolierte Ausfälle).
- Eine gemeinsame **Prüfreihe** (`axsafe_core::conformance`) prüft alle vier Adapter – YARA-X im Prozess und im abgeschotteten Worker, ClamAV per clamscan und dauerhaft geladen – im bereiten und im nicht bereiten Zustand. Sie erkennt nachweislich eine absichtlich fehlerhafte Engine.

### Neu – Phase P03, Etappe 6: Regelpflege und Regeltests
- Jede YARA-X-Regel braucht jetzt zusätzlich eine **Version**; IDs müssen eindeutig sein. Ein fehlerhafter Regelsatz wird vollständig abgelehnt (keine stille Teilladung). Funde nennen Regel-ID **und** Regelversion.
- **Regeltests** (`rule-tests/<id>.json`): Zu jeder Regel gehören Positiv- und gutartige Gegenbeispiele; die CI prüft sie bei jedem Lauf, ebenso eine Laufzeitgrenze je Regelsatz. Beispiele entstehen zur Laufzeit.
- `axsafe regeln` zeigt ID, Version, Herkunft, Lizenz und das Kennzeichen „NUR FUNKTIONSTEST“.
- Signatur des Regelsatzes: bewusst noch offen, kommt mit dem Updatevertrauen in P04.

### Neu – Phase P03, Etappe 5: Container-Härtetests
- Eigene, begrenzte **Strukturprüfung** für ZIP/OOXML, 7z und CAB (im Dienst im abgeschotteten Worker): beschädigte oder abgeschnittene Archive, verschlüsselte Einträge und übergroße Entpackgrößen (Archivbomben) erscheinen als Prüflücke – auch wenn die Engine selbst nichts meldet. Gemessen: ClamAV meldet eine 150-MiB-Nullbombe allein als „OK“.
- **ISO 9660** ist jetzt mit echtem ClamAV (clamscan und dauerhafter Worker) als inhaltlich geprüft belegt; die dauerhafte Engine hat dafür eigene Formattests.
- Pfadausbruch-Namen in Archiven (`../`, absolute Pfade) erscheinen als Hinweis; AXSafe entpackt nichts auf die Platte (Test prüft, dass nichts außerhalb entsteht).
- **RAR** gilt nur dann als inhaltlich geprüft, wenn ClamAV RAR nachweislich lesen kann: Der dauerhafte Worker prüft das beim Start mit einer harmlosen Probe. Der Windows-Test deckte auf, dass der Worker die unrar-Bibliothek nicht fand und RAR-Inhalt sonst als „ohne Fund“ gemeldet hätte; der Worker setzt jetzt den ClamAV-Ordner als DLL-Suchordner. Ohne RAR-Fähigkeit bleibt RAR eine sichtbare Lücke. VHD/VHDX, VMDK, WIM und UDF bleiben ehrlich „erkannt, Inhalt nicht geprüft“.

### Neu – Phase P03, Etappe 4: Sicherer Ergebnis-Cache im Dienst
- Wiederholte Prüfungen über den Dienst überspringen die Engines für Dateien, deren **Inhalt** (SHA-256) unter **demselben** Engine-, Regel-, Signatur-, Richtlinien- und Programmstand schon vollständig geprüft wurde. Dateien werden trotzdem immer gelesen; Heuristik, Herkunft und Signatur werden neu bestimmt.
- Geänderter Inhalt (auch mit zurückgesetztem Zeitstempel), neue Signaturen, neue Regeln oder eine andere Richtlinie führen immer zu einer neuen Bewertung. Unvollständige Ergebnisse werden nie zwischengespeichert.
- Der Cache liegt im Dienstordner, auf den Benutzer keinen Zugriff haben; Berichte nennen Treffer und markieren übernommene Ergebnisse.
- Fortsetzungsdateien gelten höchstens 7 Tage.

### Neu – Phase P03, Etappe 3: Scanarten, Fortschritt, Abbruch und Fortsetzen
- `axsafe scan --art schnell|voll|wechsel|benutzer`: Schnellprüfung (Downloads, Desktop, Temp, Autostart-Ordner), alle festen Laufwerke, angeschlossene Wechseldatenträger oder eigene Pfade. Der Bericht nennt Scanart, Auslöser und **was die Scanart nicht abdeckt**. `axsafe ziele --art …` zeigt die Ziele vorab.
- **Fortschritt** in CLI, Oberfläche und Dienst (Objekte, Bytes; Prozent, sobald die Vorabzählung fertig ist).
- **Fortsetzen** nach Abbruch oder Absturz: `axsafe scan --fortsetzen <datei>` bzw. „Abgebrochene Prüfung fortsetzen“ in der Oberfläche. Übernommen wird nur, was inhaltlich gleich ist (SHA-256) und unter demselben Engine-, Regel-, Richtlinien- und Programmstand vollständig geprüft wurde; alles andere wird neu geprüft.
- **Kontextmenü** „Mit AXSafe prüfen“ (`scripts/windows/kontextmenue.ps1`, nur für den Benutzer, ohne Adminrechte) und **geplante Prüfungen** (`scripts/windows/zeitplan.ps1`, Aufgabenplanung mit Benutzerrechten; Berichte landen im Berichtsordner der Oberfläche). `--json-ordner` legt Berichte mit eindeutigem Namen ab.
- Oberfläche: Schaltflächen für Schnell-, Voll- und Wechseldatenträgerprüfung statt des bisher deaktivierten Platzhalters.

### Neu – Phase P03, Etappe 2: Statische Merkmale und Heuristik mit Belegen
- Berichte enthalten zusätzlich SHA-1 und MD5 (nur zum Abgleich), die **PE-Struktur** (Sektionen mit Entropie und Rechten, Importe, Overlay, Einsprungpunkt) – im Dienst im abgeschotteten Worker bestimmt –, die **Herkunft** laut Mark of the Web (nur Zone und Rechnername, keine Adressparameter) und den **Authenticode-Status** (Windows, ohne Netzabfrage).
- Drei **Heuristiken** melden „Verdächtig“ nur bei eindeutigen Täuschungsmustern und nennen ihre Belege: Richtungssteuerzeichen im Dateinamen, doppelte Endung (z. B. `.pdf.exe`), Programm mit Dokument-Endung. Hohe Entropie, fehlende Signatur, Packer oder Internet-Herkunft sind **nie** ein Fund, nur ein Hinweis. Gutartige Gegenfälle sind getestet.
- CLI zeigt Belege; mit `-v` auch Signatur, Herkunft und Hinweise. Die Oberfläche zeigt Belege, Signatur und Herkunft in den Details.

### Neu – Phase P03, Etappe 1: Typerkennung und Fähigkeitsmatrix
- Typerkennung nach Inhalt erweitert: Skriptsprachen (PowerShell, Batch, VBScript, JavaScript, HTA, Python, Shell), OLE-Untertypen (MSI, Word, Excel, PowerPoint 97–2003), Datenträgerabbilder (UDF, VHD, VMDK, WIM) und weitere Archive (TAR, BZIP2, XZ).
- `axsafe faehigkeiten` zeigt je Format getrennt, ob es **erkannt** wird und welche bereite Engine seinen **Inhalt** tatsächlich prüft; die Fähigkeitsmatrix wird daraus erzeugt und in der CI auf Gleichstand geprüft.

### Neu – Phase P02 abgeschlossen (Grundsystem)
- **Prozess-Mitigationen** für alle abgeschotteten Worker (AXS-013), beim Start gesetzt und vor dem Fortsetzen geprüft; fehlt eine, startet der Worker nicht.
- **Betriebszustand** (AXS-019): `axsafe zustand` und der Dienststatus melden Scanner, Echtzeitsensor, Richtlinie, Definitionen (Alter der ClamAV-Signaturen), Primärschutz und Dienst getrennt. Keine oder ungültige Antwort = „Unbekannt“, nie grün. Die Oberfläche zeigt diesen Zustand (Tooltip mit allen Bestandteilen).
- **Richtlinie und Ausnahmen** (AXS-017): versionierte Datei `%ProgramData%\AXSafe\Policy\policy.json`, nur von Administratoren änderbar – sonst wird sie nicht angewandt. Ausnahmen nur für genaue Dateien oder eng begrenzte Ordner, mit Grund, Urheber und Ablauf (höchstens 90 Tage). Ausgenommenes steht im Bericht und macht den Auftrag unvollständig. `axsafe richtlinie` zeigt und prüft sie.
- **Nachvollziehbarkeit** (AXS-016): Berichte nennen den ausführenden Prozess und – beim Dienst – den Prozess des Auftraggebers mit PID **und** Startzeit sowie die Zeitzone; das Dienstprotokoll führt beides je Auftrag.
- **Dateiidentität** (AXS-018): 128-Bit-Datei-IDs; versteckte Datenströme (Alternate Data Streams) werden gefunden und einzeln geprüft; lange und Unicode-Pfade getestet.
- **Lokale Daten** (AXS-020): Dienstberichte mit Aufbewahrungsgrenze (1000), Protokollzeilen bereinigt (keine Zeilenumbrüche, Länge begrenzt, Geheimnis-Werte geschwärzt), beschädigte Berichte werden gemeldet statt den Dienst zu stören.

### Neu – B-18: ClamAV-Signaturen bleiben geladen (dauerhafter, abgeschotteter Worker)
- **`axsafe-clamav-worker`**: eigenes Programm, das libclamav aus der separat installierten ClamAV-Installation **einmal** lädt und danach beliebig viele Objekte prüft. Bisher lud `clamscan` die Datenbank für jedes Objekt neu (auf dem Zielrechner ~16,8 s je Datei). Der Worker bekommt nur Bytes über eine anonyme Pipe: keine Pfade, kein clamd, kein TCP-Port.
- **Gleiche Abschottung wie bisher für clamscan:** eingeschränktes Token, Integrität Niedrig, Job Object (1 Prozess, Speichergrenze), eigener Arbeitsordner, minimale Umgebung, ausgehende Firewall-Sperrregel für das Worker-Programm (Einrichtung und Dienstinstallation legen sie an). Unter Linux sperrt Landlock nach dem Laden der Datenbank alles außer dem Arbeitsordner. Jeder Start wird vor der ersten Datenübergabe geprüft: Protokoll, geladener Datenbankstand passend zu den Dateiköpfen, Umgebung, Zugriffsprobe.
- **Robust und ehrlich:** Zeitgrenze je Objekt, Größen- und Speichergrenzen, begrenzte Warteschlange (Lücke „ausgelastet“). Absturz, Hänger und Protokollbruch werden zur Lücke, der Worker wird ersetzt; nach wiederholten Ausfällen ist ClamAV „nicht verfügbar“, nie „sauber“. Nach 10 Minuten Leerlauf wird der Worker beendet und der Speicher freigegeben.
- **Signaturupdates:** Ein neuer Datenbankstand gilt erst als aktiv, wenn ein neuer Worker ihn erfolgreich geladen und die Prüfung bestanden hat. Scheitert das, bleibt der bisherige Stand aktiv, und „SIGNATURUPDATE NICHT GELADEN“ steht sichtbar in der Engine-Angabe. Veraltete Signaturen (älter als 3 Tage) werden als „VERALTET“ ausgewiesen.
- **Dienst:** Alle Aufträge teilen sich eine Engine, die Datenbank wird nicht je Auftrag neu geladen. **CLI:** `--clamav-modus auto|dauerhaft|clamscan` (Standard: dauerhaft, wenn der Worker vorhanden ist).
- **Messung:** `axsafe clamav-messung <ordner>` vergleicht clamscan je Objekt mit der dauerhaften Engine auf genau denselben Dateien: Start, erster Scan, Folgescans, Gesamtdauer, Speicherspitze. Weichen die Ergebnisse je Datei ab, ist die Messung ungültig.
- **Lizenz:** libclamav ist GPL-2.0-only und mit Apache-2.0 nicht vereinbar. Deshalb ist der Worker ein eigenes Programm ohne YARA-X/wasmtime, und `scripts/check_gpl_component.py` prüft in der CI seine Abhängigkeiten. Siehe [`docs/LICENSE-REVIEW-libclamav.md`](docs/LICENSE-REVIEW-libclamav.md). Richtiggestellt: Die GPL erlaubt kommerzielle Nutzung und Verkauf; ausgeschlossen ist nur geschlossene Software.
- Einrichtung: Der Programmpfad für die Firewall-Regel des Workers wird normalisiert. Auf dem Zielrechner stand sonst `…\scripts\windows\..\..\cli\…` in der Regel.

### Neu – Phase P02, Schritt 2: Hintergrunddienst und Named Pipe
- **Dienst `AXSafeService`** (`axsafe-service.exe`): Konto *LocalService* mit eigener Dienst-SID, nur die Privilegien `SeImpersonatePrivilege` und `SeChangeNotifyPrivilege`, Neustart nach Absturz. Programmordner unter *Program Files* (Benutzer nur Lesen), Datenordner `%ProgramData%\AXSafe\Service` ohne Benutzerzugriff. Reproduzierbare Installation und Entfernung (`scripts/windows/install-service.ps1`, `uninstall-service.ps1`, `Dienst-installieren.cmd`).
- **Named Pipe `\\.\pipe\AXSafe.v1`, Protokoll `axsafe.ipc/1`:** DACL nur für SYSTEM, Administratoren und interaktive Benutzer (ohne Recht, eigene Pipe-Instanzen anzulegen), Netzwerkclients abgewiesen. Die Identität kommt **aus dem Windows-Token** (Benutzer-SID, Anmeldesitzung, Sitzungs-ID), nie aus der Nachricht; Sitzung 0 und Dienstkonten werden abgewiesen. Nachrichten höchstens 64 KiB, Schema mit unbekannten Feldern verboten, Zeitgrenzen gegen langsame Clients, Sequenz und Nonce gegen Wiederholung, Ratenbegrenzung. Erlaubt sind nur: Status, Scan starten, eigenen Scan abbrechen, eigene Aufträge und Berichte.
- **Dateizugriff mit den Rechten des Auftraggebers:** Der Dienst liest Dateien nur unter Impersonation des Clients und kehrt danach zu seinen Rechten zurück; scheitert der Wechsel, wird nicht gelesen (Lücke „Zugriff verweigert“).
- **Begrenzte Aufträge:** höchstens 2 gleichzeitig, 8 in der Warteschlange, 4 je Benutzer; Berichte werden nie überschrieben und nur dem Eigentümer (Benutzer + Anmeldesitzung) gezeigt.
- **Oberfläche:** neuer Zustand „Hintergrunddienst“ (fehlt / startet / bereit / gestört / nicht erreichbar) – „bereit“ erst, wenn der Dienst es bestätigt. Prüfungen laufen über den Dienst, wenn er bereit ist, sonst lokal; der Prüfweg steht im Ergebnis.
- `axsafe dienst status|scan|auftrag|bericht|abbrechen` in der CLI.

### Neu – Abschottung erweitert
- **Typerkennung läuft im Worker** (nicht mehr im Prozess mit Dateizugriff). Fällt sie aus, wird das als Lücke gemeldet.
- **ClamAV läuft unter Windows mit eingeschränktem Token** (keine Privilegien, Integritätsstufe Niedrig, Einschränkungs-SIDs RESTRICTED/Jeder/Benutzer/Anmelde-SID) im Job Object; das Token wird vor dem Start geprüft. Dateien, die nur der Benutzer lesen darf, bleiben unerreichbar; schreiben darf clamscan nur in seinem eigenen Arbeitsordner. Netzwerk sperrt eine ausgehende Firewall-Regel für `clamscan.exe`, die die Einrichtung anlegt. **Ein AppContainer ist für ClamAV 1.5 nicht möglich** – gemessen: Windows verweigert dort `GetFinalPathNameByHandleW` mit DOS-Namen, ClamAV braucht das für seinen Zertifikatsordner. Ohne Abschottung meldet die Engine „nicht verfügbar“; Betrieb ohne Abschottung gibt es nur mit dem ausdrücklichen Schalter `--clamav-ohne-abschottung` und sichtbarem Hinweis.
- Worker: Bereitschaft (Regeln, Inhaltsversion, Abschottungsprobe) wird **nach jedem Neustart** neu geprüft; der Worker bekommt nur eine minimale, ausdrückliche Umgebung.

### Neu – ClamAV-Einrichtung für Windows
- `scripts/windows/setup-clamav.ps1` (Start per `ClamAV-einrichten.cmd`, eine UAC-Bestätigung): offizielles MSI von Cisco Talos, Prüfung von SHA-256 und Talos-PGP-Signatur vor der Ausführung, geschützte Daten- und Protokollordner, FreshClam mit offiziellen Quellen, geplanter Signaturupdate-Auftrag alle 4 Stunden ohne Überlappung mit Fehler- und Erfolgsprotokoll, Nachweisbericht a)–g). Kein clamd, kein TCP-Port. Defender bleibt aktiv.

### Behoben
- **ClamAV im Dienst startete nicht** (STATUS_DLL_INIT_FAILED): Das eingeschränkte Token durfte die Fensterstation des Dienstes nicht nutzen. Aufgedeckt erst durch den neuen gemeinsamen Test (Dienst + echte ClamAV-Engine auf einer Maschine); vorher liefen beide nur getrennt. Im Dienstkontext enthält das Token jetzt die Dienstkonto-SID.
- Berichte nennen ihre Herkunft (`executed_by`), der Dienst protokolliert je Auftrag Engines und Lückengründe, die Oberfläche speichert Dienstberichte nachvollziehbar unter `%LOCALAPPDATA%\AXSafe\reports`.
- ClamAV-Einrichtung (Windows): Prüfung von Datenbank, Zertifikatsordner und Arbeitsordner jetzt **mit dem echten eingeschränkten Token** (`axsafe clamav-abschottung`) statt anhand von ACL-Einträgen; eigener Arbeitsordner je Engine-Instanz (parallele Instanzen störten sich: „Can't write to temporary directory“); Netzsperre wirksam nachgewiesen; ausgeschaltetes Firewall-Profil ist ein Fehler.
- Windows PowerShell 5.1: Hilfsfunktionen hießen wie eingebaute Aliasse (`sc` = Set-Content, `r` = Invoke-History) und wurden dadurch nie aufgerufen. Die CI prüft das jetzt für alle Skripte.
- CLI überschrieb unter Windows den festen Standardpfad der ClamAV-Datenbank mit „keiner“.

### Neu – Phase P02, Schritt 1: isolierter Scanworker
- **YARA-X läuft jetzt in einem abgeschotteten Worker-Prozess** (`axsafe-worker`). Er bekommt nur Regeltexte und Dateibytes, nie Pfade.
  - Windows: **AppContainer ohne Fähigkeiten** (kein Netzwerk, kein Zugriff auf Benutzerdateien) im **Job Object** (1 Prozess, Speichergrenze, Kill-on-close). Ohne AppContainer verweigert der Worker die Arbeit.
  - Linux (Entwicklung): Selbstbeschränkung mit **Landlock** (kein Dateizugriff, kein Programmstart, kein TCP).
  - Die Abschottung wird bei jedem Start **nachgewiesen**: Lese-, Schreib-, Anlege-, Verbindungs- und Startversuche müssen scheitern. Auf Windows Server (CI) und Linux belegt; Windows 10 LTSC offen.
  - Absturz, Hänger, Speicherüberschreitung und Protokollbruch bleiben im Worker, werden als Lücke gemeldet; der Worker wird beim nächsten Objekt neu gestartet, nach wiederholten Ausfällen abgeschaltet.
- `axsafe engines` und die Oberfläche zeigen je Engine die **Isolation** (Art, nachgewiesen, Einzelheiten).
- Oberfläche zeigt die Version aus dem Programm statt fest „0.1“ (vom UI-Screenshot aufgedeckt); UI-Prüfung vergleicht sie mit der CLI.

### Behoben (nur durch echte Windows-Läufe sichtbar)
- Jeder ClamAV-Aufruf galt unter Windows als „hinterließ Nachkommen“: `conhost.exe` zählte im Job mit. Kindprozesse starten jetzt ohne Konsole (`DETACHED_PROCESS`).
- Paralleler erster Start mehrerer Worker scheiterte mit „Datei nicht gefunden“, solange das AppContainer-Profil angelegt wurde: prozessübergreifend serialisiert.
- Probeordner paralleler Engines konnten kollidieren.

## [0.2.0] – 2026-10-24 · Korrektur unabhängiger Befunde (Release-Entwurf, nicht veröffentlicht)

Grundlage: acht unabhängig gefundene Befunde zu Stand `491956e`. Reproduktion vorher/nachher in `docs/evidence/`.

### Sicherheit / Datenintegrität
- **Befund 1 – kein Datenverlust mehr beim JSON-Bericht:** Das Berichtsziel wird vor dem Scan exklusiv neu angelegt (`O_EXCL` bzw. `CREATE_NEW`); bestehende Dateien, Links, Junctions und Ordner werden nie überschrieben (Exit 3 mit verständlicher Meldung). Das reservierte Ziel wird über seine Datei-ID (Volume + Index) vom Scan ausgeschlossen – auch über Hardlinks, Symlinks und Reparsepunkte – und im Bericht als Ausschluss genannt. Geschrieben wird über das gehaltene Handle, ohne erneute Pfadauflösung.
- **Befund 4 – ein gemeinsames Ablaufdatum für den ganzen Engine-Aufruf:** neues Crate `axsafe-proc`. Keine unbegrenzten Joins mehr; Nachkommen, die Pipes offen halten, werden beendet und als Lücke gemeldet. Windows: Start angehalten, Job Object (Kill-on-close, kein Breakaway, Speicher- und Prozessgrenze), dann Fortsetzen. Unix: eigene Prozessgruppe, `RLIMIT_AS`. Ausgabe je Kanal begrenzt. Zeitüberschreitung ist immer „unvollständig“.

### Geändert (Berichtsschema v2, Exitcodes)
- **Befund 2 – Fund und Prüfabdeckung getrennt:** Schema `axsafe.scan-report/2` mit `detection` und `gaps[]` je Objekt, Status `detection_incomplete` („Fund vorhanden; zusätzliche Prüflücke“), Auftrags-`outcome`, `complete`, `job_gaps` und eindeutig definierten, überlappenden Zählern. CLI, Client und WPF synchron. Exitcode 4 = Fund und unvollständig.
- **Befund 3 – Containerabdeckung ehrlich:** Engines melden, welche Containerformate sie inhaltlich prüfen. Für ClamAV nur die 7 mit echtem ClamAV belegten Formate (ZIP, OOXML, OLE/CFB, 7z, GZIP, CAB, PDF). Sonst Lücke `content_not_inspected`; `Encrypted` nur bei sicherer Feststellung durch die Engine. YARA-X gilt als „nur Rohbytes“.
- **Befund 5 – Berichte eindeutig zugeordnet:** neues, plattformneutrales `AXSafe.Client`: zufällige Auftrags-ID (`--job-id`), eigenes Berichtsziel mit ID im Namen, Prüfung von Schema, ID, Pfaden, Exitcode und Zählern; alte oder fremde Berichte werden nie angezeigt; Datei-, Rechte- und Lesefehler werden kontrolliert gemeldet.
- **Befund 6 – leere Aufträge:** `nothing_scanned` („Keine prüfbaren Objekte“, Exit 5), unabhängig von Engine- und Auftragsfehlern.
- **Befund 7 – Testregeln unübersehbar:** Regelbestand (`test_only`, `production`, `official_signatures`, `custom_signatures`) getrennt von Bereitschaft und Containerfähigkeit; CLI warnt, die Oberfläche zeigt „NUR FUNKTIONSTEST-REGELN GELADEN“. Eigener CI-Job für offizielle ClamAV-Signaturen über FreshClam.

### Tests und Release-Nachweise (Befund 8)
- Tests mit externer Vorbedingung sind `#[ignore = "Grund"]` und scheitern laut, statt still zu bestehen; Linux-CI führt sie verpflichtend aus (ClamAV, Nicht-root) und bricht ab, wenn trotzdem ein Test ausgelassen wurde. Zusammenfassung zählt bestanden/fehlgeschlagen/ausgelassen getrennt (`scripts/ci/test_summary.py`).
- 16 xUnit-Tests für den Client gegen die echte CLI (Linux und Windows).
- UI-Prüfung per UI Automation statt nur Screenshots (`scripts/ci/ui_check.ps1`).
- Windows Server (CI) wird nirgends mehr als LTSC-Nachweis geführt.
- Release nur manuell und nur für einen Commit mit erfolgreicher CI; SBOM mit Commit gestempelt, Inventar, Lizenzhinweise und SHA256SUMS über alle Assets.
- `THIRD-PARTY-NOTICES.txt` aus dem echten Abhängigkeitsgraphen der Windows-CLI (167 Pakete) plus Lizenzdateien der eingebetteten .NET-Laufzeit im Paket; fehlende Crate-Lizenzdateien versionsgenau aus Upstream (`licenses/upstream/SOURCES.json`). `ascii_tree` ohne upstream Copyright-Vermerk → B-14.
- Inventar-Selbsttests für künstliches Schlüsselmaterial (Inhalt und `.pem`) und fehlende Lizenzhinweise; Testhelfer dürfen nicht ins Paket.
- `bincode` (RUSTSEC-2025-0141) bleibt eine **dokumentierte Ausnahme**, nicht behoben (B-13).

### Behoben (vor den Befunden)
- Wackeltest `hanging_engine_is_timeout`: Linux meldete beim sofortigen Start des frisch geschriebenen Testskripts gelegentlich „Text file busy“. Der Adapter meldete korrekt `Error`; der Test wartet jetzt, bis das Skript startbar ist (8 Wiederholungen ohne Fehler).
- Paket: `axsafe.exe` (CLI) überschrieb unter Windows `AXSafe.exe` (Oberfläche), weil Windows Groß-/Kleinschreibung nicht unterscheidet. CLI liegt jetzt in `cli\`; die Oberfläche schließt sich bei der CLI-Suche selbst aus. Paketbau prüft, dass die Oberfläche enthalten ist.
- Oberfläche stürzte beim Start ab: einer `Background`-Eigenschaft wurde eine Farbe statt eines Pinsels zugewiesen (vom Windows-CI-Screenshot-Schritt aufgedeckt).
- Absturzprotokoll nach `%LOCALAPPDATA%\AXSafe\logs` mit verständlicher Meldung statt stillem Beenden.
- Inventarprüfung las den Wert von `--inventory` als zweiten Paketpfad (erster Windows-CI-Lauf schlug deshalb fehl); jetzt argparse, UTF-8-Ausgabe unter Windows.
- Gitleaks-Fehlalarm auf die PEM-Suchmuster im Inventarskript: Muster werden zur Laufzeit gebildet, alter Fund begründet in `.gitleaksignore`.

### Neu (vor den Befunden)
- README zeigt echte Screenshots der Oberfläche, automatisch auf dem Windows-Runner aufgenommen.
- Oberfläche wählt ClamAV automatisch ab, wenn es nicht installiert ist, und erklärt den kleineren Prüfumfang.
- Selbsttest 3 in der CI: Inventarprüfung muss EICAR erkennen und saubere Pakete durchlassen (T-012).
- ADR-0006 (Entwurf): isolierter Scanworker mit Job Object/AppContainer und Named-Pipe-IPC `axsafe.ipc/1` als Plan für Phase P02.

## [0.1.0] – 2026-10-24 · erste Vorversion

### Neu
- **Kern (`axsafe-core`)**: ehrliches Ergebnismodell mit zehn Zuständen; Aggregation, bei der Lücken nie zu „sauber“ werden; Dateiidentität über das geöffnete Handle (Windows: `GetFileInformationByHandle`) mit Änderungserkennung; Typerkennung nach Inhalt (PE32/PE64/DLL/.NET, ZIP, OOXML, OLE, PDF, RTF, LNK, 7z, RAR, GZIP, CAB, ISO, VHDX); Scan-Orchestrierung mit Größen-, Tiefen- und Zeitlimits, Abbruch und JSON-Bericht.
- **YARA-X-Adapter**: Regeln mit Pflichtmetadaten und Mindestversion, Zeitbudget, abgefangene Panics.
- **ClamAV-Adapter**: `clamscan` als getrennter Prozess über stdin, ohne TCP; Absturz → Fehler, Hänger → Zeitlimit; verschlüsselte Archive → `Encrypted`.
- **CLI `axsafe`**: `scan`, `engines [--json]`, `filetype`; stabile Exitcodes 0/1/2/3.
- **Oberfläche (WPF, .NET 10)**: dunkelblaues Design, Übersicht mit echtem Engine-Status, Virenscan mit Abbruch, Berichte; nicht vorhandene Funktionen sind deaktiviert und erklärt; `--scan <Pfad>`.
- **Projektgrundlagen (P00/P01)**: Plattformmatrix (gemessen), Bedrohungsmatrix, Bedrohungsmodell, ADRs, Rechtsprüfakte, Budgetmatrix, Blockerregister, Laborregeln, Testdatenmanifest, Requirements-Matrix mit Generator.
- **CI**: Linux und Windows, Clippy/Format, Tests mit echtem ClamAV, cargo-deny, Gitleaks, Selbsttests der Lieferkettenprüfung, SBOM, Paketinventar, Screenshots.

### Behoben (während der Entwicklung durch Tests gefunden)
- Eine hängende Engine mit Kindprozessen blockierte AXSafe bis zu 30 s über das Zeitbudget hinaus. Jetzt endet die Prüfung nach dem Zeitbudget (Test `hanging_engine_is_timeout`).

### Sicherheit
- cargo-deny-Befund RUSTSEC-2025-0141 (`bincode` nicht gepflegt, transitiv über yara-x): begründete, befristete Ausnahme in `deny.toml`, Blocker B-13.

### Bekannte Grenzen
- Kein Echtzeitschutz, keine Quarantäne, keine Updates, kein Dienst. Siehe [`docs/BLOCKERS.md`](docs/BLOCKERS.md).
