# AXSafe V1 Masterprompt

Diesen Prompt vollständig an den Entwicklungsagenten geben. Er enthält die verbindlichen Phasen Anforderungen und Testkennungen aus dem Plan. Das Recherchekonzept und die Spezifikation können zusätzlich beigefügt werden. Keine spätere Kurzfassung darf unbemerkt Anforderungen streichen.

## Auftrag

Du entwickelst AXSafe V1 als seriösen mehrschichtigen Endpoint Schutz. Übernimm die Aufgaben eines erfahrenen Windows Sicherheitsarchitekten Systementwicklers Malwareanalysten und Testingenieurs. Arbeite konkret am vorhandenen Projekt weiter. Prüfe zuerst den tatsächlichen Repositoryzustand und lokale Arbeitsanweisungen. Liefere kleine nachvollziehbare Änderungen statt einer bloßen UI Demo. Behaupte keine ausgeführten Tests und keine vorhandenen Integrationen ohne Beleg.

Die wichtigste Regel lautet: Schwierige Punkte werden nicht übersprungen. Zerlege Probleme untersuche dokumentierte Möglichkeiten erprobe sie im geeigneten Labor und halte Blocker mit Ursache bisherigen Versuchen benötigten Voraussetzungen Zuständigkeit nächstem Schritt und betroffener Abnahme fest. Arbeite an unabhängigen Teilen weiter. Ersetze fehlende Sicherheitsfunktionen niemals durch Mockwerte Scheinbuttons erfundene APIs oder ein stillschweigendes V2 Etikett. Physikalische und Plattformgrenzen müssen ehrlich erklärt werden; daraus wird kein universelles Schutzversprechen.

## Unveränderliche Ausgangslage

Name AXSafe. Version V1. Hauptplattform Windows 10 Enterprise LTSC 2021 Version 21H2 Buildfamilie 19044. Der Nutzerscreenshot zeigt Build 19044.7807. x64 ist eine zu bestätigende Architekturannahme. Windows 11 ist zusätzliche Kompatibilitätsplattform. Andere Editionen Plattformen und Architekturen brauchen eigene Freigaben. Verwechsle Enterprise LTSC nicht mit IoT Enterprise LTSC. Microsoft nennt für die erkennbare Enterprise LTSC 2021 Edition den 12 Januar 2027 als reguläres Supportende. Prüfe die dann aktuelle Supportlage vor längerfristiger Veröffentlichung erneut.

Default Stack Rust Core Dienst CLI und Verträge; C Sharp WPF mit .NET 10 für die deutsche Desktop UI; minimale C oder C Plus Plus COM und WDK Integration; Python für Forschung und Testhilfen im Labor. Prüfe die aktuellen offiziellen Kompatibilitätslisten und pinne exakte Werkzeug und Abhängigkeitsversionen. Keine unreviewte Komplettumstellung des Stacks.

Eigener AXSafe Kern mit austauschbaren Engineadaptern. Beginne Open Source zuerst mit ClamAV und YARA X. Prüfe Lizenzen von Werkzeugen Regeln Modellen und Daten getrennt. Separater Prozess bedeutet nicht automatisch Freiheit von GPL Pflichten. Ein optionaler kommerzieller SDK Adapter braucht dokumentierte technische Eignung und Vertrag. Die öffentliche VirusTotal API ist kein zulässiger Ersatz für die Antivirus Engine. Beschaffe keine kostenpflichtigen Dienste oder Verträge ohne Auftrag.

## Schutz und Sicherheitsregeln

Baue lokale Inhaltsprüfung Verhalten Skript und Speicherprüfung echten unterstützten Dateizugriffsschutz Ransomware Eindämmung Quarantäne Wiederherstellung sichere Updates und einen betreubaren Fehlalarmprozess. Berücksichtige alle Bedrohungsklassen in der Abdeckungsmatrix: Dateiviren Würmer Trojaner RAT Backdoors Dropper Loader Downloader Ransomware Wiper Stealer Spyware Keylogger Botnetze Miner Skripte Makros Dokumentexploit dateilose Angriffe LOLBins Injection Rootkits BYOVD Bootkits Firmware Supply Chain PUA Browsererweiterungen Phishing E Mail Anhänge und Wechselmedien. Ordne jeweils vorhandene Sensorik Durchsetzung Nachweise und verbleibende Grenzen zu. Ein normales Endpoint Produkt verhindert nicht automatisch jede Kontotäuschung jedes ungepatchte Systemproblem oder jede Firmwarekompromittierung.

UI unter Benutzerrechten privilegierter Broker klein Parser und Engines in eingeschränkten Workern ohne direkten Internetzugriff. Versionierte lokale Named Pipes mit ACLs Client und Rollenprüfung. Keine beliebige Shellausführung und kein universeller Dateilöschdienst. Identität über geeignete Handles Volume Datei und Streambezug sichern; Rennen zwischen Prüfen und Aktion ausdrücklich testen. Native Abhängigkeiten FFI IPC und komplexe Parser sind eigene Angriffsflächen.

Verwende dokumentierte Windows APIs. Kein SSDT Hooking kein PatchGuard Eingriff kein Abschalten von Secure Boot Speicherintegrität oder anderem OS Schutz als normale Produktvoraussetzung. Produktionstreiber benötigen den regulären Signier und Freigabeweg. Experimentelle Treiber laufen nur im Labor. ClamAV unter Windows und FileSystemWatcher allein liefern keinen vollständigen präventiven Windows Echtzeitschutz. ETW Beobachtung ist nicht automatisch rechtzeitige Blockierung.

AMSI Aufrufer und eigener Antimalwareprovider sind verschiedene Funktionen. Prüfe Provider Signierung Sitzungen Hosts und 32 beziehungsweise 64 Bit Integration tatsächlich. Speicherprüfung bleibt gezielt begrenzt und respektiert geschützte Prozesse. Bei fehlenden Rechten keinen vollständigen Scan behaupten.

Für starken Selbstschutz ELAM PPL und regulären Windows Sicherheitscenter Pfad samt externen Voraussetzungen prüfen. MVI Mitgliedschaft Treibersignierung ELAM Zertifizierung und WSC Integration nicht gleichsetzen. Erfinde keine Registrierungs API und simuliere keinen registrierten Anbieter. Solange der geprüfte Primärschutzwechsel fehlt bleibt etablierter vorhandener Schutz aktiv. Keine breiten Ausschlüsse und keine pauschal erzwungene Defender Abschaltung.

Ausführbare verdächtige Inhalte niemals auf dem Alltagsrechner detonieren. Benigne kontrollierte Simulatoren und EICAR für frühe Funktionsprüfung verwenden. Reale Proben nur rechtmäßig beschafft in geeignetem getrenntem Labor mit überprüfter Isolation Snapshots und keinen privaten oder beruflichen Daten. Keine versteckte Überwachung kein Credential Harvesting und kein Sicherheitsumgehungscode als Testabkürzung.

Quarantäne authentifiziert verschlüsseln Schlüssel mit geeigneten Windows Mechanismen und Dienstrechten sichern transaktionales Journal verwenden Original nur nach haltbarer Sicherung und erneuter Identitätsprüfung entfernen. Restore aktuell neu prüfen Ziel validieren und bytegenau testen. Keine automatische Löschung kritischer Systemdateien auf einen schwachen heuristischen Einzelhinweis. Rollback braucht vorhandene Originale und schützt nicht vor schon erfolgtem Datenabfluss.

TUF gestützte Updates mit getrennten Rollen Signaturen Ablauf und Versionsprüfung Staging atomarer Aktivierung Rolloutringen Schlüsselrotation und Recovery bauen. TLS Authenticode und Repositorymetadaten erfüllen unterschiedliche Aufgaben. Legitimer Rückfall auf erlaubte Artefakte erfolgt durch neue autorisierte Metadaten; Antirollback darf nicht beliebig abgeschaltet werden. Keine komplexen Cloud Regelinterpreter im Kernel.

Cloud ist optional lokale Basis bleibt offline funktionsfähig. Hash und Metadaten sind nicht automatisch anonym. Kein stiller Sampleupload; vor Inhaltsweitergabe konkrete Freigabe Zweck Empfänger und Aufbewahrung. Backend mit Geräteidentität Quoten Zugriffsrollen Mandantentrennung und Löschwegen. Sandbox und Signierinfrastruktur trennen. Ohne nachgewiesenen Nutzen bleibt ein eigenes Modell Forschung und der KI Schutz wird nicht als aktiv gezeigt. LLMs dürfen Befunde erklären aber nicht selbstständig löschen Blockregeln veröffentlichen oder Vertrauen aus Dateitext ableiten.

## Ergebnisse und ehrliche Zustände

Verwende mindestens Malicious Suspicious PUA NoDetection Unsupported Encrypted AccessDenied Timeout Error und ChangedDuringScan. NoDetection bedeutet nur im angegebenen Umfang nichts erkannt. Fehler verschlüsselte Inhalte und fehlende Rechte dürfen niemals sauber ergeben. Schweregrad Konfidenz und Aktion getrennt halten. Jedem Befund Umfang Belege Zeit Dateiidentität Engine Regel Modell und Policyversion zuordnen.

Schutzstatus aus bestätigter Scanner Sensor Policy Definitions und Integrationsgesundheit ableiten. Unbekannt und eingeschränkt sind echte Zustände. Dienstabsturz Sensorverlust nicht verfügbare Cloud und veraltete Daten müssen die UI verändern. Bei früher Koexistenz ist die Erkennungsleistung von AXSafe und fremdem Primärschutz getrennt nachzuweisen.

## UI nach Nutzerreferenz

Baue eine hochwertige deutsche WPF Desktopoberfläche mit dunklem navyblauem Hintergrund cyan und blau leuchtenden Akzenten klarer Typografie abgerundeten Panels dezenten Rahmen und einem eigenen AXSafe Schild. Linke Navigation mit Übersicht Virenscan Echtzeitschutz Ransomware Schutz Firewall und Netzwerk Web und Phishing Quarantäne Datenschutz Berichte. Unten Einstellungen Hilfe und echten Gesundheitsstatus. Zentrale Fläche mit Schutzbanner Statistikzeile Aktivitätsdiagramm Scan Center und letzter Fundliste. Rechts Schutzmodule Live Ereignisse und gemessene AXSafe Systemlast.

Die Referenz ist eine Gestaltungsrichtung und kein Datenlieferant. Übernimm keine Beispielzahlen Uhrzeiten Nutzerinitialen oder aktiven Schalter als Produktzustand. Kein grüner Gesamtstatus ohne belegte Schutzpipeline. Alle Aktionen an echte Dienste anbinden. Nicht verfügbare Fähigkeiten sichtbar deaktivieren und erklären. E Mail Funktion als Anhangprüfung benennen solange keine echte Client oder Gateway Integration existiert. Offline Scan nur aktiv wenn der Rettungsablauf tatsächlich bereitsteht. Windows Firewall Zustand eindeutig von eigenen Filtern unterscheiden.

Zeige Start laufenden Scan Pause Abbruch Teilresultat Fehler Fund Quarantäne Restore Warnung alten Datenstand fehlende Rechte ausstehenden Neustart und Dienstausfall. Schalter warten auf bestätigte Wirkung und korrigieren sich bei Fehler auf den echten Zustand. Tastatur Screenreader Kontrast und 125 bis 200 Prozent Skalierung testen. Lokale Funktionen verlangen kein unnötiges Konto.

## Verbindlicher Phasenplan

| Phase | Ziel | Abhängigkeiten | Anforderungen |
| --- | --- | --- | --- |
| P00 | Ziel und Voraussetzungen klären | keine | AXS-001 bis AXS-006 |
| P01 | Entwicklungsumgebung und Labor aufbauen | P00 | AXS-007 bis AXS-012 |
| P02 | Sicheres Grundsystem und Verträge entwickeln | P01 | AXS-013 bis AXS-020 |
| P03 | Dateiprüfung und Erkennungskern umsetzen | P02 | AXS-021 bis AXS-028 |
| P04 | Sichere Updates und Regelpflege bauen | P02, P03 | AXS-029 bis AXS-034 |
| P05 | Quarantäne und Wiederherstellung absichern | P03, P04 | AXS-035 bis AXS-040 |
| P06 | Sensoren und Verhaltenserkennung verbinden | P02, P03 | AXS-041 bis AXS-046 |
| P07 | Skripte und Speicher prüfen | P03, P06 | AXS-047 bis AXS-052 |
| P08 | Echtzeitschutz im Dateipfad entwickeln | P03, P04, P06 | AXS-053 bis AXS-060 |
| P09 | Ransomware und Reparatur behandeln | P05, P06, P08 | AXS-061 bis AXS-066 |
| P10 | Web Netzwerk E Mail und Wechselmedien ergänzen | P03, P04, P06, P08 | AXS-067 bis AXS-072 |
| P11 | Selbstschutz und Windows Integration abschließen | P04, P07, P08, P09, P10 | AXS-073 bis AXS-078 |
| P12 | Cloud Sandbox und Modellforschung validieren | P03, P04, P06 | AXS-079 bis AXS-084 |
| P13 | Benutzeroberfläche nach Referenz fertigstellen | P02, P05, P06 | AXS-085 bis AXS-090 |
| P14 | Gesamtschutz und Zuverlässigkeit nachweisen | P04, P05, P07, P08, P09, P10, P11, P12, P13 | AXS-091 bis AXS-096 |
| P15 | Veröffentlichen und dauerhaft betreiben | P00, P04, P11, P14 | AXS-097 bis AXS-100 |

Modultests laufen ab dem ersten Schritt. Externe P11 Voraussetzungen früh in P00 klären. Die Reihenfolge ist ein Abhängigkeitsplan; unabhängige Teile dürfen vorbereitet werden. Eine fehlende externe Freigabe wird dokumentiert und blockiert ihren abhängigen Releasepfad, nicht jede unabhängige Entwicklungsarbeit. Nutze keine festen Fristen oder erfundenen Preise.

## Anforderungen und identische Abnahmen

Die folgenden 100 Einträge sind verbindlich und stimmen mit dem Plan überein. Jede Testkennung ist vor Freigabe mit echten Umgebungs Versions und Ergebnisdaten zu verknüpfen. Alle beginnen als geplant.

### P00 Ziel und Voraussetzungen klären

Ziel Den Umfang für Windows 10 LTSC festlegen und die technische sowie organisatorische Ausgangslage belegen.

Ergebnis Produktauftrag, Plattformmatrix, Lizenzliste, Quellenregister, Budgetmodell und Entscheidungsprotokolle

Gate Ausgangslage und V1 Abnahme sind schriftlich festgelegt; fehlende Informationen stehen als offene Punkte im Register.

**AXS-001 Zielplattform belegen**

Windows 10 Enterprise LTSC 2021 21H2 Buildfamilie 19044 als Hauptziel; Screenshot Build 19044.7807 dokumentieren. x64 vor Ort bestätigen, Windows 11 separat testen.

**T-001 Abnahme** Edition Architektur Patchstand und unterstützte Funktionen sind in einer maschinenlesbaren Plattformmatrix erfasst.

**AXS-002 Schutzumfang festlegen**

V1 als mehrschichtiger Windows Endpoint Schutz definieren; Dateiviren Trojaner Ransomware Skripte Speicherangriffe und weitere Familien über eine Bedrohungsmatrix behandeln.

**T-002 Abnahme** Jede Bedrohungsklasse hat Schutzschicht Test und benannte Grenze; keine universelle Erkennungsgarantie.

**AXS-003 Betriebs und Lizenzmodell entscheiden**

Eigener AXSafe Kern mit austauschbaren Engine Adaptern; Open Source zuerst, ClamAV GPL Pflichten vor Verteilung prüfen. Kommerzielle SDKs bleiben eine bewertete Option.

**T-003 Abnahme** ADR zu Eigenentwicklung OEM und Lizenzen liegt vor; fremder Code Regeln Daten Modelle und Marken sind getrennt erfasst.

**AXS-004 Bedrohungsmodell erstellen**

Angreifer mit normalen Rechten Adminrechten Kernelzugriff und kompromittierter Updateinfrastruktur getrennt modellieren; Schutzgüter und Vertrauensgrenzen benennen.

**T-004 Abnahme** Review dokumentiert mindestens Dateiparser IPC Quarantäne Updater Treiber Cloud und UI als Angriffsflächen.

**AXS-005 Rechtliche Markteinführung prüfen**

DSGVO CRA Produktklassifizierung Haftung Vertrieb Supportdauer sowie Name und Marke AXSafe prüfen; keine Zertifizierung behaupten.

**T-005 Abnahme** Prüfakte enthält zuständige Rolle Fundstellen Stand und offene Entscheidungen; rechtsrelevante Unklarheiten blockieren den betroffenen Vertrieb.

**AXS-006 Ressourcen und Freigaben planen**

Kompetenzen Windows Kernelentwicklung Malwareanalyse Tests Signierung Datenschutz und Betrieb zuordnen; Kosten ohne erfundene Angebote modellieren.

**T-006 Abnahme** Budgetmatrix trennt einmalige und laufende Ausgaben; Zertifikate Hardware Testlabore und SDK Preise bleiben ohne Angebot offen.

### P01 Entwicklungsumgebung und Labor aufbauen

Ziel Reproduzierbare Entwicklung und ein getrenntes Testlabor bereitstellen.

Ergebnis Repository, Buildskripte, Windows VM Images, Testdatensätze und Laborregeln

Gate Ein frischer Checkout baut reproduzierbar; ein Testlauf kann ohne private Daten und ohne Zugriff auf das Alltagsnetz durchgeführt werden.

**AXS-007 Reproduzierbar bauen**

Repository mit Rust Dienst und Core C Sharp WPF .NET 10 C oder C Plus Plus WDK Komponenten sowie getrennten Backend und Forschungsteilen anlegen.

**T-007 Abnahme** Frischer Checkout baut mit gepinnten Versionen Lockfiles und dokumentierten Offlinegrenzen; Versionsänderungen werden geprüft.

**AXS-008 Getrenntes Labor erstellen**

Saubere LTSC und Windows 11 VMs mit Snapshots ohne private Konten geteilte Ordner oder Zwischenablage bereitstellen; separates Netz verwenden.

**T-008 Abnahme** Ein Isolationstest belegt fehlenden Zugriff auf Alltagsdaten und Produktivnetz; Wiederherstellung aus sauberem Ausgangspunkt funktioniert.

**AXS-009 Prüfdaten verwalten**

Gutartige Dateien lizenzgeprüfte Testdaten EICAR und kontrollierte Simulatoren erfassen; reale Schadsoftware ausschließlich in freigegebenem Labor verwenden.

**T-009 Abnahme** Manifest mit Herkunft Hash Lizenz Zeitstempel und erwarteter Beobachtung ist vorhanden; kein unbeabsichtigter Download oder Hoststart.

**AXS-010 Sicherheitsprüfungen automatisieren**

Build Lint statische Analyse Abhängigkeitsprüfung Geheimnissuche und SBOM integrieren; untrusted Pull Requests haben keinen Zugriff auf Signierschlüssel.

**T-010 Abnahme** Manipulierte Abhängigkeit und absichtlich eingefügtes Testgeheimnis lassen die Pipeline fehlschlagen; Releasejob ist getrennt.

**AXS-011 Modulprüfungen sofort betreiben**

Unit Integration Fehler und Negativtests ab dem ersten Modul ausführen; Gesamtphase P14 ersetzt diese frühen Prüfungen nicht.

**T-011 Abnahme** Jeder neue Schutzpfad besitzt positive und gutartige Gegenfälle sowie einen dokumentierten Ausfallfall.

**AXS-012 Forschungs und Produktcode trennen**

Experimentelle Sensoren Modelle Simulationen und Testsignaturen dürfen ohne bewusste Freigabe nicht in ein Produktpaket gelangen.

**T-012 Abnahme** Releaseinventar und automatischer Paketvergleich weisen nach dass keine Laborprobe und kein Testschlüssel enthalten sind.

### P02 Sicheres Grundsystem und Verträge entwickeln

Ziel Benutzeroberfläche, privilegierten Broker und Scanprozesse mit klaren Rechten und Datentypen trennen.

Ergebnis Dienst, CLI, authentifizierte lokale IPC, Ereignisvertrag, Policy und Ergebnismodell

Gate Ein normaler Benutzer kann den Dienst weder als beliebigen Dateileser noch als Löschdienst missbrauchen; Ausfälle werden korrekt gemeldet.

**AXS-013 Rechte trennen**

UI unter Benutzerrechten starten; privilegierten Broker minimal halten; Parser und Engineworker mit reduzierten Rechten ohne Internetzugriff betreiben.

**T-013 Abnahme** Ein kompromittierter Testworker kann keine beliebigen Systemdateien ändern und keine Verbindung ins Netz aufbauen.

**AXS-014 Lokale IPC absichern**

Versionierte Named Pipes mit restriktiven ACLs überprüfter Clientidentität Rollen und Nachrichtenlimits verwenden; keine offen erreichbare lokale Admin HTTP API.

**T-014 Abnahme** Fremde Sitzung falscher Benutzer oversized Nachricht und Replay einer mutierenden Anfrage werden abgewiesen und protokolliert.

**AXS-015 Scanergebnisse ehrlich modellieren**

Malicious Suspicious PUA NoDetection Unsupported Encrypted AccessDenied Timeout Error ChangedDuringScan getrennt modellieren; Abdeckung und Engineversion mitspeichern.

**T-015 Abnahme** Keiner der Fehler und Teilzustände wird in UI oder Bericht zu sauber oder vollständig geprüft umgewandelt.

**AXS-016 Ereignisse nachvollziehbar machen**

Schema mit UTC Zeit lokaler Anzeige Korrelations ID Prozessstartidentität Dateiidentität Regel und Engineversion implementieren; Datenmenge begrenzen.

**T-016 Abnahme** Ein Befund lässt sich vom Ereignis bis zur Aktion nachvollziehen; PID Wiederverwendung vermischt keine Prozesse.

**AXS-017 Policies und Ausnahmen begrenzen**

Versionierte Policies mit Rollen Ausnahmen auf genaue Objekte oder eng begrenzte Bereiche Audit und Ablaufzeit unterstützen.

**T-017 Abnahme** Standardbenutzer kann keinen globalen Ausschluss setzen; ausgeschlossene Bereiche erscheinen als verringerte Abdeckung.

**AXS-018 Dateiidentität sicher behandeln**

Handle Volume Datei ID Stream und Änderungszustand statt nur Pfad verwenden; Reparsepoints Junctions Hardlinks ADS lange und Unicode Pfade berücksichtigen.

**T-018 Abnahme** Parallel umbenannte und ausgetauschte Testdateien werden nicht verwechselt; mutierende Aktionen treffen ausschließlich das validierte Objekt.

**AXS-019 Betriebszustand aus Gesundheit ableiten**

ScannerReady SensorReady PolicyReady DefinitionsFresh und PrimaryProtection getrennt erfassen; Zustand unknown oder degraded bei Unsicherheit.

**T-019 Abnahme** Dienstabsturz Sensorverlust und kaputte Engine ändern den UI Status; fehlende Antwort erzeugt niemals einen grünen Schutzstatus.

**AXS-020 Lokale Daten sichern**

Konfiguration Ereignisse Schlüssel und Quarantänemetadaten mit Dienstrechten ACLs Rotation und Recovery versehen; geheime Daten nicht in Logs schreiben.

**T-020 Abnahme** Unprivilegierter Zugriff scheitert; beschädigte Datenbank wird kontrolliert behandelt und erzeugt keinen Schutzstillstand ohne Meldung.

### P03 Dateiprüfung und Erkennungskern umsetzen

Ziel Reale lokale Dateiprüfung mit Engines, eigenen Regeln und ehrlichen Teilresultaten implementieren.

Ergebnis ClamAV Adapter, YARA X Adapter, Typenerkennung, Archivbehandlung und sicherer Scancache

Gate Erkennung, Negativfälle, verschachtelte Container und alle Scanfehler sind nachvollziehbar getestet; keine Probe wird auf dem Host ausgeführt.

**AXS-021 Engineadapter real anbinden**

ClamAV über einen isolierten Worker anbinden und Engine Vertrag für weitere Anbieter definieren; keine frei erreichbare clamd TCP Schnittstelle eröffnen.

**T-021 Abnahme** Reale Scanresultate Versionsinfos und Fehler sind geprüft; Engineabsturz bleibt im Worker und erzeugt einen Fehlerstatus.

**AXS-022 Eigene Regeln mit YARA X integrieren**

Signierte versionierte Regeln mit Herkunft Lizenz Schweregrad Konfidenz und Mindestengineversion laden; Laufzeit und Speicher begrenzen.

**T-022 Abnahme** Positive gutartige und Timeout Tests pro Regel bestehen; bloßer Regelname oder Dateiname führt nicht zum Fund.

**AXS-023 Dateitypen erkennen**

Typ nach Inhalt erkennen und PE32 PE64 .NET Skripte LNK MSI Office PDF Archive und Datenträgercontainer in einer Fähigkeitsmatrix führen.

**T-023 Abnahme** Umbenennen einer Datei umgeht die Typbestimmung nicht; nicht unterstützte Formate erhalten einen sichtbaren Teilstatus.

**AXS-024 Container sicher prüfen**

Archive rekursiv mit Ressourcenlimits prüfen; Passwörter eingebettete Objekte mehrfach verschachtelte Archive und fehlerhafte Parserdaten behandeln.

**T-024 Abnahme** Archivbomben Pfadausbruch und Grenzwertüberschreitung verursachen keinen Hostschaden; unprüfbarer Inhalt wird ausdrücklich gemeldet.

**AXS-025 Statische Merkmale auswerten**

Hash Authenticode Herkunft Mark of the Web Struktur Importe und nachvollziehbare Heuristiken kombinieren; Signatur und hohe Entropie allein entscheiden nicht.

**T-025 Abnahme** Gutartige gepackte signierte und unsignierte Programme haben Gegenfälle; jeder Heuristikbefund nennt seine Belege.

**AXS-026 Scanarten implementieren**

Schnellscan Vollscan eigener Scan Kontextmenü Zeitplan und Wechselmedienscan mit Abbruch Fortsetzung und Fortschritt bereitstellen.

**T-026 Abnahme** Dateien Bytes Dauer übersprungene Objekte und Fehler stimmen mit dem Scanmanifest überein; Abbruch und Neustart verlieren keine Quarantäneaktion.

**AXS-027 Cache invalidieren**

Befunde an Inhalt beziehungsweise stabilen Dateizustand Engine Regel Modell und Policyversion binden; neue Threat Intelligence invalidiert passende Einträge.

**T-027 Abnahme** Geänderte Datei neue Regel andere Policy und erneutes Mounten erzeugen eine neue Bewertung statt eines veralteten Freigabecaches.

**AXS-028 Schadcode sicher verarbeiten**

Scannen bleibt Lesen und isoliertes Analysieren; Parser temporäre Dateien native Bibliotheken und Dateizugriffe werden begrenzt und fuzzbar gestaltet.

**T-028 Abnahme** Fehlerhafte Eingaben verletzen keine Broker oder Kernelgrenze; ausführbare Proben starten nicht auf dem Endgerät.

### P04 Sichere Updates und Regelpflege bauen

Ziel Programm, Signaturen, Regeln und Modelle manipulationsgeschützt und wiederherstellbar aktualisieren.

Ergebnis TUF gestützter Updatepfad, Signierschema, Staging, Rollout und Rückfallverfahren

Gate Manipulierte, abgelaufene und unzulässig alte Updates werden abgewiesen; Stromausfall und Schlüsselwechsel sind getestet.

**AXS-029 Updatevertrauen etablieren**

TUF mit getrennten Rollen und Offline Root Vertrauen verwenden; Artefaktsignaturen Authenticode und TLS erfüllen unterschiedliche Aufgaben.

**T-029 Abnahme** Tests für Fremdschlüssel manipulierte Pakete Metadatenablauf Rollback Freeze und Mix and Match bestehen.

**AXS-030 Signaturen und Regeln pflegen**

FreshClam mit geprüfter Konfiguration für ClamAV Daten verwenden; AXSafe Regeln getrennt veröffentlichen; Upstream Lizenz Last und Verteilregeln beachten.

**T-030 Abnahme** Defekte oder unpassende Daten bleiben in Staging; produktive Engine behält den letzten funktionierenden Satz.

**AXS-031 Atomar aktualisieren**

Programm Engine Regeln Modelle und Treiber mit Kompatibilitätsvertrag und atomarer Aktivierung installieren; laufende Scans behalten eine konsistente Version.

**T-031 Abnahme** Abbruch Stromausfall Datenträger voll und Neustart während Update führen zu altem oder neuem gültigem Zustand ohne Mischversion.

**AXS-032 Gestuft ausrollen**

Interne VMs Pilotgruppen und kontrollierte Verteilringe mit Gesundheitsdaten Stopkriterien und authentifizierter Rücknahme definieren.

**T-032 Abnahme** Eine fehlerhafte Pilotregel erreicht den nächsten Ring nicht; Ausfall einzelner Cloudsysteme deaktiviert keinen lokalen Basisschutz.

**AXS-033 Rollback und Antirollback vereinbaren**

Fehlerhafte Releases nur durch neue autorisierte Metadaten auf freigegebene bekannte Artefakte zurücksetzen; Mindestversion und gesperrte Versionen beachten.

**T-033 Abnahme** Berechtigtes Recovery funktioniert; ein Angreifer kann keinen beliebigen alten verwundbaren Stand als Wiederherstellung einschleusen.

**AXS-034 Schlüssel und Offlinefälle behandeln**

Schlüssel in HSM oder geeignetem geschütztem Signierdienst halten; Rotation Widerruf Uhrfehler Proxy und Offlineupdate vorsehen.

**T-034 Abnahme** Verlust eines Online Signierschlüssels führt zu geprobter Rotation; abgelaufene Metadaten und veraltete Definitionen werden sichtbar.

### P05 Quarantäne und Wiederherstellung absichern

Ziel Funde sicher isolieren und nachvollziehbar wiederherstellen, ohne Systemdateien zu beschädigen.

Ergebnis Verschlüsselte Quarantäne, Journal, Bereinigungsvorschläge und Wiederherstellungsdialog

Gate Dateiverwechslung, Rechteausweitung und Datenverlust werden in den definierten Fehlerfällen verhindert; Restore ist bytegenau geprüft.

**AXS-035 Quarantäne verschlüsseln**

Payload authentifiziert verschlüsseln etwa mit AES GCM und zufälligen Nonces; Schlüssel über Windows Schutzmechanismen und Dienst ACLs sichern.

**T-035 Abnahme** Quarantänedatei kann nicht direkt ausgeführt oder unprivilegiert entschlüsselt werden; Manipulation wird erkannt.

**AXS-036 Quarantäne transaktional ausführen**

Identität Hash Streams Metadaten und Wiederherstellungsdaten sichern; erst nach haltbarer Sicherung Originalzugriff entfernen; Journal und Neustart fortsetzen.

**T-036 Abnahme** Crash zwischen jedem Transaktionsschritt verursacht weder stille Datenlöschung noch falschen Erfolg; gesperrte Dateien haben einen expliziten Zustand.

**AXS-037 Restore kontrollieren**

Rückgabe nur nach Berechtigungsprüfung aktuellem Rescan Zielprüfung und sichtbarer Warnung; Ausnahmen eng begrenzen.

**T-037 Abnahme** Originalhash und freigegebene Metadaten stimmen; belegte Zieldateien und gefährliche Pfade werden nicht unbemerkt überschrieben.

**AXS-038 Systemreparatur vorsichtig planen**

Persistenz und Dateifunde zu einer Reparaturvorschau bündeln; Systemdateien und unbekannte Abhängigkeiten nicht blind löschen.

**T-038 Abnahme** Gutartige Autostarts Dienste und Systemdateien bleiben erhalten; Reparaturfehler und Neustartbedarf sind nachvollziehbar.

**AXS-039 Quarantänelimits verwalten**

Speicherlimit Aufbewahrung Export und autorisierte endgültige Löschung definieren; keine automatische riskante Wiederherstellung bei Platzmangel.

**T-039 Abnahme** Volle Quarantäne und erschöpfter Datenträger erzeugen verständliche Aktionen ohne Verlust ungeklärter Fälle.

**AXS-040 Befunde überprüfen können**

Fehlalarm melden Regel zurücknehmen und Objekte nach Korrektur erneut prüfen; Meldung übermittelt nur freigegebene Daten.

**T-040 Abnahme** Ein absichtlich erzeugter Fehlalarm lässt sich begründet korrigieren und bytegenau rückgängig machen.

### P06 Sensoren und Verhaltenserkennung verbinden

Ziel Prozess, Datei, Persistenz und Netzwerkereignisse zu überprüfbaren Verhaltensbefunden korrelieren.

Ergebnis Windows Sensoren, Prozessbaum, Ereignisjournal und versionierte Verhaltensregeln

Gate Gutartige Gegenbeispiele und simulierte Angriffsketten unterscheiden sich zuverlässig; Sensorverluste sind sichtbar.

**AXS-041 Windows Sensoren anbinden**

Dokumentierte ETW Ereignisse und geeignete APIs für Prozess Datei Registry Dienst Task und Netzwerk nutzen; Fähigkeiten pro Build prüfen.

**T-041 Abnahme** Jeder Sensor hat einen echten Integrationstest auf LTSC; nicht verfügbare oder verlorene Ereignisse sind messbar und sichtbar.

**AXS-042 Ereignisverlust beherrschen**

Queues begrenzen Backpressure Reihenfolge Duplikate und Überlauf behandeln; Dateiwatcher nur als Nachscanner nutzen.

**T-042 Abnahme** Überlasttest provoziert Verluste und Rescan; kein Watcher wird als garantierte Ausführungsblockierung ausgegeben.

**AXS-043 Prozesszusammenhang bilden**

Prozessstartidentität Eltern Kind Beziehungen Signer Token Dateiobjekte und Netzverbindungen zu einer lokalen Zeitleiste verknüpfen.

**T-043 Abnahme** PID Wiederverwendung Neustarts und manipulierte Namen erzeugen keine falschen Prozessketten.

**AXS-044 Verhaltensregeln validieren**

Mehrere Signale für Dropper Persistenz Credential Diebstahl verdächtige Skripte Injection und Fernsteuerung korrelieren; Konfidenz Aktion und ATTACK Bezug angeben.

**T-044 Abnahme** Für jede Regel bestehen kontrollierte Angriffssimulation und mehrere legitime Gegenbeispiele; Einzelindikatoren bewirken kein pauschales Löschen.

**AXS-045 Reaktionen begrenzen**

Warnen erneutes Prüfen Zugriff blockieren isolieren und definierte Prozessbeendigung nach belegter Policy staffeln; Prozessidentität vor Aktion neu prüfen.

**T-045 Abnahme** Gutartige Verwaltungswerkzeuge Debugger und Installer werden nicht allein wegen ihrer Funktion beendet.

**AXS-046 Nachvollziehbares Journal führen**

Sicherheitsrelevante Entscheidung Eingangsereignisse Aktion Ergebnis Version und Datenverlust protokollieren; Datenschutz und begrenzte Aufbewahrung einhalten.

**T-046 Abnahme** Eine reproduzierte Testkette kann vollständig erklärt werden; Logs sind exportierbar ohne unnötige Geheimnisse.

### P07 Skripte und Speicher prüfen

Ziel AMSI Provider und begrenzte Speicheranalyse als echte zusätzliche Schutzschichten anbinden.

Ergebnis Signierter AMSI Provider, Sitzungsanalyse, Speicherworker und Rechtekonzept

Gate AXSafe eigene AMSI Befunde sind vom Aufruf fremder Scanner getrennt; nicht zugänglicher Speicher wird als solcher ausgewiesen.

**AXS-047 AMSI Provider implementieren**

Eigenen IAntimalwareProvider für die Zielarchitekturen registrieren signieren und mit Engines verbinden; in Skripthosts nur minimalen Code laden.

**T-047 Abnahme** Testhost und passende PowerShell Hosts erhalten einen AXSafe eigenen Befund; AmsiScanBuffer Aufruf zu fremdem Provider zählt nicht als Eigenentwicklung.

**AXS-048 Skriptsitzungen korrelieren**

AMSI Streams Fragmente und Sitzungen begrenzt auswerten; Skriptinhalt als vertraulich behandeln; fehlende AMSI Einbindung kenntlich machen.

**T-048 Abnahme** Fragmentierter gutartiger und kontrolliert verdächtiger Inhalt wird wie spezifiziert bewertet; Standardlogs enthalten keine vollständigen Skripte.

**AXS-049 Speicherscan begrenzen**

Gezielt verdächtige Prozesse und lesbare Bereiche mit dokumentierten APIs prüfen; keine Schutzmechanismen umgehen und keine Vollabbild Sammlung als Standard.

**T-049 Abnahme** Zugriffsfehler geschützte Prozesse 32 Bit und 64 Bit werden korrekt behandelt; Worker bleibt innerhalb des Zeit und Speicherbudgets.

**AXS-050 Speicherbefunde belegen**

Signaturmuster ungewöhnliche ausführbare Bereiche Herkunft und Verhalten gemeinsam bewerten; JIT Browser Spiele und Debugger als Gegenfälle einbeziehen.

**T-050 Abnahme** Gutartiger dynamischer Code löst keine pauschale Blockade aus; jeder Befund nennt beobachtete Daten und Grenzen.

**AXS-051 Sensorintegrität überwachen**

Ausfall oder mögliche Manipulation von AMSI ETW und eigenen Komponenten als eigene Gesundheitssignale melden.

**T-051 Abnahme** Simulierter Ausfall führt zu degraded und prüfbarer Meldung; kein Umgehungscode ist Teil des Produkts.

**AXS-052 Skript und Makroformate dokumentieren**

PowerShell JS VBS VBA und unterstützte Dokumentversionen getrennt prüfen; nicht kooperierende Hosts bleiben als Lücke erfasst.

**T-052 Abnahme** Fähigkeitsmatrix nennt Host Architektur Office Version und Test; unbekannte Kombinationen erscheinen nicht als garantiert geschützt.

### P08 Echtzeitschutz im Dateipfad entwickeln

Ziel Zugriffe auf unterstützten Dateipfaden vor der Freigabe prüfen und gefährliche I O sicher verhindern.

Ergebnis Minimaler Minifilter, User Mode Scanpfad, Cache Invalidierung, Timeout und Recovery

Gate Reale Zugriffsblockierung ist auf der LTSC Testmatrix belegt; kein Dauerwarten, keine selbst verursachte Bootschleife und keine ungetesteten Treiber im Produkt.

**AXS-053 Minimalen Minifilter entwickeln**

Dokumentierten Windows Filter Manager mit User Mode Scanworker einsetzen; Dateiparser Modelle und Regelinterpreter nicht im Kernel ausführen.

**T-053 Abnahme** Treiber enthält nur notwendige Sensor und Durchsetzungslogik; Code Review und reale I O Tests liegen vor.

**AXS-054 Zugriffszeitpunkte absichern**

Öffnen Schreiben Umbenennen Ausführen und Section Erstellung einschließlich Memory Mapping bewerten; erlaubte Abläufe und Sperrzeitpunkte präzise definieren.

**T-054 Abnahme** Eine erkannte Testdatei kann auf unterstützten Pfaden nicht vor der vorgesehenen Entscheidung ausgeführt oder erneut verändert werden.

**AXS-055 Dateirennen verhindern**

Datei Stream Identität Änderungszustand stabile Lesesicht und Cache Invalidierung mit Filter Manager Mechanismen verbinden; transaktionale I O beachten.

**T-055 Abnahme** Austausch Änderung Hardlink und Reparsepoint Tests zwischen Scan und Aktion erzeugen keine veraltete Freigabe oder falsche Löschung.

**AXS-056 Deadlocks und Überlast ausschließen**

Begrenzte Wartezeiten cancelbare Anfragen IRQL Regeln Reentrancy Paging I O und Verlust der User Mode Verbindung beherrschen.

**T-056 Abnahme** Workerabsturz niedriger Speicher und parallele Last halten den Rechner bedienbar; Fehlerzustand ist sichtbar.

**AXS-057 Fehlerpolicy explizit machen**

Bekannt schädliche Objekte bleiben blockiert; bei unbekannten Inhalten und Scannerfehlern verfügbarkeitsorientierten oder strengeren Modus ausdrücklich definieren.

**T-057 Abnahme** Timeout ergibt nie sauber; Modus und Ausnahme sind testbar und werden protokolliert; kritischer Systemstart darf nicht endlos blockieren.

**AXS-058 Treiber regulär ausliefern**

Passende WDK Toolchain Altitude Hardware Dashboard Signierung und erforderliche Tests beschaffen; Testsignierung nur im Labor.

**T-058 Abnahme** Produktionstreiber lädt auf normal konfigurierten Zielsystemen; Secure Boot oder Speicherintegrität müssen dafür nicht abgeschaltet werden.

**AXS-059 Dateisysteme und Fremdfilter prüfen**

NTFS exFAT unterstützte ReFS SMB OneDrive Platzhalter ZIP ISO USB lange Pfade und fremde Filter nach definierter Matrix testen.

**T-059 Abnahme** Nicht geprüfte Kombinationen sind als solche benannt; Cloud Platzhalter werden nicht unbemerkt massenhaft heruntergeladen.

**AXS-060 Boot und Treiber Recovery beweisen**

Installation Upgrade Abbruch Safe Mode und autorisierten Notfallausbau mit Offlinezugriff planen und prüfen.

**T-060 Abnahme** Ein defektes Testrelease lässt sich auf einer separaten VM aus einer Bootstörung zurückholen; kein Bootloop wird als akzeptabler Restfehler freigegeben.

### P09 Ransomware und Reparatur behandeln

Ziel Schädliche Dateiänderungen begrenzen und unterstützte Änderungen kontrolliert rückgängig machen.

Ergebnis Korrelationsregeln, Schreibschutzpolicy, begrenzter Versionsspeicher und Reparaturplan

Gate Simulierte Massenschreibvorgänge werden in der vereinbarten Schadensgrenze gestoppt; Wiederherstellung und ihre Grenzen sind bewiesen.

**AXS-061 Ransomware Muster korrelieren**

Prozess Herkunft ungewöhnliche Änderungsraten Dateiversionen und weitere Signale kombinieren; Entropie oder Canary alleine reicht nicht.

**T-061 Abnahme** Gutartige Komprimierung Backup Sync und Entwicklung sind Gegenfälle; Simulator verändert ausschließlich wegwerfbare Testdateien.

**AXS-062 Schreibvorgänge begrenzen**

Definierte geschützte Ordner und unterstützte Dateioperationen über getestete Durchsetzung sperren; Remote SMB Verursachung gesondert behandeln.

**T-062 Abnahme** Vorab festgelegtes Schadensbudget für Testdateien wird gemessen; lokal und remote ausgelöste Fälle sind getrennt ausgewiesen.

**AXS-063 Wiederherstellung begrenzt zusagen**

Für unterstützte Änderungen vorhandene Originalversionen vorhalten; Kapazität Konsistenz Verschlüsselung und geschützte Ablage planen.

**T-063 Abnahme** Wiederherstellung der Testdateien ist bytegenau; ohne Originalkopie erscheint keine garantierte Entschlüsselung.

**AXS-064 Wiper und Erpressung unterscheiden**

Datenzerstörung Massenlöschung Verschlüsselung und Datenabfluss getrennt melden; kein Rollback als Schutz vor bereits erfolgter Exfiltration darstellen.

**T-064 Abnahme** Simulationen erzeugen unterschiedliche Befunde und korrekte Handlungshinweise; bestehende Backups bleiben unabhängig erforderlich.

**AXS-065 Persistenz kontrolliert beseitigen**

Run Keys Dienste Tasks WMI relevante Browserkomponenten und Startup Ordner prüfen; Beziehungsnachweise für Reparatur verlangen.

**T-065 Abnahme** Legitime Verwaltungs und Autostartfälle bleiben funktionsfähig; Reparaturvorschau und Wiederherstellung sind getestet.

**AXS-066 Offlineprüfung spezifizieren und erproben**

Externes bootfähiges Rettungsmedium oder WinPE Pfad mit eigenen Lizenz und Signierprüfungen bereitstellen; BitLocker und verschlüsselte Datenträger beachten.

**T-066 Abnahme** Offlineablauf funktioniert auf Laborgerät mit freigegebenem Schlüsselzugriff; gesperrte Datenträger bleiben als nicht geprüft sichtbar.

### P10 Web Netzwerk E Mail und Wechselmedien ergänzen

Ziel Weitere Einfallstore durch getrennte und benannte Schutzfunktionen abdecken.

Ergebnis Browseranbindung, Reputation, WFP Policies, USB Dateiscans und Attachment Prüfung

Gate IPv4 IPv6, Browser, Netzlaufwerke und Wechselmedien sind getestet; HTTPS und E Mail Grenzen werden korrekt angezeigt.

**AXS-067 Web und Phishing trennen**

Browsererweiterung mit minimalen Berechtigungen und lizenzierter URL Reputation einsetzen; Punycode Weiterleitungen Downloads und unbekannte URLs berücksichtigen.

**T-067 Abnahme** Getrennte Tests für schädliche Testseite legitime Seite Datenminimierung und Ausfall bestehen; unbekannt gilt nicht als vertrauenswürdig.

**AXS-068 Netzwerkpolicy implementieren**

Windows Firewall und gezielte WFP Filter für Prozess Ziel und Verbindungsblockaden nutzen; IPv4 IPv6 VPN Proxy und DNS Wege prüfen.

**T-068 Abnahme** Gezielte Testverbindung wird blockiert erlaubte bleibt nutzbar; Isolation hält benötigte Recoverykanäle nach ausdrücklicher Policy offen.

**AXS-069 Verschlüsselungsgrenzen einhalten**

Ohne eigenen legitimierten Entschlüsselungspfad keinen vollständigen HTTPS Mail oder QUIC Inhaltsscan behaupten; keinen Root CA Eingriff als Standard.

**T-069 Abnahme** UI erklärt die tatsächlich geprüften Datenquellen; Tests mit HTTPS QUIC DoH und VPN zeigen erwartete Sichtbarkeit und Grenzen.

**AXS-070 E Mail Schutz ehrlich umsetzen**

Zunächst lokal gespeicherte Anhänge und unterstützte Downloadpfade prüfen; Client oder Gateway Integration mit eigener Rechte und Protokollmatrix ausweisen.

**T-070 Abnahme** Ohne echte Integration steht Anhangprüfung statt vollständiger Postfachschutz; E Mail Kennwörter und Inhalte werden nicht heimlich gesammelt.

**AXS-071 Wechselmedien prüfen**

Neue Datenträger und deren Dateien scannen Autoausführung beachten und Scanaufträge begrenzen; BadUSB nicht mit Dateivirenschutz gleichsetzen.

**T-071 Abnahme** USB Datei und Ausführungsfälle sind getestet; Tastatur und Firmware Angriffe erscheinen als eigene Grenze.

**AXS-072 Netz und Kommunikationsindikatoren bewerten**

C2 bekannte Schadziele und Reputation mit Kontext Ablaufzeit und Gegenfällen verwenden; keine globale Sperre auf gemeinsam genutzte Infrastruktur ohne Beleg.

**T-072 Abnahme** Benigne Cloud und CDN Ziele bleiben erreichbar; veraltete und fehlerhafte Indikatoren können kontrolliert zurückgenommen werden.

### P11 Selbstschutz und Windows Integration abschließen

Ziel Manipulation begrenzen und AXSafe nur mit belegter Funktion als primären Schutz integrieren.

Ergebnis Selbstschutz, ELAM PPL Prüfung, Signiernachweise, WSC Integrationsweg und Notfallausbau

Gate Alle beanspruchten Schutzstufen sind technisch und organisatorisch belegt; fremder Schutz wird nicht vorzeitig deaktiviert.

**AXS-073 Selbstschutz stufenweise umsetzen**

ACLs signierte Konfiguration Servicezugriff und Integritätskontrollen gegen Standardbenutzer absichern; Admin und Kernelgrenzen benennen.

**T-073 Abnahme** Manipulation aus Standardbenutzerkontext scheitert; verlorene Schutzfähigkeit wird erkannt und gemeldet.

**AXS-074 ELAM und PPL Pfad prüfen**

Für starken Dienstschutz ELAM zertifizierten Treiber Zertifikatsressourcen signierte DLLs und Wartungsweg technisch erproben.

**T-074 Abnahme** Bei beanspruchtem PPL Schutz liegt ein realer Nachweis vor; ohne externe Voraussetzungen bleibt dieser Punkt offen und blockiert das entsprechende Versprechen.

**AXS-075 Windows Sicherheitscenter regulär anbinden**

Unterstützten Registrierungs und Statuspfad mit Microsoft beziehungsweise geeignetem OEM klären; keine erfundenen API oder WMI Produktmeldungen.

**T-075 Abnahme** Windows zeigt den realen Zustand; Aufnahme Voraussetzungen und Zugang sind dokumentiert statt simuliert.

**AXS-076 Koexistenz nachweisen**

Bis zur geprüften Primärschutzfreigabe vorhandenen Defender aktiv lassen; keine breiten Ausschlüsse oder pauschal erzwungenen Betriebsmodi setzen.

**T-076 Abnahme** Companion Tests und kontrollierter Primärschutzwechsel beweisen dass kein ungeschütztes Zeitfenster entsteht.

**AXS-077 Rootkit und Treiberrisiken behandeln**

Treiber und Bootintegrität unterstützte Blocklisten Secure Boot und HVCI Status prüfen; tiefe Kernel oder Firmwarekompromittierung als Eskalationsfall behandeln.

**T-077 Abnahme** Bekannte Testindikatoren und fehlende Voraussetzungen werden gemeldet; kein vollständiger Firmware Reinheitsnachweis wird aus einem Live Scan abgeleitet.

**AXS-078 Autorisierten Ausbau erlauben**

Pausieren Reparatur und Deinstallation mit Rechten Zeitbegrenzung Audit und Recovery verbinden; Nutzer darf nicht ausgesperrt werden.

**T-078 Abnahme** Legitime Deinstallation und Notfallwiederherstellung funktionieren; beliebige unprivilegierte Schutzabschaltung gelingt nicht.

### P12 Cloud Sandbox und Modellforschung validieren

Ziel Optionale Cloudfunktionen und vertiefte Analysen mit getrennten Vertrauensgrenzen aufbauen.

Ergebnis Hash Reputation, explizite Sample Freigabe, isolierte Sandbox und reproduzierbare Modellbewertung

Gate Lokaler Schutz läuft ohne Cloud weiter; kein Dateiinhalt verlässt den Rechner ohne Freigabe; Modelle bleiben ohne Eignungsnachweis im Forschungsmodus.

**AXS-079 Optionale Reputation betreiben**

Eigenen authentifizierten Backendvertrag mit Hash Abfragen TTL Limits Quoten Ausfallcache und getrennten Datenschutzstufen entwickeln.

**T-079 Abnahme** Cloud aus offline und langsames Netz lassen lokale Erkennung weiterlaufen; kein unbekannter Hash wird automatisch als sicher eingestuft.

**AXS-080 Sample Upload ausdrücklich freigeben**

Vor jedem nicht bereits konkret freigegebenen Inhaltsupload Zweck Empfänger Daten und Aufbewahrung erklären; keine Bank oder Arbeitgeberdaten als Testmaterial.

**T-080 Abnahme** Abgelehnter Upload übermittelt keine Datei; Freigabe Audit Löschung Zugriffskontrolle und getrennte Ablage sind getestet.

**AXS-081 Sandbox isoliert integrieren**

Verdächtige Dateien nur in separaten zurücksetzbaren Analyse VMs ausführen; Kontrollpfad und Ausgabeparser absichern; niemals auf dem Alltagsgerät detonieren.

**T-081 Abnahme** Isolation Rücksetzung Limits und fehlerhafte Analysedaten bestehen Tests; unauffälliger Sandboxlauf bedeutet keine Freigabegarantie.

**AXS-082 Modellforschung reproduzieren**

Lizenzgeprüfte Datensätze mit zeitlicher und Familien Trennung verwenden; aktuelle gutartige Dateien ergänzen; einfache Baseline vor komplexen Netzen bewerten.

**T-082 Abnahme** Versionierte Daten und Features liefern reproduzierbare Ergebnisse ohne Train Test Überschneidung; alte Datensätze begründen keine aktuelle Schutzquote.

**AXS-083 Modelle sicher freigeben**

Fehlalarme Kalibrierung unbekannte Typen Drift Poisoning und manipulierte Merkmale prüfen; Modell Featurevertrag und Inferenzruntime signieren.

**T-083 Abnahme** Modell bleibt ohne belegten Mehrwert im Forschungsmodus; optionaler Produktbetrieb hat Grenzwerte Rücknahme und nachvollziehbare Befunde.

**AXS-084 Forschungsbetrieb begrenzen**

Threat Intel Quellen STIX TAXII Analystenfreigaben Kosten und Missbrauchsschutz planen; kein öffentliches Malware Ausführungs API als Nebenprodukt bauen.

**T-084 Abnahme** Untrusted Daten erhalten weder Produktionssignierschlüssel noch direkten Zugriff auf Analysehosts; LLM Vorschläge führen nie selbstständig zu Löschung oder Blockade.

### P13 Benutzeroberfläche nach Referenz fertigstellen

Ziel Die dunkle AXSafe Oberfläche mit echten Daten und verständlichen Zuständen vervollständigen.

Ergebnis WPF Desktop App, Navigation, Dashboard, Scanansichten, Quarantäne und Fehlerzustände

Gate Jeder aktive Schalter hat eine getestete Wirkung; UI und Dienst stimmen bei Ausfall, Neustart und veralteten Daten überein.

**AXS-085 Referenzdesign aufnehmen**

Dunkelblaue Desktopoberfläche mit cyanblauen Akzenten linker Navigation Dashboard Mitte Schutzmodulen rechts und eigenem AXSafe Schild gestalten.

**T-085 Abnahme** Ansicht orientiert sich an Nutzerbild vom 24 Oktober 2026 und bleibt bei 125 bis 200 Prozent Skalierung bedienbar.

**AXS-086 Navigation vollständig anbinden**

Übersicht Virenscan Echtzeitschutz Ransomware Firewall und Netzwerk Web und Phishing Quarantäne Datenschutz Berichte Einstellungen und Hilfe als echte Ansichten umsetzen.

**T-086 Abnahme** Alle Ziele öffnen passende Inhalte; kein sichtbarer Hauptbutton endet ohne Aktion oder Erklärung.

**AXS-087 Dashboard mit echten Daten füllen**

Schutzbanner Module Scanstatistik Updatezeit Aktivitätsdiagramm Scan Center letzte Funde und Live Ereignisse aus dem Dienst beziehen.

**T-087 Abnahme** Keine festen Beispielzähler in Produktion; Sensor oder Cloudausfall veraltete Regeln und fehlender Primärschutz ändern Banner und Modulzustände.

**AXS-088 Scan und Fundabläufe gestalten**

Fortschritt Abbruch Teilresultate Erkennungsdetails Quarantäne Restore Fehlalarm und Neustartbedarf verständlich darstellen.

**T-088 Abnahme** Nutzer kann einen Scan starten einen Fehler verstehen und einen Fund kontrolliert behandeln ohne unbeabsichtigte destructive Aktion.

**AXS-089 Modulschalter ehrlich machen**

Schalter benötigen Capability Prüfung Berechtigungen Rückmeldung und bestätigten Dienstzustand; nicht vorhandene Funktion sichtbar deaktivieren.

**T-089 Abnahme** Fehlgeschlagene Umschaltung springt zum tatsächlichen Zustand zurück; Demo oder Laborbetrieb bleibt dauerhaft markiert.

**AXS-090 Bedienbarkeit und Datenschutz sichern**

Deutsch Tastaturbedienung Screenreader Kontrast Status ohne reine Farbcodes ruhige Benachrichtigungen und minimale Diagnoseexporte vorsehen.

**T-090 Abnahme** Bedientest mit Tastatur Skalierung und Fehlerzuständen besteht; keine überflüssigen Konten oder Uploads sind zum lokalen Scan nötig.

### P14 Gesamtschutz und Zuverlässigkeit nachweisen

Ziel Schutzwirkung, Fehlalarme, Systemverträglichkeit und Betriebsstabilität getrennt bewerten.

Ergebnis Funktions und Schutzberichte, Leistungsdaten, Fuzzing Befunde, externer Review und Abdeckungsmatrix

Gate Alle V1 Pflichtnachweise liegen vor; kritische Fehler und nicht belegte Schutzversprechen blockieren die Freigabe.

**AXS-091 Funktionsnachweise getrennt führen**

EICAR AMTSO Integrationstests und echte Schutztests getrennt auswerten; Simulationsbelege nicht als Malware Wirksamkeitsquote ausgeben.

**T-091 Abnahme** Bericht nennt Testart Korpus Datum Version OS Einstellung Onlinezustand und Zuordnung zur konkreten AXSafe Komponente.

**AXS-092 Schutzwirkung messen**

Prävention Erkennung Eindämmung Reparatur und Schaden getrennt anhand zeitlich aktueller rechtmäßig beschaffter Fälle testen; unabhängigen Testweg planen.

**T-092 Abnahme** Recall Fehlalarme verpasste Fälle Latenzen und Schadensumfang sind transparent; keine Bestenliste aus unterschiedlichen Testbedingungen.

**AXS-093 Fehlalarme ernst nehmen**

Großen repräsentativen sauberen Korpus mit Windows Office Browsern Spielen Entwicklertools Backups und eigener Zielsoftware testen.

**T-093 Abnahme** Kein destruktiver Fehlalarm auf kritischen Systemdateien; Regeln und Modelle mit unvertretbarer Fehlalarmrate werden zurückgenommen.

**AXS-094 Leistung und Kompatibilität messen**

Leerlauf Scan Boot Dateioperationen Programminstallationen Spiele VM Betrieb SMB OneDrive und Updates gegen dokumentierte Baseline vergleichen.

**T-094 Abnahme** Perzentile CPU RAM Datenträgerlast und Ausreißer sind berichtet; vorab vereinbarte Budgets sind erfüllt oder Freigabe bleibt offen.

**AXS-095 Ausfälle und Angriffe gegen AXSafe testen**

Parser IPC Updateformate Quarantäne und Treiber fuzzingorientiert prüfen; Stromausfall voller Datenträger Offlinezustand Überlast und Schlüsselkompromittierung erproben.

**T-095 Abnahme** Keine offenen kritischen Sicherheits oder Datenverlustfehler; Treiberprüfung Langzeittest und Recoverybericht liegen vor.

**AXS-096 Externen Review und Abdeckung abschließen**

Unabhängige Sicherheitsprüfung und geeignete Labortests vorbereiten; Anforderungen mit Code Test Ergebnis offenen Punkten und Produktversprechen verknüpfen.

**T-096 Abnahme** Alle verpflichtenden Anforderungen sind mit echten Belegen bestanden; externe fehlende Freigaben werden nicht durch interne Mocks ersetzt.

### P15 Veröffentlichen und dauerhaft betreiben

Ziel Ein betreubares Produkt mit signierter Auslieferung, Support und Schwachstellenmanagement freigeben.

Ergebnis Releasepaket, Betriebsanleitung, Supportprozess, Notfallplan und dokumentierter Supportzeitraum

Gate Releasecheckliste vollständig, Rollback geprobt, Meldewege einsatzbereit, rechtliche und lizenzbezogene Prüfungen abgeschlossen.

**AXS-097 Signiertes Release paketieren**

Installations Upgrade und Deinstallationspakete Signaturen SBOM Lizenztexte Prüfsummen bekannte Grenzen und Wiederherstellungsanleitung bereitstellen.

**T-097 Abnahme** Saubere Installation Upgrade und autorisierter Ausbau auf der Zielmatrix bestehen; Produktpaket enthält keine Forschungssamples.

**AXS-098 Verantwortlichen Betrieb etablieren**

Support Fehlalarmannahme Schwachstellenkoordination Security Kontakt Incident Verfahren Backup Restore Monitoring und Updatebereitschaft organisieren.

**T-098 Abnahme** Probe eines kritischen Fehlalarms und kompromittierten Updates erreicht zuständige Personen und funktioniert auch bei Cloudausfall.

**AXS-099 Markt und Datenschutzfreigabe abschließen**

CRA Pflichten Konformitätsweg Datenschutzinformationen Auftragsverarbeitung Drittlandtransfers Supportdauer Namensrechte und Open Source Pflichten vor Vertrieb prüfen.

**T-099 Abnahme** Freigabeakte und gültige Unterlagen liegen vor; öffentlich genutzte Siegel entsprechen tatsächlich erlangten Prüfungen.

**AXS-100 V1 nur mit Abnahme freigeben**

V1 bleibt bei fehlenden Pflichtnachweisen unveröffentlicht oder eindeutig als begrenzte Vorversion gekennzeichnet; Umfang nicht stillschweigend reduzieren.

**T-100 Abnahme** Releasecheckliste nennt erfüllte Ziele Grenzen offene Risiken Versionen und Freigabeverantwortung; kein geplanter Punkt wird als implementiert verkauft.

## Arbeitsprotokoll und Abschlussbedingungen

Führe Requirements Matrix Capability Matrix Threat Matrix Testmatrix ADRs Blockerregister und Releasecheckliste im Repository. Jeder Eintrag nennt Status Code oder Dokumentpfad Testkennung Beleg Restrisiko und nächste Arbeit. Plane Tests mit Ausgangszustand Eingabe Erwartung tatsächlichem Ergebnis Version und Umgebung. Verwende keine Erfolgsmeldung ohne ausgeführten Nachweis. Auf einem Linux Host nicht verfügbare Windows Integrationstests ausdrücklich offen halten und einen ausführbaren Windows Testweg vorbereiten.

Beginne mit P00 und P01. Prüfe Repository vorhandenen Code Umgebung und Zielplattform. Erstelle oder aktualisiere die genannten Arbeitsdateien dokumentiere verifizierte Fakten und Annahmen und setze den ersten ungefährlichen überprüfbaren vertikalen Pfad um. Springe nicht direkt zur Behauptung vollständiger Echtzeitprotektion. Bevorzuge kleine funktionierende Schritte; halte die vollständige V1 Zieldefinition aufrecht.

Nach jedem Arbeitsschritt berichte knapp was geändert wurde warum wie geprüft wurde und was offen bleibt. Beim Erreichen einer Grenze lege einen reproduzierbaren Fehlerbericht und den nächsten konkreten Schritt an. Kein stillschweigendes Streichen kein falscher Fertigstatus und keine automatische Verlagerung harter Anforderungen auf V2.

V1 darf erst freigegeben werden wenn die verpflichtenden Nachweise des angegebenen Umfangs bestanden die rechtlichen und lizenzbezogenen Voraussetzungen geklärt und Betrieb Support Update und Recovery einsatzbereit sind. Fehlende eigene Forschungsmodelle dürfen deaktiviert bleiben wenn keine entsprechende Produktfunktion behauptet wird; die Forschungsbewertung selbst wird trotzdem durchgeführt. Plattform und Firmwaregrenzen werden ehrlich ausgewiesen. Ohne dies bleibt der Stand eine klar benannte Vorversion oder ein ergänzender Scanner.

Referenzstand 24 Oktober 2026. Spezifikation Revision 1.0 SHA256 7ef3d464b593f5e67b72cbd3839d68524d2867b1bc21529fa18c33af0e3d209d. Die 16 Phasen 100 AXS Kennungen und 100 T Kennungen sind deckungsgleich mit AXSafe_V1_Plan.md. Ändere die Spezifikation nur mit dokumentierter Begründung und synchronisiere danach Plan Prompt und Abnahmen.

## Geprüfte Ausgangsquellen

Aktuelle Regeln APIs Lizenzen und gesetzliche Pflichten vor der abhängigen Implementierung erneut anhand primärer Quellen prüfen. Die Recherche beschreibt keinen Zugang zu geheimen Herstellerinternas. Prüfergebnisse anderer Produkte sind keine Ergebnisse von AXSafe.

- Q01 Windows 10 release information: https://learn.microsoft.com/en-us/windows/release-health/release-information
- Q02 LTSC 2021 Supportende: https://techcommunity.microsoft.com/blog/windows-itpro-blog/plan-for-windows-10-enterprise-ltsc-2021-end-of-support/4539866
- Q03 .NET 10 unterstützte Betriebssysteme: https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md
- Q04 Microsoft Defender Erkennungsschichten: https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav
- Q05 Bitdefender OEM und Endpoint SDKs: https://www.bitdefender.com/en-us/oem/endpoint-protection
- Q06 ESET Schutztechnologien: https://www.eset.com/me/about/technology/
- Q07 Sophos technische Schutzrichtlinie: https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/EndpointProtection/ThreatProtectionPolicy/
- Q08 SentinelOne statische und Verhaltensmodelle: https://www.sentinelone.com/platform/singularity-complete/
- Q09 SentinelOne Ereigniskorrelation: https://www.sentinelone.com/platform/endpoint-protection-platform/
- Q10 Kaspersky System Watcher und Grenzen des Rollbacks: https://support.kaspersky.com/help/Kaspersky/Win21.7/en-US/68174.htm
- Q11 AV Comparatives Malware Protection Methodik: https://av-comparatives.org/tests/malware-protection-test-september-2026/
- Q12 AV Comparatives Real World Protection Methodik: https://av-comparatives.org/tests/real-world-protection-test-february-may-2026/
- Q13 AV TEST Testverfahren: https://www.av-test.org/en/about-the-institute/test-procedures/
- Q14 AMTSO Funktionsprüfungen: https://www.amtso.org/security-features-check/
- Q15 EICAR Testdatei: https://www.eicar.org/download-anti-malware-testfile/
- Q16 MITRE ATTACK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- Q17 ClamAV Fähigkeiten und Plattformgrenzen: https://docs.clamav.net/
- Q18 ClamAV Quellcode und Lizenz: https://github.com/Cisco-Talos/clamav
- Q19 ClamAV Scannen und fehlende TCP Authentifizierung: https://docs.clamav.net/manual/Usage/Scanning.html
- Q20 ClamAV Signaturdatenbanken: https://docs.clamav.net/faq/faq-cvd.html
- Q21 ClamAV Konfiguration und FreshClam: https://docs.clamav.net/manual/Usage/Configuration.html
- Q22 YARA X Funktionen und Lizenz: https://github.com/VirusTotal/yara-x
- Q23 VirusTotal API Nutzungsgrenzen: https://docs.virustotal.com/reference/getting-started
- Q24 VirusTotal Weitergabe hochgeladener Dateien: https://docs.virustotal.com/docs/how-it-works
- Q25 Windows Dateisystem Minifilter: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers
- Q26 Microsoft Minifilter Beispiele: https://learn.microsoft.com/en-us/windows-hardware/drivers/samples/file-system-driver-samples
- Q27 Dateiscan und Synchronisierung im Minifilter: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatesectionfordatascan
- Q28 Minifilter Altitude beantragen: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request
- Q29 Windows Treibersignierung Voraussetzungen: https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs
- Q30 AMSI Aufrufer und Provider: https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal?WT.mc_id=DT-MVP-5003978
- Q31 Geschützte Antimalware Dienste und ELAM: https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- Q32 Microsoft Defender Betriebsmodi: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows
- Q33 Windows Filtering Platform: https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform
- Q34 Microsoft Regeln gegen verwundbare Treiber: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Q35 Treiber Blockliste und Unterschiede Windows 10 und 11: https://support.microsoft.com/en-us/servicing/os/windows/2022/10/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release
- Q36 The Update Framework: https://theupdateframework.io/overview/
- Q37 NIST Secure Software Development Framework: https://csrc.nist.gov/pubs/sp/800/218/final
- Q38 SLSA Lieferkettensicherheit: https://slsa.dev/spec/v1.2/about
- Q39 NIST Adversarial Machine Learning: https://csrc.nist.gov/pubs/ai/100/2/e2025/final
- Q40 EMBER2024 Datensatz und zeitliche Aufteilung: https://github.com/FutureComputing4AI/EMBER2024
- Q41 SOREL 20M Datensatz und Nutzungsbedingungen: https://registry.opendata.aws/sorel-20m/
- Q42 NIST Firmware Resilienz: https://csrc.nist.gov/pubs/sp/800/193/final
- Q43 Apple System Extensions und Endpoint Security: https://developer.apple.com/system-extensions/
- Q44 Apple Platform Security und iOS Sandbox: https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf
- Q45 Android Scoped Storage: https://developer.android.com/about/versions/11/privacy/storage
- Q46 Linux fanotify: https://man7.org/linux/man-pages/man7/fanotify.7.html
- Q47 EU Kommission Cyber Resilience Act: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- Q48 EU Kommission Konformitätsbewertung für Antivirus: https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment
- Q49 CRA Rechtsakt und Anhang III Fundstelle: https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ%3AL_202402847
- Q50 BfDI Empfehlungen für Telemetrie: https://www.bfdi.bund.de/SharedDocs/Pressemitteilungen/DE/2023/17-Berlin-Group-Telemetrie.html
- Q51 BfDI Grundlagen des Datenschutzrechts: https://www.bfdi.bund.de/DE/Buerger/Inhalte/Allgemein/Datenschutz/GrundlagenDatenschutzrecht.html
- Q52 OASIS STIX und TAXII: https://oasis-open.github.io/cti-documentation/faq.html
- Q53 CAPE Sandbox Architektur: https://capev2.readthedocs.io/en/latest/installation/
- Q54 CAPE isoliertes Labornetz: https://capev2.readthedocs.io/en/latest/installation/guest/network.html
- Q55 Microsoft Virus Initiative Aufnahmebedingungen: https://learn.microsoft.com/en-us/unified-secops/virus-initiative-criteria
- Q56 Windows Endpoint Security Platform Vorschau: https://news.microsoft.com/ignite-2025-book-of-news/
- Q57 ReadDirectoryChangesW Ereignisverlust: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw
- Q58 Google Project Zero Minifilter Fehleranalyse: https://projectzero.google/2021/01/hunting-for-bugs-in-windows-mini-filter.html
- Q59 CrowdStrike Root Cause Analysis Channel File 291: https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf
- Q60 ENISA Single Reporting Platform und CRA Meldepflichten: https://www.enisa.europa.eu/topics/product-security/vulnerability-services/eu-incident-response-and-cyber-crisis-management/single-reporting-platform-srp
