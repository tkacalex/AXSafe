# AXSafe V1 Recherche und Produktkonzept

Stand 24 Oktober 2026

AXSafe soll ein eigener mehrschichtiger Schutz für Windows werden. Dieses Konzept führt von den Grundlagen über die Arbeitsweise etablierter Anbieter bis zu Architektur, Prüfung und Betrieb. Am Ende steht ein verbindlicher Entwicklungsplan. Ein gesonderter Masterprompt enthält dieselben Phasen und Anforderungen für die Umsetzung.

Die wichtigste Entscheidung lautet: AXSafe wird zuerst für dein Windows 10 Enterprise LTSC 2021 entwickelt. Ein früher Dateiscanner ist ein sinnvoller Zwischenstand. Als fertige V1 darf er erst gelten, wenn auch die zugesagten Schutzschichten und ihre Abnahmen tatsächlich funktionieren. Die Regel, schwierige Punkte nicht zu überspringen, wird durch ein Anforderungsregister mit 100 Punkten, Tests und Freigabesperren umgesetzt.

Eine Garantie gegen jede vorhandene und zukünftige Schadsoftware ist technisch nicht seriös. Vollständigkeit bedeutet hier, die wesentlichen Aufgaben, Abhängigkeiten und bekannten Grenzen im gewählten Produktumfang abzudecken. Es bedeutet keinen mathematischen Beweis, dass ein Rechner niemals kompromittiert werden kann.

## 1 Ausgangslage und verbindliche Entscheidungen

Dein Screenshot zeigt Windows 10 Enterprise LTSC, Version 21H2, OS Build 19044.7807. Microsoft ordnet die Buildfamilie 19044 LTSC 2021 zu; die veröffentlichte Releaseübersicht nennt auch diesen konkreten Build. Für Windows 10 Enterprise LTSC 2021 nennt Microsoft den 12 Januar 2027 als reguläres Supportende. Die länger unterstützte IoT Edition ist ein anderes Produkt. Aus deinem Screenshot lässt sich deren Einsatz nicht ableiten. [Q01, Q02]

Die Prozessorarchitektur und Hardwareausstattung sind im Screenshot nicht erkennbar. Für den Entwurf gilt x64 als Annahme. Vor der Umsetzung muss das Zielgerät diese Annahme bestätigen. Auch ein x64 Antivirus muss unter anderem 32 Bit Programme und passende Skripthosts prüfen können.

Windows 11 wird als zusätzliche Testplattform eingeplant. Windows 10 Home, Pro, andere LTSC Versionen, ARM64 und x86 als Betriebssystemarchitektur erhalten keine automatische Freigabe. Für jede Kombination braucht es eine eigene Supportentscheidung. Ein Programm, das auf einer Version startet, ist dort noch nicht als Schutzprodukt geprüft.

Microsoft führt Windows 10 21H2 Enterprise LTSC in der Unterstützungsmatrix von .NET 10. Deshalb eignet sich eine native WPF Oberfläche mit .NET 10 als Ausgangspunkt. Diese Unterstützung ist an die jeweils geltenden Betriebssystem und Runtime Lebenszyklen gebunden. Vor längerem Produktbetrieb muss die Plattformstrategie erneut geprüft werden. [Q03]

| Entscheidung | Festlegung für den Entwurf |
| --- | --- |
| Produkt | AXSafe V1 als eigener Windows Endpoint Schutz |
| Hauptziel | Windows 10 Enterprise LTSC 2021 21H2 Buildfamilie 19044 |
| Architektur | x64 geplant und auf dem Gerät noch zu bestätigen |
| Oberfläche | Deutsche Desktop App nach deiner dunklen blauen Referenz |
| Schutzkern | Eigene Policies Sensorik Quarantäne Updates und Korrelation mit austauschbaren Engines |
| Einstieg | Open Source zuerst mit ClamAV und YARA X nach Lizenzprüfung |
| Alternative | Kommerzieller OEM Baustein nur nach fachlichem und vertraglichem Vergleich |
| Cloud | Ergänzung mit konkreter Freigabe für Inhaltsuploads und funktionsfähigem Offlinebetrieb |
| Frühphase | Ergänzender Scanner bei weiter aktivem etabliertem Primärschutz |
| V1 Freigabe | Erst nach allen verpflichtenden Funktions Sicherheits und Betriebsnachweisen |

## 2 Was ein Antivirus leisten kann

Ein Computervirus ist eine bestimmte Art von Schadsoftware, die sich an andere Objekte anhängt und darüber verbreitet. Im Alltag meint Antivirus meistens einen Schutz gegen viele Schadsoftwarearten. Für AXSafe ist deshalb der Begriff mehrschichtiger Endpoint Schutz genauer.

Drei Aufgaben müssen getrennt betrachtet werden. Prävention verhindert eine gefährliche Handlung. Erkennung stellt verdächtige oder schädliche Aktivität fest. Reaktion begrenzt den Schaden und unterstützt die Bereinigung. Eine Meldung nach dem Diebstahl von Zugangsdaten ist keine nachträgliche Verhinderung des Diebstahls.

EPP bezeichnet den Schutz auf dem Endgerät. EDR ergänzt Ereignisaufzeichnung, Untersuchung und Reaktion. XDR verbindet weitere Datenquellen wie Identität oder E Mail Infrastruktur. AXSafe V1 benötigt einen belastbaren EPP Kern und eine nachvollziehbare lokale Ereigniszeitleiste. Eine organisationsweite XDR Plattform gehört nicht automatisch zu einer einzelnen Desktop App.

MITRE ATTACK beschreibt beobachtete Vorgehensweisen von Angreifern und eignet sich zur Strukturierung der Abdeckung. Es ist keine vollständige Liste aller Schadprogramme und keine Zertifizierung. AXSafe muss konkrete Techniken, Datenquellen und Tests zuordnen, statt nur einen ATTACK Schriftzug auf das Dashboard zu setzen. [Q16]

## 3 Welche Bedrohungen berücksichtigt werden

Die folgende Matrix ist ein Arbeitsmodell für AXSafe. Sie fasst Schutzansätze zusammen und nennt die Grenze, die bei einer späteren Produktbehauptung sichtbar bleiben muss. Verwandte Klassen überschneiden sich. Eine einzelne Familie kann mehrere Zeilen betreffen.

| Bedrohung | Erforderliche Schichten | Wichtige Grenze |
| --- | --- | --- |
| Klassische Dateiviren und File Infector | Inhaltsprüfung generische Signaturen Dateiintegrität Reparatur | Eine infizierte legitime Datei lässt sich nicht immer verlustfrei desinfizieren |
| Würmer | Datei Netzwerk Ausführung und Persistenz gemeinsam betrachten | Ungepatchte Netzwerkdienste bleiben ein eigenständiges Risiko |
| Trojaner und Backdoors | Dateibewertung Verhalten Herkunft und Netzwerk | Ein legitimer Programmname oder gültiger Signer beweist keine Harmlosigkeit |
| RAT und missbrauchte Fernwartung | Prozesskontext Persistenz Fernsteuerung und Verbindungen | Legitime Fernwartung darf nicht pauschal als Malware gelten |
| Dropper Loader und Downloader | Prozessbaum Downloadfolge nachgeladene Dateien | Nur die erste Datei zu prüfen reicht für mehrstufige Angriffe nicht |
| Ransomware | Früherkennung Schreibkontrolle Prozesskorrelation Versionen | Schon vor der Erkennung kann Schaden entstehen |
| Wiper und Massenlöschung | Schutz wichtiger Schreib und Löschvorgänge Recovery | Wiederherstellung braucht vorhandene Originaldaten |
| Infostealer Keylogger und Spyware | Verhalten sensible Zugriffe Netzwerk und Speicher | Bereits offengelegte Geheimnisse müssen außerhalb der App ersetzt werden |
| Banking Trojaner | Browser und Prozesskontext Skripte Web Reputation | Getäuschte Nutzer und freigegebene Zahlungen sind nicht vollständig technisch erkennbar |
| Botnetze und C2 | Kontextbezogene Netzwerkindikatoren und Verhalten | Gemeinsam genutzte Cloudinfrastruktur erschwert pauschale Sperren |
| Cryptominer | Herkunft Ausführung Persistenz Ressourcen und Kommunikation | Hohe CPU oder GPU Last allein beweist keinen Schadcode |
| Skript und Makromalware | AMSI Dateiregeln Dokumentanalyse Verhalten | Nur tatsächlich angebundene Hosts liefern AMSI Inhalte |
| Schädliche PDF Office und andere Dokumente | Sichere Parser eingebettete Inhalte Exploitmuster | Unbekannte Formate und nicht sichtbare verschlüsselte Inhalte bleiben teilweise ungeprüft |
| Dateilose und speicherbasierte Angriffe | AMSI Ereigniskorrelation gezielte Speicheranalyse | Ein Dateiscanner erfasst nicht jeden ausgeführten Inhalt |
| Living off the Land | Sequenzen Rollen Kontext und Aktionen bewerten | PowerShell oder Systemwerkzeuge sind nicht grundsätzlich schädlich |
| Injection Hollowing und manipulierte Module | Prozess und Speicherindikatoren dokumentierte Durchsetzung | Geschützte Prozesse und Sensorlücken begrenzen die Sicht |
| Rootkits und schädliche Treiber | Signaturen Treiberinventar OS Integrität Offlineanalyse | Ein bereits kompromittierter Kernel kann seinen eigenen Prüfer täuschen |
| BYOVD | Regeln gegen bekannte verwundbare Treiber und Integritätszustand | Auch ein regulär signierter Treiber kann verwundbar sein |
| Bootkits UEFI und Gerätefirmware | Secure Boot Status Herstellermechanismen begrenzte Integritätsprüfung | Kein allgemeiner Firmware Reinheitsbeweis aus einer Windows App |
| Polymorphe metamorphe gepackte Malware | Generische Muster Emulation Verhalten und Speicher | Entropie oder Packing allein rechtfertigen keine Löschung |
| Exploits und bislang unbekannte Schwachstellen | Updates Angriffsflächenreduktion Exploitindikatoren Verhalten | Zero Day Schutz ist keine Garantie gegen jede neue Sicherheitslücke |
| PUA Adware und unerwünschte Installer | Gesonderte Klassifizierung transparente Policy | Unerwünscht und eindeutig schädlich sind verschiedene Bewertungen |
| Schädliche Browsererweiterungen | Herkunft Rechte unterstützte Browserintegration | AXSafe darf keine vollständige Kontrolle über jeden Browser behaupten |
| Manipulierte Updates und Lieferketten | Signaturprüfung Herkunft Verhalten sichere eigene Lieferkette | Ein bekanntes Herstellerzertifikat ersetzt keine Inhalts und Verhaltensbewertung |
| Paket und Entwicklerangriffe | Downloads Archive Skripte Installationsfolgen | Ein vollständiger Quellcode Audit aller Abhängigkeiten ist ein eigener Dienst |
| LNK MSI ISO VHD und eingebettete Inhalte | Typ nach Inhalt Container und Ausführungsfolge prüfen | Formaterkennung muss die tatsächliche Enginefähigkeit berücksichtigen |
| Phishing und betrügerische Webseiten | Browseranbindung Reputation Warnungen | Nicht jede betrügerische Handlung benötigt Schadsoftware |
| BEC MFA Täuschung Kontodiebstahl | Warnung Websignale gegebenenfalls externe Identitätsdaten | Ein lokaler Antivirus ersetzt keine Identitätssicherheit |
| Schädliche E Mail Anhänge | Download oder lokale Anhangprüfung Client oder Gateway Anbindung | Ohne Integration ist kein vollständiger Postfachschutz vorhanden |
| USB Malware | Dateiprüfung und getestete Zugriffskontrolle | BadUSB als Tastatur oder Firmwareangriff ist eine andere Angriffsklasse |
| Netzwerk und Remote Angriffe | Firewall Prozessverbindungen OS Patches | Eine Dateisignatur allein verhindert keinen Dienstexploit |
| Manipulation von AXSafe | Rechte Signaturen Selbstschutz Update und Brokerhärtung | Admin und Kernelgegner sind stärker als ein normaler Benutzer |
| Angriffe auf Modelle und Analyse | Datenherkunft Modelltests Isolation Freigabe | Mehr KI bedeutet nicht automatisch mehr Schutz |

Für jede Zeile werden konkrete, ungefährliche Funktionssimulationen und gutartige Gegenbeispiele festgelegt. Aktuelle echte Malwarefälle werden nur in einem geeigneten getrennten Labor und bei rechtmäßigem Zugriff geprüft. Eine feste Zahl von Familien ist kein sinnvolles Vollständigkeitskriterium; die Matrix muss mit neuen Erkenntnissen weitergeführt werden.

## 4 Wie etablierte Anbieter technisch arbeiten

Die Auswahl deckt unterschiedliche öffentlich dokumentierte Ansätze ab. Sie ist weder eine Rangliste nach Unternehmensgröße noch die Behauptung, dass diese Produkte jeden Angriff verhindern. Herstellerquellen beschreiben ihre eigene Technik und sind keine unabhängige Bestätigung jeder Werbeaussage. Proprietäre Modelle, komplette Signaturbestände und interne Betriebsabläufe sind öffentlich nicht vollständig verfügbar.

| Anbieter | Öffentlich dokumentierter Ansatz | Folgerung für AXSafe |
| --- | --- | --- |
| Microsoft | Verbindet lokale und cloudgestützte Modelle mit Verhalten Speicher AMSI Emulation und Reputation [Q04] | Mehrere spezialisierte Schichten benötigen gemeinsame Ergebnis und Versionsverträge |
| Bitdefender | Bietet unterschiedliche OEM SDKs für Antimalware Verhalten und weitere Schutzfunktionen sowie umfassendere Endpoint Bausteine [Q05] | Eigene App und eigene Engine sind verschiedene Geschäftsentscheidungen |
| ESET | Beschreibt unter anderem Speicherprüfung Exploit Blocker Ransomware Schutz und eine eigene leichte Analyseumgebung [Q06] | Verschleierung und mehrstufige Angriffe brauchen zusätzliche Sicht zur Datei |
| Sophos | Dokumentiert Laufzeitschutz Skriptprüfung Exploit und Ransomware Funktionen sowie Ereignisjournale [Q07] | Schutzwirkung und Untersuchbarkeit müssen zusammen geplant werden |
| SentinelOne | Beschreibt statische und Verhaltensmodelle sowie die Korrelation zusammengehöriger Ereignisse über Storyline [Q08, Q09] | Zusammenhängende Vorfälle sind hilfreicher als viele isolierte Warnungen |
| CrowdStrike | Dokumentiert im technischen Vorfallbericht lokale Sensorkorrelation und aus der Cloud gelieferte Erkennungsinhalte [Q59] | Neue Regeln brauchen ebenso harte Zuverlässigkeitsprüfungen wie Programmcode |
| Kaspersky | Beschreibt in einer älteren System Watcher Dokumentation Verhaltensaufzeichnung und begrenzte Rücknahme von Änderungen [Q10] | Reparatur und Rollback müssen präzise begrenzt und getestet sein |

Die verwendete Kaspersky Quelle erklärt einen historischen technischen Mechanismus. Daraus folgt keine aktuelle Produktempfehlung, Lizenzverfügbarkeit oder Aussage über die heutige konkrete Produktversion.

Aus den Dokumentationen lässt sich für AXSafe ein gemeinsames Muster ableiten: Ereignisse erfassen, schnell lokal bewerten, unsichere Fälle vertiefen, gezielt reagieren und Erkenntnisse kontrolliert aktualisieren. Das ist eine technische Ableitung aus den Quellen. Welche konkrete Reihenfolge, Gewichtung und Datenmenge ein Hersteller intern nutzt, ist damit nicht vollständig bekannt.

## 5 Was hinter dem sichtbaren Programm liegt

Ein tragfähiger Anbieter benötigt mehr als Entwickler für eine Oberfläche. Für AXSafe sind mindestens folgende Verantwortungen einzuplanen: Windows Integration, sichere Parser und Engineanbindung, Malware und Verhaltensanalyse, Testautomatisierung, Fehlalarmbearbeitung, Updatebetrieb, Produktsicherheit, Datenschutz sowie Support. Eine Person kann am Anfang mehrere Rollen übernehmen. Dadurch verschwinden diese Aufgaben nicht.

Ein sinnvoller Arbeitsablauf für neue Erkenntnisse ist: rechtmäßig erfassten Hinweis aufnehmen, Herkunft und Duplikate prüfen, in isolierter Umgebung analysieren, Befund mit gutartigen Beispielen abgleichen, neue Erkennung versionieren, Regressionen prüfen und erst danach kontrolliert verteilen. Nach der Verteilung werden Schutzwirkung und mögliche Fehlalarme beobachtet. Eine fehlerhafte Regel braucht einen ebenso schnellen Rücknahmeweg.

Für den Regelbetrieb werden Warteschlangen, Berechtigungen, Fristen, Verantwortliche und Aufbewahrung benötigt. Hinweise auf mögliche neue Malware, bekannte Fehlalarme und Schwachstellen in AXSafe sind getrennte Vorgänge. Ein Meldungskanal ohne Zuständigkeit ist noch kein funktionierender Support.

Der entscheidende Lernpunkt aus dem CrowdStrike Vorfall vom Juli 2024 ist nicht, dass ein einzelner Hersteller grundsätzlich ungeeignet wäre. Sein technischer Bericht zeigt, dass auch Erkennungsinhalte einen gefährlichen Ausführungspfad erreichen können. Für AXSafe folgen daraus begrenzte Interpreter, harte Schema und Grenzprüfungen, Fuzzing, Pilotverteilung sowie getestete Recovery. Die konkreten AXSafe Maßnahmen sind eine eigene Designentscheidung. [Q59]

## 6 Eigene Engine oder vorhandene Bausteine

| Weg | Vorteile | Kosten und Grenzen |
| --- | --- | --- |
| Alles selbst entwickeln | Volle Kontrolle über Daten Erkennung und Technik | Sehr hoher Forschungsaufwand eigener Bestand aktueller Fälle Parser und dauerhafte Pflege nötig |
| Open Source kombinieren | Verständlicher Einstieg überprüfbarer Code und echte lokale Erkennung | Lizenzpflichten Qualität und Fähigkeiten müssen selbst geprüft werden kein fertiger Windows Gesamtschutz |
| Kommerzielles SDK lizenzieren | Bewährte Bausteine und eventuell umfangreichere Sensorik | Angebot Vertrag Integration Datenrechte Supportabhängigkeit und laufende Gebühren |
| Fertiges OEM Endpoint Produkt anpassen | Kann Teile der Systemintegration und Schutzpipeline abdecken | Starke Anbieterbindung Produktverantwortung und eigene Prüfung bleiben bestehen |

Empfohlen ist ein eigener modularer AXSafe Kern mit austauschbaren Engineadaptern. ClamAV kann zunächst eine reale Inhaltsprüfung liefern. YARA X ergänzt eigene nachvollziehbare Regeln. Eigene Sensorik, Verhalten, Updatevertrauen und Quarantäne bilden den AXSafe Anteil. Ein optionaler kommerzieller Adapter wird nur nach Vergleich und Vertragsprüfung aktiviert. Das ist eine Entwicklungsstrategie, keine Behauptung über gleiche Schutzwirkung wie ein etablierter Anbieter.

ClamAV dokumentiert seine eigene On Access Funktion für Linux. Eine Windows Einbindung von ClamAV liefert deshalb nicht automatisch Windows Echtzeitschutz. ClamAV steht unter GPLv2. Für ein vertriebenes Produkt sind die konkrete Integration, Weitergabe und Quellcodepflichten zu prüfen; ein separater Prozess ist keine pauschale rechtliche Freistellung. [Q17, Q18]

YARA X ist ein in Rust geschriebenes Musterwerkzeug unter BSD 3 Clause. Es liefert eine Regelengine, keine fertige Datenbasis für alle Angriffe und keine automatische Windows Durchsetzung. Die Lizenzen verwendeter Regeln und Datensätze sind zusätzlich zur Werkzeuglizenz zu prüfen. [Q22]

Die VirusTotal API darf nicht als kostenloser Ersatz für die eigene Antivirus Engine eingeplant werden. Die offiziellen Bedingungen verbieten die öffentliche API unter anderem als Antivirus Ersatz und in kommerziellen Produkten. Hochgeladene Inhalte können mit Partnern und bestimmten Kunden geteilt werden. Für AXSafe ist ein eventueller rechtskonformer Analysezugriff getrennt vom laufenden Schutz zu behandeln; Verträge und Datenschutz sind vorher zu klären. [Q23, Q24]

Bei einem SDK Vergleich sind die Plattformen, Formate, Erkennungs und Reaktionsfunktionen, Offlinefähigkeit, Updates, Verteilrechte, Datenweitergabe, Signierung, Supportfristen und Kündigungsfolgen wichtiger als ein einzelner Werbewert. Öffentlich dokumentierte Bitdefender OEM Angebote zeigen, dass solche Bausteine existieren. Genaue Preise und Konditionen wurden nicht verifiziert und werden nicht erfunden. [Q05]

## 7 Architektur mit klaren Vertrauensgrenzen

Die Oberfläche läuft mit Benutzerrechten. Ein kleiner privilegierter Broker nimmt nur klar definierte Aufträge an. Scanworker lesen untrusted Inhalte mit reduzierten Rechten. Windows Sensoren liefern Ereignisse. Der minimale Treiber übernimmt ausschließlich die notwendigen Entscheidungen im Dateipfad. Ein optionales Backend ergänzt Reputation und freigegebene Analyse. Signierinfrastruktur und Sandbox liegen außerhalb des Clients.

| Komponente | Aufgabe | Sicherheitsgrenze |
| --- | --- | --- |
| AXSafe Desktop | Status Scans Funddetails Einstellungen | Kein dauerhaftes Administratorrecht und keine eigenen behaupteten Schutzwerte |
| AXSafe Broker | Rechteprüfung Auftragsvergabe Quarantäne | Kleine geprüfte API keine beliebigen Shell oder Dateibefehle |
| Scanworker | Dateiformate Regeln Engine und gegebenenfalls Modelle | Eingeschränkter Prozess ohne direkten Internetzugriff und ohne unnötige Schreibrechte |
| Sensor und Korrelation | Prozess Datei Registry Netzwerk und Zeitleiste | Begrenzt speichert keine unnötigen Geheimnisse meldet Datenverlust |
| Dateisystem Minifilter | Notwendige Zugriffskontrolle | Keine komplexen Parser oder aus der Cloud geladenen Interpreter im Kernel |
| Updatekomponente | Verifizieren Staging Aktivieren Wiederherstellen | Signatur Rollen Versionen und lokale Rechte getrennt prüfen |
| Backend | Optionale Reputation und freigegebene Aufträge | Geräteidentität Quoten Mandantentrennung und minimale Datenerfassung |
| Sandbox | Ausführung in isolierten Analyse VMs | Getrennte Daten Hosts Kontrollkanäle und vollständig zurücksetzbarer Zustand |
| Freigabe und Signierung | Prüfen und veröffentlichen | Kein Zugriff für untrusted Analysejobs und normale Pull Request Builds |

Vorgeschlagener Stack: Rust für Core Dienst CLI und Vertragstypen, C Sharp mit WPF und .NET 10 für die Oberfläche, kleine C oder C Plus Plus Komponenten für erforderliche Windows COM und WDK Integration. Python eignet sich für Forschung und Modelltraining im Labor. Der Desktop Schutz soll nicht von einer Python Entwicklungsumgebung auf dem Nutzergerät abhängen. Exakte Versionen werden zu Beginn geprüft und gepinnt.

Rust reduziert bestimmte Speicherfehler im eigenen sicheren Code, macht aber weder native Fremdbibliotheken noch FFI oder die Gesamtarchitektur automatisch sicher. Job Objects eingeschränkte Tokens ACLs Prozessmitigations und gegebenenfalls AppContainer sind Umsetzungsmöglichkeiten. Ihre tatsächliche Eignung muss mit den ausgewählten Engines auf LTSC getestet werden.

Lokale Kommunikation nutzt versionierte Named Pipes mit restriktiven ACLs Clientprüfung und Rollen. Es gibt keine offen erreichbare lokale Admin Web API. Scanaufträge sind typisiert. Eine Anfrage darf dem Dienst weder beliebige Löschziele noch Shellbefehle unterschieben. Dateiinhalte und Pfade werden nicht als vertrauenswürdige Befehle interpretiert.

## 8 Ergebnis und Ereignisvertrag

Ein Scanergebnis enthält mindestens Auftrags ID Dateiidentität Umfang Anfang und Ende Engine und Regelversionen Befunde Grenzen sowie Fehler. Ein Ereignis enthält UTC Zeit Quelle Prozessstartidentität Datei oder Netzwerkbezug Korrelations ID und verlorene Ereignisse. Die Oberfläche zeigt Uhrzeiten lokal an.

| Ergebnis | Bedeutung | Konsequenz |
| --- | --- | --- |
| Malicious | Genügend belegte schädliche Merkmale gemäß Policy | Unterstützte Blockierung oder Quarantäne |
| Suspicious | Auffälligkeit mit verbleibender Unsicherheit | Vertiefung Warnung oder begrenzte Aktion nach Policy |
| PUA | Potenziell unerwünscht gemäß gesonderter Regelung | Nutzer und Policyentscheidung transparent halten |
| NoDetection | Im angegebenen Umfang nichts erkannt | Kein Beweis vollständiger Harmlosigkeit |
| Unsupported | Format oder Pfad nicht unterstützt | Prüflücke ausweisen |
| Encrypted | Inhalt ohne Zugang nicht vollständig sichtbar | Ungeprüften Inhalt melden |
| AccessDenied | Berechtigung oder Sperre verhindert Prüfung | Nicht als sauber zählen |
| Timeout | Zeitbudget überschritten | Unvollständigen Status und Fehlerpolicy anwenden |
| Error | Engine Parser oder Infrastrukturfehler | Schutzstatus überprüfen und Fehler melden |
| ChangedDuringScan | Objekt wurde während der Prüfung verändert | Neu prüfen oder freigebende Entscheidung verwerfen |

Schweregrad, Konfidenz und endgültige Aktion sind getrennte Felder. Ein Modellwert von beispielsweise 0,9 ist ohne Kalibrierung keine nachgewiesene 90 Prozent Wahrscheinlichkeit einer Infektion. Herkunftssignatur, einzelne verdächtige Zeichenfolge, ungewöhnlicher Dateiname oder hohe Entropie reichen allein nicht als allgemeiner Löschbeweis.

In der frühen Entwicklungsphase kann ein vorhandener Defender eine Testdatei bereits entfernen. Dann muss der Testbericht sagen, welche AXSafe Komponente überhaupt zum Zuge kam. Schutz durch ein anderes Produkt darf nicht als AXSafe Eigenleistung gezählt werden.

## 9 Lokale Datei und Containerprüfung

Die Pipeline beginnt mit einer sicheren Dateireferenz und Inhaltsbestimmung. Danach folgen passende Engineprüfung, Regeln und belegte Heuristiken. Eine vertiefte Analyse wird nur bei Bedarf angefordert. Dateien werden nicht allein nach ihrer Endung ausgeschlossen.

Die Fähigkeitsmatrix erfasst mindestens PE32 PE64 .NET EXE DLL SYS Skripte Office PDF MSI LNK Archive sowie ISO oder andere relevante Container. Ein Parser pro Format wird nicht pauschal selbst neu geschrieben. Zuerst wird geprüft, welche Funktion die ausgewählte Engine tatsächlich und mit welchen Grenzen abdeckt. Fehlende Formate bleiben sichtbar offen.

Archive erfordern Limits für Verschachtelung, Anzahl Objekte, expandierte Datenmenge, Laufzeit und Speicher. Grenzwerte werden nach Tests festgelegt und versioniert. Passwortschutz, beschädigte Archive und überschrittene Limits erzeugen Teilresultate. Ein Container kann nicht als vollständig geprüft gelten, wenn ein Teil davon unzugänglich blieb.

Besonders relevant sind Unicode und lange Pfade, NTFS Alternate Data Streams, Reparsepoints, Junctions, Hardlinks, Symlinks, sparse Dateien, Netzlaufwerke, Wechselmedien und Cloud Platzhalter. Bei Cloud Platzhaltern darf ein Scan nicht unbemerkt riesige Datenmengen nachladen. Temporäre Parserausgaben dürfen keinen Pfadausbruch oder unbeabsichtigte Ausführung ermöglichen.

Ein Cache muss mit Dateiinhalt beziehungsweise gesicherter Dateiänderung sowie Engine Regel Modell und Policyversion zusammenpassen. Ein unzuverlässiger Cache kann aus einem erfolgreichen Scan eine spätere falsche Freigabe machen. Ein gleicher Pfad und unveränderte Dateigröße reichen dafür nicht aus.

Die ClamAV Dokumentation weist darauf hin, dass clamd auf TCP Verbindungen keine eigene Authentifizierung schützt. AXSafe eröffnet deshalb keine offen erreichbare clamd Schnittstelle. Für den Produktpfad wird ein isolierter Engineworker mit kontrollierter lokaler Schnittstelle bevorzugt. [Q19]

## 10 Echter Echtzeitschutz auf deinem Windows

Ein Dateiwatcher sieht Änderungen und kann Nachprüfungen auslösen. Er garantiert keine rechtzeitige Entscheidung vor Ausführung. Windows dokumentiert außerdem Pufferüberläufe und verlorene Änderungsinformationen, die eine erneute Aufzählung erfordern. Ein solcher Watcher ist für einen frühen Scanner brauchbar, aber kein vollständiger Ersatz für eine geprüfte Zugriffskontrolle. [Q57]

Windows Minifilter arbeiten im Dateisystempfad und können Dateioperationen beobachten oder beeinflussen. Microsoft stellt Scanner und AvScan Beispiele als Einstieg bereit. Diese Beispiele sind keine fertigen Antivirus Produkte. AXSafe benötigt zusätzlich richtige Zeitpunkte, sichere Kommunikation, korrekte Dateiidentität und eine umfassende Ausfallbehandlung. [Q25, Q26]

Das kritische Problem ist das Zeitfenster zwischen Prüfen und Verwenden. Wird nach dem Scan eine andere Datei unter denselben Namen geschoben oder der Inhalt verändert, ist das alte Ergebnis unbrauchbar. Daher braucht AXSafe eine geprüfte Verbindung zwischen Datei und Streamidentität, stabiler Lesesicht, Änderungszustand und Entscheidung. Microsoft dokumentiert für Minifilter unter anderem Mechanismen für synchronisierte Datenprüfung über Sections; das konkrete Design muss zum jeweiligen I O Pfad passen. [Q27]

Schwierige Fälle sind Memory Mapping, bereits geöffnete Dateien, Paging I O, ausführbare Sections, parallele Änderungen, Dateisystemtransaktionen, Netzpfade und andere Filter. Auch die richtige Reaktion auf Abbruch, Reentrancy und niedrigen Speicher gehört zur Kernaufgabe. Eine kurz funktionierende EXE Sperre beweist diese Fälle nicht.

Die Fehlerpolicy muss ausdrücklich festgelegt werden. Bekannt schädliche Objekte bleiben blockiert. Bei noch unbekanntem Inhalt und ausgefallenem Scanner sind Sicherheitsrisiko und Verfügbarkeit abzuwägen. Für den normalen Desktop wird ein begrenzter verfügbarkeitsorientierter Fehlerpfad vorgeschlagen, der den Schutz als eingeschränkt meldet; ein strengerer Modus braucht eigene Tests. Niemals darf der Kernel unbegrenzt auf eine Cloudantwort warten.

Für einen regulären Minifilter sind eine geeignete Altitude, ein zulässiger Signierweg und die jeweilige Hardware Dashboard beziehungsweise Zertifizierungsprüfung einzuplanen. Microsoft dokumentiert hierfür konkrete Voraussetzungen, darunter EV Zertifikatsanforderungen für relevante Einreichungen. Diese sind von der User Mode Codesignierung und einer möglichen MVI Mitgliedschaft zu unterscheiden. [Q28, Q29]

Auf dem Alltagsgerät werden weder Testsignierung noch das Abschalten von Secure Boot oder Speicherintegrität als normale Installationsvoraussetzung akzeptiert. Treiberexperimente finden in separaten VMs oder einem dafür vorgesehenen Laborgerät statt. Google Project Zero dokumentiert die zusätzliche Angriffsfläche von fehlerhaften Minifiltern; die Treiberschnittstelle ist deshalb selbst Gegenstand von Sicherheitsprüfungen. [Q58]

## 11 Skript Speicher und Verhaltensschutz

AMSI hat zwei Seiten: Anwendungen können Inhalte zur Prüfung einreichen; Antimalwareanbieter implementieren einen Provider. Der Aufruf von AmsiScanBuffer kann einen bereits installierten Anbieter benutzen. Er macht AXSafe nicht automatisch zur eigenen Skripterkennung. Für einen eigenen Schutz sind Provider, Signierung, Hostarchitekturen, Sitzungsbehandlung und echte Anbindung an die Erkennung nötig. [Q30]

Der Provider muss klein bleiben, weil er in andere Prozesse geladen werden kann. Untrusted Inhalte werden für die eigentliche Analyse an einen begrenzten Worker gegeben, soweit der unterstützte Host und die Antwortfristen dies erlauben. Vollständige Skripte können Zugangsdaten enthalten und gehören nicht standardmäßig in Logs oder Cloudtelemetrie.

Speicherprüfung wird gezielt bei nachvollziehbarem Verdacht gestartet. Sie kombiniert lesbare Bereiche, ausführbare Speicherregionen, Modulherkunft und beobachtetes Verhalten. JIT Compiler Browser Entwicklerwerkzeuge und Spiele erzeugen legitimen dynamischen Code. AXSafe darf ihn nicht allein wegen seiner Speichermerkmale blockieren.

Geschützte Prozesse und fehlende Rechte begrenzen die Prüfung. Diese Grenze wird gemeldet und nicht durch das Umgehen von Betriebssystemschutz aufgehoben. Ein vollständiges Speicherabbild ist weder ein notwendiger Standardscan noch eine datenschutzarme Diagnose.

ETW und andere dokumentierte Quellen liefern Ereignisse für Korrelation. Der Prozessbezug muss den Startzeitpunkt oder eine entsprechende stabile Instanzidentität berücksichtigen, weil Prozessnummern wiederverwendet werden. Ereignisse können fehlen, später eintreffen oder unter Last verloren gehen. Ein Diagramm ohne Datenvollständigkeit kann täuschen.

Eigene Regeln verbinden mehrere Signale, beispielsweise verdächtigen Ursprung, ungewöhnliche Prozessfolge, Persistenz und anschließende Kommunikation. Für jede Regel werden legitime Gegenfälle getestet. Ein Backup Programm, Administrator oder Debugger darf nicht allein wegen mächtiger Funktionen als Angreifer gelten.

## 12 Ransomware Quarantäne und Reparatur

Quarantäne ist ein Sicherheits und Datenintegritätsproblem. Ein bloßes Umbenennen einer Datei genügt nicht. AXSafe plant authentifiziert verschlüsselte Payloads, restriktive Rechte, geschützte Schlüssel und ein transaktionales Journal. Die Sicherung muss haltbar vorliegen, bevor ein Original endgültig entfernt wird.

Die Metadaten erfassen den Originalbezug, Hash, betroffene Streams, Befund, Versionsstand, Zeit und nötige Wiederherstellungsinformationen. Bei jeder Aktion wird die Dateiidentität erneut geprüft. Sonst kann eine zwischenzeitliche Pfadänderung den Dienst zum Löschen einer unbeteiligten Datei missbrauchen.

Wiederherstellung benötigt Berechtigungsprüfung, aktuellen Rescan, sichere Zielprüfung und einen klaren Umgang mit vorhandenen Dateien. Eine Freigabe darf nicht unbemerkt den gesamten Ordner vom Schutz ausschließen. Stromausfall, gesperrte Datei, volle Platte und kaputte Datenbank sind Pflichtfälle.

Ransomware Schutz bewertet Änderungen zusammen mit Prozesskontext und weiteren Signalen. Entscheidend ist nicht nur eine spätere Warnung, sondern wie viele Testdateien vor der Eindämmung verändert wurden. Canaries und Entropiewerte können Hinweise liefern, aber keine alleinige allgemeine Entscheidung tragen.

Rollback ist nur dort möglich, wo korrekte Originalversionen vorhanden und noch zugänglich sind. Es braucht Kapazitätsgrenzen, konsistente Aufnahme, geschützte Ablage und Wiederherstellungstests. Lokale Schattenkopien ersetzen keine unabhängigen Backups. Gegen bereits erfolgten Datenabfluss hilft ein nachträgliches Dateirollback nicht.

Reparatur von Autostarts, Diensten oder Tasks setzt den belegten Zusammenhang mit dem Vorfall voraus. Systemdateien werden nicht auf einen einzigen unsicheren Treffer hin gelöscht. Bei hoher Unsicherheit sind eine Reparaturvorschau, externe Untersuchung oder ein sauberer Neuaufbau ehrlicher als eine behauptete vollständige Bereinigung.

## 13 Web Netzwerk E Mail und USB

Webschutz kann Browserereignisse, Downloads und lizenzierte Reputation nutzen. Dabei sind Weiterleitungen, internationale Domainnamen, gemeinsam genutzte Infrastruktur und unbekannte Ziele zu berücksichtigen. Der Status unbekannt ist kein Vertrauensbeweis.

Windows Filtering Platform bietet Netzwerkfilterung und erweiterbare Entscheidungen an unterschiedlichen Schichten. AXSafe soll vorhandene Windows Firewall Funktionen und gezielte eigene Policies nutzen, statt früh einen vollständigen Netzwerkstack zu ersetzen. Filter müssen nach Prozess, Richtung und Ziel nachvollziehbar sein. IPv6, VPN, Proxy, DNS Wege und Recoveryverbindungen gehören in die Testmatrix. [Q33]

Eine Paket oder Verbindungsfilterung entschlüsselt HTTPS nicht automatisch. QUIC und verschlüsselte DNS Wege verändern ebenfalls die verfügbare Sicht. Das Konzept sieht keine standardmäßige Installation einer eigenen Root CA zur umfassenden TLS Aufbrechung vor. Browsernahe Informationen und tatsächliche Datei Downloads sind getrennte Datenquellen.

E Mail Schutz bedeutet anfangs: unterstützte lokal gespeicherte oder heruntergeladene Anhänge prüfen. Für Outlook, Webmail oder einen Mailgateway braucht es jeweils echte Integration mit klaren Rechten. Ohne diese Integration bleibt ein Schalter mit der Behauptung vollständiger E Mail Schutz deaktiviert oder entsprechend anders benannt.

USB Schutz prüft Dateien, Einbindung und unterstützte Ausführungswege. Ein USB Gerät, das sich als Tastatur ausgibt oder manipulierte Firmware enthält, lässt sich damit nicht vollständig beurteilen. Diese Grenze wird ausdrücklich dokumentiert.

## 14 Selbstschutz Rootkits und Plattformintegrität

AXSafe unterscheidet Standardbenutzer, lokale Administratoren und bereits aktive Kernelgegner. ACLs, Dienstrechte, signierte Konfiguration und Integritätsprüfung schützen gegen viele Manipulationen mit normalen Rechten. Gegen jeden Administrator oder einen kompromittierten Kernel ist daraus kein absoluter Schutz ableitbar.

Microsoft dokumentiert geschützte Antimalware Dienste über einen ELAM gestützten Weg mit zusätzlichen Anforderungen an Zertifikate und geladene Komponenten. PPL ist kein beliebiger Schalter, den jede Desktop App voraussetzungslos aktivieren kann. Wartung und autorisierte Deinstallation müssen mit geplant werden. [Q31]

Für Windows Sicherheitscenter und einen gegebenenfalls gewünschten Partnerzugang wird der unterstützte Integrationsweg früh geklärt. Die öffentliche Recherche verifiziert keinen frei nutzbaren vollständigen Schreib und Registrierungsvertrag für AXSafe. Daher erfindet der Entwicklungsplan keine API und keine WMI Registrierung. Das ist ein externer Klärpunkt mit zuständiger Rolle und Freigabesperre.

Microsofts MVI Programm hat veröffentlichte Aufnahmebedingungen einschließlich realer Schutzfunktionen, laufender Verantwortung, vertraglicher Anforderungen und unabhängiger Prüfungen. Aufnahme ist nicht garantiert. Eine MVI Voraussetzung, die Betriebssystemregistrierung, ELAM Zertifizierung und allgemeine Treibersignierung sind unterschiedliche Themen und werden nicht gleichgesetzt. [Q55]

Bis zur geprüften Primärschutzintegration bleibt vorhandener Defender aktiv. Sein aktiver, passiver oder deaktivierter Modus hängt vom Windows und Produktszenario ab; der passive Modus ist nicht beliebig auf jedem Client als identischer Standard verfügbar. AXSafe soll keine breiten Ausschlüsse setzen und keinen pauschalen Betriebsmodus erzwingen. [Q32]

Bekannte verwundbare Treiber werden als eigener Risikobereich berücksichtigt. Microsoft dokumentiert sowohl empfohlene Blockregeln als auch Unterschiede der Standardaktivierung zwischen Windows 10 und Windows 11. Eine Windows 11 Voreinstellung darf deshalb nicht ungeprüft für deine LTSC Installation behauptet werden. Änderungen müssen zunächst auf Kompatibilität getestet werden. [Q34, Q35]

Bei Firmware und Bootkompromittierung braucht es unter Umständen Herstellerfunktionen, Offlineanalyse oder Wiederherstellung außerhalb des laufenden Betriebssystems. NIST beschreibt Firmware Resilienz als Schutz, Erkennung und Wiederherstellung von Plattformfirmware. AXSafe kann dafür Signale und Abläufe anbieten, aber keinen universellen Firmware Scanner oder risikofreies automatisches Flashen aller Hardware versprechen. [Q42]

Microsoft hat eine Windows Endpoint Security Platform API zunächst als Vorschau für MVI Partner beschrieben. Die hier geprüfte Ankündigung liefert keinen Beleg, dass AXSafe diese API allgemein auf Windows 10 LTSC verwenden kann. Der Plan darf deshalb nicht von ihr abhängig werden; für Windows 11 wird die konkrete Verfügbarkeit vor einer Implementierung erneut geprüft. [Q56]

## 15 Cloud Sandbox und eigene Modelle

Die lokale Basis muss ohne Cloud funktionieren. Reputation kann einen Hash, wenige notwendige Metadaten und eine zeitlich begrenzte Bewertung verwenden. Ein unbekannter Hash führt nicht automatisch zu einem Upload. Auch Hashes und Metadaten können vertrauliche Informationen verraten und werden nicht pauschal als anonym bezeichnet.

Das Backend braucht Geräteauthentifizierung, Quoten, Zugriffsrollen, verschlüsselte Verbindungen, Missbrauchsschutz, Löschregeln und getrennte Ablagen für unterschiedliche Datenarten. Ein kompromittierter Analyseworker darf weder Produktionssignierschlüssel noch Zugriff auf andere Kunden erhalten. Bei Netzproblemen bleibt der lokale Schutz aktiv; die Oberfläche zeigt die fehlende Zusatzfunktion.

Eine echte Sandbox führt ausgewählte Dateien in zurücksetzbaren Analyse VMs aus. CAPE dokumentiert einen Host und Guest Aufbau sowie isolierte Netze. Daraus folgt für AXSafe ein separater Analysebetrieb; eine Containerhülle auf dem Alltagsrechner ist kein gleichwertiger Nachweis einer ausreichenden Isolation. Ausgabeformate und Resultatparser sind ebenfalls untrusted. [Q53, Q54]

Ein unauffälliger Sandboxlauf beweist keine Harmlosigkeit. Zeitverzögerung, benötigte Nutzerinteraktion, fehlende Netzwerkbedingungen oder Analyseerkennung können Verhalten ausbleiben lassen. Sandboxbefunde ergänzen andere Schichten und werden mit Version, Laufzeit und tatsächlicher Beobachtung dokumentiert.

Eigene KI beginnt mit einer konkreten Aufgabe, zum Beispiel Klassifikation unterstützter PE Dateien. Benötigt werden rechtmäßig nutzbare Daten, belastbare Labels, stabile Features, ein Basismodell, zeitlich getrennte Bewertung, aktuelle gutartige Gegenfälle und ein nachvollziehbarer Freigabeprozess.

EMBER2024 liefert Forschungsfeatures und Labels für mehrere Dateitypen mit einer zeitlichen Aufteilung. SOREL 20M ist ein weiterer umfangreicher Forschungsbestand mit eigenen Nutzungsbedingungen. Solche Bestände können Experimente ermöglichen, ersetzen aber keine aktuelle Schutzbewertung des fertigen AXSafe und keine Rechteprüfung für kommerzielle Nutzung. [Q40, Q41]

Wichtig sind Duplikatentfernung und Trennung verwandter Familien oder Kampagnen, damit fast gleiche Beispiele nicht gleichzeitig in Training und Test stehen. Ein kleiner Teil sehr ähnlicher Dateien darf die Statistik nicht künstlich verbessern. Für Modelle werden Fehlalarme, Recall, Latenz, Speicher, Kalibrierung und Verhalten bei unbekannten Dateitypen gemessen.

NIST beschreibt unter anderem Evasion, Datenvergiftung und weitere Angriffe auf ML Systeme. AXSafe muss daher Datenherkunft, Modellintegrität, Manipulation von Eingangsmerkmalen und Drift prüfen. Ein Modell wird erst nach nachgewiesenem Zusatznutzen im Produkt aktiviert; bis dahin ist es ausdrücklich Forschung. [Q39]

Ein Sprachmodell kann optional Befunde erklären oder Analysten unterstützen. Texte in verdächtigen Dateien werden dabei als untrusted Daten behandelt. Ein LLM darf weder direkt Blockregeln veröffentlichen noch Dateien löschen, Geheimnisse anfordern oder seine eigenen Vorschläge als überprüfte Malwarebelege darstellen.

## 16 Updates und Lieferkette

AXSafe verteilt mehrere Arten von Änderungen: Programmcode, Engine, Erkennungsdaten, Verhaltensregeln, Modelle und eventuell Treiber. Sie haben unterschiedliche Kompatibilitäts und Risikoanforderungen. Eine scheinbar kleine Regel kann trotzdem Verfügbarkeit oder Fehlalarme stark beeinflussen.

TLS schützt die Verbindung, reicht aber als gesamtes Updatevertrauen nicht aus. The Update Framework beschreibt zusätzliche verifizierbare Metadaten, Rollen, Schlüssel, Versionen und Ablaufzeiten zur Begrenzung verschiedener Repository und Schlüsselangriffe. Für AXSafe wird eine gepflegte geeignete TUF Implementierung bevorzugt; ein ähnliches selbst erfundenes Verfahren muss nicht dieselben Eigenschaften haben. [Q36]

Vorgeschlagen sind getrennte Root und Veröffentlichungsrollen, geschützte Schlüssel, ein offline abgesicherter Vertrauensanker, signierte Artefakte, Kompatibilitätsangaben und ein geprobter Widerruf. Ein kompromittierter Online Schlüssel darf nicht automatisch jede Vertrauensstufe kontrollieren.

Staging prüft Paketintegrität, Schemas, Engineverträglichkeit, gutartige Regressionen, Testbefunde und Startfähigkeit. Erst danach folgen kontrollierte Verteilringe. Stopkriterien orientieren sich unter anderem an Abstürzen, Fundspitzen und Reparaturfehlern. Die Ringgrößen und Beobachtungszeiten sind Projektentscheidungen, keine hier belegten Branchennormen.

Rollback und Schutz gegen alte verwundbare Versionen müssen zusammenpassen. Ein legitimes Zurücksetzen erfolgt über neue autorisierte Metadaten auf einen ausdrücklich erlaubten Stand. Ein Angreifer darf keinen beliebig alten Release als Recovery ausgeben. Auch Schlüsselrotation und Recovery müssen mit Offlinegeräten und falscher Gerätezeit getestet werden.

NIST SSDF bietet einen Rahmen für sichere Entwicklungsprozesse; SLSA behandelt die Vertrauenswürdigkeit der Softwarelieferkette. AXSafe leitet daraus konkrete Aufgaben ab: kontrollierte Änderungen, getrennte Releasejobs, gepinnte Abhängigkeiten, SBOM, nachvollziehbare Buildherkunft und Schutz der Signierschlüssel. Das Dokument behauptet keine bereits erreichte SSDF oder SLSA Zertifizierung. [Q37, Q38]

## 17 Datenschutz Recht und Vertrieb

Die zentrale Produktregel ist Datenminimierung: lokal prüfen, nur zweckgebundene Metadaten verarbeiten, Inhalte nur nach konkreter Freigabe übermitteln und Aufbewahrung begrenzen. Einwilligung ist kein Ersatz für die Prüfung der jeweiligen Rechtsgrundlage. Datenschutzinformationen, Rollen, Empfänger, Dienstleister, Drittlandtransfers und Betroffenenrechte werden anhand des tatsächlichen Betriebsmodells geklärt. Die BfDI veröffentlicht Grundlagen des Datenschutzrechts sowie Empfehlungen für datenschutzfreundliche Telemetrie. [Q50, Q51]

Für dich besonders praktisch: Private oder berufliche Bankdaten, Kundendaten und Arbeitsplatzsysteme werden nicht als Testmaterial verwendet. Das Projekt kann auf künstlichen Dokumenten, rechtmäßig nutzbaren öffentlichen Testdaten und einem eigenen Labor aufbauen. Damit ist keine Freigabe für einen Einsatz in der Sparkasse verbunden.

Der Cyber Resilience Act ist für eine geplante öffentliche oder kommerzielle Bereitstellung früh einzuplanen. Nach der EU Kommission gelten die wesentlichen Verpflichtungen ab 11 Dezember 2027, die vorgesehenen Meldepflichten bereits ab 11 September 2026. Ob und in welcher Rolle AXSafe konkret erfasst wird, hängt vom Bereitstellungsmodell ab. Kostenlos bedeutet nicht automatisch außerhalb des Anwendungsbereichs. [Q47]

Die Kommission nennt Antivirus Software als ein für die Cybersicherheit wichtiges Produkt mit entsprechendem Konformitätsweg. Die in Anhang III vorgesehene Zuordnung für Software zum Suchen Entfernen oder Quarantänisieren von Malware ist als Ausgangspunkt zu prüfen. Zusätzliche Kernfunktionen wie Firewall oder IPS können die Bewertung beeinflussen. AXSafe darf nicht ungeprüft eine Selbsterklärung oder ein beliebiges Siegel als ausreichende Marktfreigabe behandeln. [Q48, Q49]

Für genaue Rechtsartikel und die endgültige Produktklassifizierung ist eine aktuelle juristische Prüfung erforderlich. Der direkte Volltextabruf von EUR Lex war in dieser Recherche teilweise durch eine technische Zugriffssperre eingeschränkt. Die Termin und Konformitätsaussagen stützen sich deshalb zusätzlich auf die zugänglichen offiziellen Kommissionsseiten. Eine verbindliche Prüfung des gesamten Rechtsakts wird dadurch nicht vorgetäuscht.

ENISA dokumentiert die Single Reporting Platform für einschlägige CRA Meldungen. Der Projektbetrieb muss entsprechende Zuständigkeiten und Eskalation vorsehen, soweit AXSafe in den Geltungsbereich fällt. Produktvorfälle, aktiv ausgenutzte eigene Schwachstellen und gewöhnliche Malwarefunde bei Nutzern sind dabei nicht automatisch derselbe Meldetatbestand. [Q60]

Vor dem Vertrieb gehören außerdem Lizenzen aller Komponenten und Regeln, Namens und Markenrechte, geschäftliche Informationen, Verträge, Gewährleistung, Supportdauer und gegebenenfalls Verbraucherrecht in die Freigabeakte. Domain oder Markenverfügbarkeit von AXSafe wurde nicht geprüft. Es wurden keine Verträge abgeschlossen und keine kostenpflichtigen Dienste bestellt.

## 18 Oberfläche nach deiner Vorlage

Die am 24 Oktober 2026 bereitgestellte Referenz zeigt eine dunkle Desktop App mit AXSafe Logo links oben, linker Navigation, breitem Statusbanner, Statistikzeile, Aktivitätsdiagramm, Scan Center und Fundliste. Rechts stehen Schutzmodule, Live Erkennung und Systemlast. Diese visuelle Richtung wird übernommen, ohne das Bild pixelgenau kopieren zu müssen.

![Vom Nutzer bereitgestellte UI Referenz](/workspace/scratch/9555f9148f69/upload/image(20261024-125609).png)

Vorgeschlagene Startfarben sind ein sehr dunkles Blau für Hintergrund und Navigation, etwas hellere blaue Karten, Cyan für Akzente sowie Blau für primäre Aktionen. Grün, Gelb und Rot kennzeichnen bestätigte Zustände zusätzlich durch Text und Symbole. Diese Farben sind Entwurfswerte und brauchen Kontrastprüfungen.

Die Navigation enthält Übersicht, Virenscan, Echtzeitschutz, Ransomware Schutz, Firewall und Netzwerk, Web und Phishing, Quarantäne, Datenschutz und Berichte. Einstellungen und Hilfe bleiben im unteren Bereich. Ein Nutzerkonto wird für lokale Scans nicht vorausgesetzt. Die im Bild sichtbaren Zähler, Uhrzeiten, Namen und Aktivzustände werden nicht als echte Produktdaten übernommen.

| Bereich | Was tatsächlich funktionieren muss |
| --- | --- |
| Hauptbanner | Gesund eingeschränkt in Prüfung Vorfall und unbekannter Zustand aus bestätigtem Dienststatus |
| Kennzahlen | Reale Dateien und Bytes mit Zeitraum Scanstand und nachvollziehbarer Zählweise |
| Aktivitätsdiagramm | Echte aggregierte Ereignisse mit klarer Achse und einblendbarer Zeitspanne |
| Scan Center | Schnell vollständig eigener Scan Zeitplan sowie ein belegter Offlineablauf |
| Fundliste | Schweregrad Befund Aktion Zeit Status und Erkläransicht |
| Schutzmodule | Tatsächliche Capability Berechtigung Abhängigkeit und bestätigter Zustand |
| Live Erkennung | Erfasste Vorgänge mit Quelle und Datenalter ohne unnötige private Inhalte |
| Systemlast | Gemessene AXSafe Last mit eindeutiger Einheit und Zeitraum |
| Quarantäne | Sichere Wiederherstellung Löschung Fehlerzustand und Fehlalarmprüfung |
| Datenschutz | Cloudstufen Uploadfreigaben Aufbewahrung und Diagnoseexport |

Keine Schaltfläche darf einen Schutz vortäuschen. Ein noch nicht implementierter Offline Scan ist deaktiviert und erklärt die fehlende Voraussetzung. Der E Mail Schalter heißt zunächst Anhangprüfung, solange keine echte Postfachintegration besteht. Die Firewall Anzeige kann den Zustand der Windows Firewall zeigen, muss die Datenquelle aber eindeutig benennen.

Benötigt werden auch Zustände, die auf dem Referenzbild nicht zu sehen sind: leerer Verlauf, laufender Scan, pausiert, abgebrochen, teilweise geprüft, veraltete Signaturen, Engineabsturz, Cloud nicht erreichbar, Schutzmodul fehlt, ausstehender Neustart, fehlende Rechte und fehlgeschlagene Wiederherstellung.

Für WPF sind vektorbasierte Symbole, gut skalierende Layouts und native Bedienbarkeit vorgesehen. Tests decken insbesondere 125 bis 200 Prozent Skalierung, kleinere Fenster, Tastatur, Screenreader und Statusverständlichkeit ab. Bei schmalen Fenstern kann die rechte Spalte unter die Hauptinhalte wechseln. Ein schöner Desktop Screenshot ersetzt keine bedienbare Fehleransicht.

## 19 Teststrategie und messbare Freigaben

EICAR und AMTSO bieten ungefährliche Funktionsprüfungen. Sie zeigen, ob bestimmte Pfade und Einstellungen funktionieren. Sie beweisen nicht, wie gut AXSafe unbekannte Malware erkennt. Das müssen UI und Testbericht unterscheiden. [Q14, Q15]

AV Comparatives unterscheidet unter anderem Dateierkennung, Schutz bei Ausführung, Online und Offline Verhalten sowie Fehlalarme. AV TEST beschreibt ebenfalls eigenständige Verfahren für die Bewertung von Schutzprodukten. AXSafe orientiert die eigene Methodik daran, ohne daraus eine bereits erlangte Zertifizierung abzuleiten. Ergebnisse unterschiedlicher Tests oder Einstellungen werden nicht als direkte Rangliste vermischt. [Q11, Q12, Q13]

| Prüfung | Nachweis |
| --- | --- |
| Modul und Vertrag | Eingaben Rechte Ausgaben Fehler Zeitlimits und Versionen passen zusammen |
| Sichere Simulation | Kontrollierte ungefährliche Szenarien erreichen den vorgesehenen AXSafe Pfad |
| Reale Schutzprüfung | Rechtskonformer aktueller Korpus im geeigneten Labor mit dokumentierten Bedingungen |
| Fehlalarmprüfung | Repräsentative legitime Programme Dokumente und Arbeitsabläufe bleiben nutzbar |
| Eindämmung | Zeit und tatsächlich veränderte Dateien oder andere Schäden werden gemessen |
| Reparatur | Daten und unterstützte Änderungen lassen sich korrekt wiederherstellen |
| Zuverlässigkeit | Ausfälle Updates Stromverlust Überlast und Wiederanlauf sind geprüft |
| Leistung | Baseline und Perzentile für Boot I O CPU RAM sowie reale Nutzung |
| Eigenangriffsfläche | Parser IPC Quarantäne Updater und Treiber erhalten Fuzzing und Sicherheitsreview |
| Betriebsprobe | Fehlalarm Schlüsselverlust und kaputtes Update lassen sich organisatorisch behandeln |

Recall ist TP geteilt durch TP plus FN. Die Fehlalarmrate ist FP geteilt durch FP plus TN. Precision ist TP geteilt durch TP plus FP. Berichte nennen die absoluten Fallzahlen und die Grundgesamtheit dazu. Sehr viele ähnliche Samples sind kein Ersatz für unabhängige und aktuelle Fälle.

Ein einfaches Rechenbeispiel zeigt die Bedeutung niedriger Fehlalarmraten: Bei einer Million gutartigen geprüften Dateien erzeugen 0,01 Prozent Fehlalarme bereits 100 falsche Funde. Das ist ein hypothetisches Beispiel und keine Messung von AXSafe oder einem Anbieter.

Für die Freigabe werden vor den Tests konkrete Leistungs und Schadensbudgets vereinbart. Die nötigen Zahlen hängen von Hardware, Engine und Umfang ab. Hier werden keine angeblich bewiesenen Werte wie 99,99 Prozent Erkennung oder maximal 100 MB RAM festgelegt. Geplante Budgets sind keine Messergebnisse.

Harte Freigabesperren gelten für offene kritische Sicherheitsfehler, Datenverlust, nicht beherrschte Bootschleifen, unautorisierte Inhaltsuploads, falsche Schutzanzeigen sowie fehlende Nachweise für beanspruchte Kernfunktionen. Ein externes Prüfergebnis wird nur mit passender Version und tatsächlichem Umfang verwendet.

## 20 Andere Betriebssysteme und die Grenze einer gemeinsamen App

Der gemeinsame Core kann Regeln Datenmodelle und Teile der Analyse wiederverwenden. Sensorik Durchsetzung Berechtigungen Installation und Tests benötigen je Plattform eine eigene Umsetzung. Die Windows V1 beansprucht daher keinen bereits fertigen plattformübergreifenden Vollschutz.

| Plattform | Erforderlicher eigener Weg | Grenze |
| --- | --- | --- |
| macOS | EndpointSecurity System Extensions Entitlements Nutzerfreigaben und separate Tests | Kein bloßes Übernehmen eines Windows Treibers [Q43] |
| Linux | Unterstützte Distributionen Kernelstände fanotify Berechtigungen und gegebenenfalls weitere Sensorik | Fähigkeiten hängen vom Kernel und Dateisystem ab [Q46] |
| Android | APK und zugängliche Dateien legitime Berechtigungen unterstützte Netzwerk und Phishingfunktionen | Scoped Storage begrenzt fremde App Daten [Q45] |
| iOS und iPadOS | Sicherheitsfunktionen innerhalb der erlaubten Plattform APIs | Sandbox verhindert einen allgemeinen Scan fremder App Daten durch eine normale App [Q44] |
| Windows ARM64 und x86 | Eigene Binärpakete Provider Treiber und Kompatibilitätstests | Ein x64 Build ist kein Nachweis für native Unterstützung |

Diese Grenzen werden nicht mit zu schwierig begründet, sondern mit konkreten technischen Voraussetzungen und Plattformregeln. Für eine spätere Plattformfreigabe werden eigene Anforderungen und Tests ergänzt. Versprochene Funktionen bleiben bis dahin deaktiviert oder außerhalb des angegebenen Schutzumfangs.

## 21 Aufwand Kosten und offene Entscheidungen

Ein vollständiger neuer Endpoint Schutz ist ein dauerhaftes Forschungs und Betriebsprojekt. Die eigene Entwicklung eines einfachen ergänzenden Scanners ist erheblich kleiner als ein allein verantwortlicher Primärschutz. Daraus folgt keine konkrete seriöse Fertigstellungsfrist ohne Kenntnis deiner Zeit, Vorkenntnisse, Teamgröße und gewählten Engine.

| Kostenbereich | Einmalig oder laufend | Vor Freigabe zu klären |
| --- | --- | --- |
| Entwicklung | Beides | Verfügbare Zeit benötigte Spezialisten und Wartungsverantwortung |
| Laborhardware | Anschaffung und Wartung | Genügend RAM Speicher und getrennte Testgeräte keine private Produktivumgebung |
| Windows und Werkzeuge | Je Lizenzmodell | Zulässige Labor und Vertriebsnutzung |
| Signierung | Einrichtung und laufend | Geeignete User Mode und Treibersignierung Schlüsselverwaltung |
| Engines und Daten | Je Lizenzmodell | Open Source Pflichten oder echtes OEM Angebot |
| Backend und CDN | Laufend | Nutzung Speicher Auslieferung Missbrauch und Verfügbarkeit |
| Sandbox und Forschung | Laufend | Rechenzeit Isolation rechtmäßige Daten und Fachwissen |
| Externe Prüfung | Wiederkehrend | Sicherheitsreview unabhängige Schutz und Kompatibilitätstests |
| Datenschutz und Recht | Einrichtung und laufend | Tatsächliches Bereitstellungsmodell Verträge und Pflichten |
| Support | Laufend | Fehlalarmbearbeitung Vorfälle Updates und erreichbare Zuständigkeit |

Ein passendes Budgetmodell lautet: einmalige Einrichtung plus Entwicklungszeit plus laufende Infrastruktur plus Lizenzen plus wiederkehrende Prüfungen und Support. Für ein finanzielles Szenario werden echte Angebote und deine verfügbare Zeit eingesetzt. Pauschale SDK oder Zertifikatspreise wären hier unzuverlässig.

Wichtige offene Entscheidungen sind: bestätigte Architektur und Hardware, reines Privatprojekt oder Veröffentlichung, Open Source Lizenzmodell, akzeptierte Cloudstufen, konkrete Leistungsbudgets, externe Zugänge für die Windows Integration und personelle Verantwortung für den Betrieb. Diese Punkte verhindern nicht, dass unabhängig daran weitergearbeitet wird. Sie blockieren aber die jeweils davon abhängigen Veröffentlichungsversprechen.

## 22 Regeln für schwierige und blockierte Punkte

Zu schwer ist kein zulässiger Abschlussstatus. Jeder offene harte Punkt bekommt Ursache, bislang geprüfte Möglichkeiten, benötigte Unterlagen oder Zugänge, zuständige Rolle, nächsten überprüfbaren Schritt und die betroffene Abnahme. Solange kein Nachweis vorliegt, wird daraus keine aktive Funktion.

| Schwieriger Punkt | Nächster konkreter Schritt | Sperre |
| --- | --- | --- |
| LTSC Lebenszyklus | Aktuellen Update und künftigen Supportweg für genau diese Edition prüfen | Kein unbegrenztes Windows 10 Supportversprechen |
| Echtzeit Minifilter | Microsoft Beispiele im Labor bauen und Datei I O Zustandsmodell reviewen | Kein primärer Echtzeitschutz aus einem Watcher |
| Treiberfreigabe | Voraussetzungen Altitude Signierweg und passende Tests dokumentieren | Kein Testtreiber im normalen Produktpaket |
| Dateirennen | Stabile Dateisicht und parallele Änderungstests implementieren | Keine Freigabe mit veraltetem Scanbefund |
| AMSI | Echten Provider mit Testhosts und Architekturen nachweisen | Kein eigener Skriptschutz durch bloßen Fremdscanneraufruf |
| PPL und ELAM | Zertifikat und Servicepfad mit den geltenden Anforderungen abgleichen | Kein starker Selbstschutz nur durch Wiederstarten eines Dienstes |
| Windows Sicherheitscenter | Unterstützten Anbieterweg und Voraussetzungen klären | Keine erfundene Produktregistrierung |
| Ransomware Rollback | Originalspeicher und bytegenaue Restoretests erstellen | Keine Entschlüsselungsgarantie ohne Originale |
| Firmware | Unterstützte Integritätssignale und Eskalationsablauf definieren | Kein universeller Live Reinheitsnachweis |
| Modelle | Zeitlich getrennte Baseline mit aktuellen Gegenfällen bewerten | Kein KI Schutzschalter ohne Messung |
| Cloud Datenschutz | Datenfluss und Freigaben implementieren und technisch kontrollieren | Keine stillen Sampleuploads |
| Fehlalarme | Legitime Korpora und funktionierenden Rücknahmeweg bereitstellen | Kein Release mit unvertretbarer destruktiver Reaktion |
| Vollständiger E Mail Schutz | Tatsächliche Client oder Gateway Integration prüfen | Keine Postfachbehauptung aus Downloadprüfung |
| Offline Scan | Rettungsmedium Lizenz Boot und Datenträgerzugang im Labor prüfen | Kein Button ohne funktionierenden Ablauf |
| Öffentlicher Vertrieb | Lizenz Datenschutz CRA Support und externe Prüfungen abschließen | Keine öffentliche Vollschutzfreigabe auf Basis eines Demos |

Der Entwicklungsagent soll Alternativen untersuchen und unabhängige Aufgaben fortsetzen. Er darf fehlende Zertifikate, Verträge oder Prüfungen aber weder fälschen noch durch Mocks ersetzen. Auch ein Sprachmodellprompt kann diese äußeren Voraussetzungen nicht beschaffen oder die Sicherheit des Ergebnisses garantieren.


## Quellenregister

Abrufstand 24 Oktober 2026. Die Q Kennungen im Konzept verweisen auf die folgenden Quellen. Herstellerangaben beschreiben die jeweilige eigene Technik; daraus wird keine unabhängige Wirksamkeitsgarantie abgeleitet. Die rechtlichen und technischen Voraussetzungen werden vor Implementierung beziehungsweise Veröffentlichung erneut geprüft.

**Q01 Windows 10 release information**

https://learn.microsoft.com/en-us/windows/release-health/release-information

**Q02 LTSC 2021 Supportende**

https://techcommunity.microsoft.com/blog/windows-itpro-blog/plan-for-windows-10-enterprise-ltsc-2021-end-of-support/4539866

**Q03 .NET 10 unterstützte Betriebssysteme**

https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md

**Q04 Microsoft Defender Erkennungsschichten**

https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav

**Q05 Bitdefender OEM und Endpoint SDKs**

https://www.bitdefender.com/en-us/oem/endpoint-protection

**Q06 ESET Schutztechnologien**

https://www.eset.com/me/about/technology/

**Q07 Sophos technische Schutzrichtlinie**

https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/EndpointProtection/ThreatProtectionPolicy/

**Q08 SentinelOne statische und Verhaltensmodelle**

https://www.sentinelone.com/platform/singularity-complete/

**Q09 SentinelOne Ereigniskorrelation**

https://www.sentinelone.com/platform/endpoint-protection-platform/

**Q10 Kaspersky System Watcher und Grenzen des Rollbacks**

https://support.kaspersky.com/help/Kaspersky/Win21.7/en-US/68174.htm

**Q11 AV Comparatives Malware Protection Methodik**

https://av-comparatives.org/tests/malware-protection-test-september-2026/

**Q12 AV Comparatives Real World Protection Methodik**

https://av-comparatives.org/tests/real-world-protection-test-february-may-2026/

**Q13 AV TEST Testverfahren**

https://www.av-test.org/en/about-the-institute/test-procedures/

**Q14 AMTSO Funktionsprüfungen**

https://www.amtso.org/security-features-check/

**Q15 EICAR Testdatei**

https://www.eicar.org/download-anti-malware-testfile/

**Q16 MITRE ATTACK Enterprise Matrix**

https://attack.mitre.org/matrices/enterprise/

**Q17 ClamAV Fähigkeiten und Plattformgrenzen**

https://docs.clamav.net/

**Q18 ClamAV Quellcode und Lizenz**

https://github.com/Cisco-Talos/clamav

**Q19 ClamAV Scannen und fehlende TCP Authentifizierung**

https://docs.clamav.net/manual/Usage/Scanning.html

**Q20 ClamAV Signaturdatenbanken**

https://docs.clamav.net/faq/faq-cvd.html

**Q21 ClamAV Konfiguration und FreshClam**

https://docs.clamav.net/manual/Usage/Configuration.html

**Q22 YARA X Funktionen und Lizenz**

https://github.com/VirusTotal/yara-x

**Q23 VirusTotal API Nutzungsgrenzen**

https://docs.virustotal.com/reference/getting-started

**Q24 VirusTotal Weitergabe hochgeladener Dateien**

https://docs.virustotal.com/docs/how-it-works

**Q25 Windows Dateisystem Minifilter**

https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers

**Q26 Microsoft Minifilter Beispiele**

https://learn.microsoft.com/en-us/windows-hardware/drivers/samples/file-system-driver-samples

**Q27 Dateiscan und Synchronisierung im Minifilter**

https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatesectionfordatascan

**Q28 Minifilter Altitude beantragen**

https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request

**Q29 Windows Treibersignierung Voraussetzungen**

https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs

**Q30 AMSI Aufrufer und Provider**

https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal?WT.mc_id=DT-MVP-5003978

**Q31 Geschützte Antimalware Dienste und ELAM**

https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-

**Q32 Microsoft Defender Betriebsmodi**

https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows

**Q33 Windows Filtering Platform**

https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform

**Q34 Microsoft Regeln gegen verwundbare Treiber**

https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

**Q35 Treiber Blockliste und Unterschiede Windows 10 und 11**

https://support.microsoft.com/en-us/servicing/os/windows/2022/10/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release

**Q36 The Update Framework**

https://theupdateframework.io/overview/

**Q37 NIST Secure Software Development Framework**

https://csrc.nist.gov/pubs/sp/800/218/final

**Q38 SLSA Lieferkettensicherheit**

https://slsa.dev/spec/v1.2/about

**Q39 NIST Adversarial Machine Learning**

https://csrc.nist.gov/pubs/ai/100/2/e2025/final

**Q40 EMBER2024 Datensatz und zeitliche Aufteilung**

https://github.com/FutureComputing4AI/EMBER2024

**Q41 SOREL 20M Datensatz und Nutzungsbedingungen**

https://registry.opendata.aws/sorel-20m/

**Q42 NIST Firmware Resilienz**

https://csrc.nist.gov/pubs/sp/800/193/final

**Q43 Apple System Extensions und Endpoint Security**

https://developer.apple.com/system-extensions/

**Q44 Apple Platform Security und iOS Sandbox**

https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf

**Q45 Android Scoped Storage**

https://developer.android.com/about/versions/11/privacy/storage

**Q46 Linux fanotify**

https://man7.org/linux/man-pages/man7/fanotify.7.html

**Q47 EU Kommission Cyber Resilience Act**

https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act

**Q48 EU Kommission Konformitätsbewertung für Antivirus**

https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment

**Q49 CRA Rechtsakt und Anhang III Fundstelle**

https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ%3AL_202402847

**Q50 BfDI Empfehlungen für Telemetrie**

https://www.bfdi.bund.de/SharedDocs/Pressemitteilungen/DE/2023/17-Berlin-Group-Telemetrie.html

**Q51 BfDI Grundlagen des Datenschutzrechts**

https://www.bfdi.bund.de/DE/Buerger/Inhalte/Allgemein/Datenschutz/GrundlagenDatenschutzrecht.html

**Q52 OASIS STIX und TAXII**

https://oasis-open.github.io/cti-documentation/faq.html

**Q53 CAPE Sandbox Architektur**

https://capev2.readthedocs.io/en/latest/installation/

**Q54 CAPE isoliertes Labornetz**

https://capev2.readthedocs.io/en/latest/installation/guest/network.html

**Q55 Microsoft Virus Initiative Aufnahmebedingungen**

https://learn.microsoft.com/en-us/unified-secops/virus-initiative-criteria

**Q56 Windows Endpoint Security Platform Vorschau**

https://news.microsoft.com/ignite-2025-book-of-news/

**Q57 ReadDirectoryChangesW Ereignisverlust**

https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw

**Q58 Google Project Zero Minifilter Fehleranalyse**

https://projectzero.google/2021/01/hunting-for-bugs-in-windows-mini-filter.html

**Q59 CrowdStrike Root Cause Analysis Channel File 291**

https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf

**Q60 ENISA Single Reporting Platform und CRA Meldepflichten**

https://www.enisa.europa.eu/topics/product-security/vulnerability-services/eu-incident-response-and-cyber-crisis-management/single-reporting-platform-srp


# Verbindlicher Entwicklungsplan

## Planstand und Umfang

Stand 24 Oktober 2026

Dieser Plan gehört zum AXSafe V1 Produktkonzept und zum Masterprompt. Beide werden aus demselben Anforderungsbestand erzeugt. Er enthält 16 Phasen und 100 Anforderungen mit eigenen Testkennungen. Alle Anforderungen sind zunächst geplant. In dieser Aufgabe wurden keine Schutzfunktionen programmiert oder getestet.

Hauptziel ist Windows 10 Enterprise LTSC 2021 21H2 Buildfamilie 19044. Dein Screenshot zeigt Build 19044.7807. x64 ist die geplante Architektur und muss vor Umsetzung auf dem Zielgerät bestätigt werden. Windows 11 erhält eine gesonderte Kompatibilitätsprüfung. Für die im Screenshot erkennbare LTSC Edition nennt Microsoft den 12 Januar 2027 als reguläres Supportende. Die IoT Edition ist nicht automatisch gemeint. [Q01, Q02]

## Verbindlicher Umfang

Eigener modularer AXSafe Kern mit Inhaltsprüfung Verhaltensanalyse Skript und Speicherprüfung echter unterstützter Dateizugriffskontrolle Quarantäne Ransomware Eindämmung sicheren Updates und nachvollziehbarer Oberfläche. Web Netzwerk Anhang und USB Funktionen müssen ihre tatsächliche Abdeckung benennen. Cloud und Inhaltsuploads sind optional; lokale Erkennung bleibt ohne Cloud funktionsfähig. Ein Forschungsmodell darf ohne Wirksamkeitsnachweis deaktiviert bleiben. Dann existiert kein aktiver eigener KI Schutz im Produkt und es wird keiner behauptet.

Open Source zuerst mit ClamAV und YARA X hinter austauschbaren Adaptern. ClamAV Lizenzpflichten und der konkrete Verteilweg müssen geprüft werden. Kommerzielle SDKs sind eine mögliche bewertete Ergänzung und keine stillschweigende Voraussetzung. Keine Bestellung oder Vertragsannahme gehört zu diesem Plan.

Default Stack: Rust für Dienst Core und CLI, C Sharp WPF mit .NET 10 für die UI, minimale C oder C Plus Plus WDK und COM Komponenten für erforderliche Windows Integration, Python ausschließlich für Forschung und Laborskripte. Exakte kompatible Versionen werden am Projektstart geprüft und gepinnt. Änderungen brauchen ein begründetes ADR.

Die UI orientiert sich an der Nutzerreferenz vom 24 Oktober 2026: dunkles Blau Cyan linke Navigation Hauptstatus Scan Center und Fundliste in der Mitte Schutzmodule rechts. Zähler Ereignisse Schalter und Schutzanzeigen stammen aus echten bestätigten Dienstdaten.

## Status und Freigabe

Zulässige Arbeitszustände sind geplant in Arbeit implementiert geprüft blockiert und begründet außerhalb des Plattformumfangs. Ein implementierter Punkt gilt erst mit bestandenem Abnahmenachweis als geprüft. Ein Mock oder eine Simulation ist nur ein dafür benannter Testbeleg. Echte Integration und Schutzwirkung werden gesondert geprüft.

Zu schwer ist kein Abschlussstatus. Jeder Blocker nennt Ursache bisherige Versuche benötigte Unterlagen oder Zugänge zuständige Rolle nächsten Schritt und blockierte Abnahme. Unabhängige Arbeit geht weiter. Ein fehlender Pflichtnachweis verhindert die betroffene Produktfreigabe. Neue Annahmen oder Umfangsänderungen werden schriftlich in Plan Prompt Spezifikation und Testmatrix synchronisiert.

Frühe Meilensteine heißen Vorversion oder ergänzender Scanner. Vorhandener Primärschutz bleibt bis zum belegten Integrationswechsel aktiv. V1 vollständig bedeutet alle im gewählten Windows Umfang verpflichtenden Nachweise; es bedeutet keinen garantierten Schutz gegen jede Malware. Die Betriebssystem und Firmwaregrenzen bleiben ausdrücklich dokumentiert.

## Phasenübersicht

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

Die Reihenfolge beschreibt Abhängigkeiten. Modulprüfungen beginnen sofort. UI Grundgerüst Updatevertrauen und externe Klärungen können früh parallel zur fachlichen Entwicklung bearbeitet werden. P14 ist der zusätzliche Gesamtnachweis und kein Aufschub aller Tests bis zum Projektende. P11 Zugänge und Zertifikate werden bereits in P00 angefragt beziehungsweise vorbereitet; ohne ausdrückliche Beauftragung erfolgt keine kostenpflichtige Beschaffung.

## Verbindliche Arbeitsweise je Phase

Vor Beginn die zugehörigen Anforderungen Risiken Quellen und noch offenen Entscheidungen lesen. Danach kleine überprüfbare Änderungen umsetzen, angemessene Tests durchführen und Belege an die Anforderungs IDs hängen. Pro Phase entstehen betroffene Dateien Buildbefehle Testfälle Ergebnisse bekannte Grenzen und aktualisierte Blocker. Nicht ausgeführte Tests werden als nicht ausgeführt gekennzeichnet.

Für jede Testkennung gibt es mindestens Ausgangszustand Umgebung Eingabe erwartetes Verhalten tatsächliches Verhalten und Versionsbezug. Bei Schutzfunktionen gehören gutartige Gegenbeispiele und Ausfälle dazu. EICAR und AMTSO prüfen Funktionswege. Echte Malware Wirksamkeit verlangt einen anderen geeigneten Labor und Prüfrahmen. Private und berufliche Daten werden nicht als Proben verwendet.

## Detaillierte Phasen und Abnahmen
### P00 Ziel und Voraussetzungen klären

Den Umfang für Windows 10 LTSC festlegen und die technische sowie organisatorische Ausgangslage belegen.

**Voraussetzungen** Projektstart

**Ergebnis** Produktauftrag, Plattformmatrix, Lizenzliste, Quellenregister, Budgetmodell und Entscheidungsprotokolle

**Freigabe** Ausgangslage und V1 Abnahme sind schriftlich festgelegt; fehlende Informationen stehen als offene Punkte im Register.

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

Reproduzierbare Entwicklung und ein getrenntes Testlabor bereitstellen.

**Voraussetzungen** P00

**Ergebnis** Repository, Buildskripte, Windows VM Images, Testdatensätze und Laborregeln

**Freigabe** Ein frischer Checkout baut reproduzierbar; ein Testlauf kann ohne private Daten und ohne Zugriff auf das Alltagsnetz durchgeführt werden.

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

Benutzeroberfläche, privilegierten Broker und Scanprozesse mit klaren Rechten und Datentypen trennen.

**Voraussetzungen** P01

**Ergebnis** Dienst, CLI, authentifizierte lokale IPC, Ereignisvertrag, Policy und Ergebnismodell

**Freigabe** Ein normaler Benutzer kann den Dienst weder als beliebigen Dateileser noch als Löschdienst missbrauchen; Ausfälle werden korrekt gemeldet.

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

Reale lokale Dateiprüfung mit Engines, eigenen Regeln und ehrlichen Teilresultaten implementieren.

**Voraussetzungen** P02

**Ergebnis** ClamAV Adapter, YARA X Adapter, Typenerkennung, Archivbehandlung und sicherer Scancache

**Freigabe** Erkennung, Negativfälle, verschachtelte Container und alle Scanfehler sind nachvollziehbar getestet; keine Probe wird auf dem Host ausgeführt.

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

Programm, Signaturen, Regeln und Modelle manipulationsgeschützt und wiederherstellbar aktualisieren.

**Voraussetzungen** P02, P03

**Ergebnis** TUF gestützter Updatepfad, Signierschema, Staging, Rollout und Rückfallverfahren

**Freigabe** Manipulierte, abgelaufene und unzulässig alte Updates werden abgewiesen; Stromausfall und Schlüsselwechsel sind getestet.

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

Funde sicher isolieren und nachvollziehbar wiederherstellen, ohne Systemdateien zu beschädigen.

**Voraussetzungen** P03, P04

**Ergebnis** Verschlüsselte Quarantäne, Journal, Bereinigungsvorschläge und Wiederherstellungsdialog

**Freigabe** Dateiverwechslung, Rechteausweitung und Datenverlust werden in den definierten Fehlerfällen verhindert; Restore ist bytegenau geprüft.

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

Prozess, Datei, Persistenz und Netzwerkereignisse zu überprüfbaren Verhaltensbefunden korrelieren.

**Voraussetzungen** P02, P03

**Ergebnis** Windows Sensoren, Prozessbaum, Ereignisjournal und versionierte Verhaltensregeln

**Freigabe** Gutartige Gegenbeispiele und simulierte Angriffsketten unterscheiden sich zuverlässig; Sensorverluste sind sichtbar.

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

AMSI Provider und begrenzte Speicheranalyse als echte zusätzliche Schutzschichten anbinden.

**Voraussetzungen** P03, P06

**Ergebnis** Signierter AMSI Provider, Sitzungsanalyse, Speicherworker und Rechtekonzept

**Freigabe** AXSafe eigene AMSI Befunde sind vom Aufruf fremder Scanner getrennt; nicht zugänglicher Speicher wird als solcher ausgewiesen.

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

Zugriffe auf unterstützten Dateipfaden vor der Freigabe prüfen und gefährliche I O sicher verhindern.

**Voraussetzungen** P03, P04, P06

**Ergebnis** Minimaler Minifilter, User Mode Scanpfad, Cache Invalidierung, Timeout und Recovery

**Freigabe** Reale Zugriffsblockierung ist auf der LTSC Testmatrix belegt; kein Dauerwarten, keine selbst verursachte Bootschleife und keine ungetesteten Treiber im Produkt.

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

Schädliche Dateiänderungen begrenzen und unterstützte Änderungen kontrolliert rückgängig machen.

**Voraussetzungen** P05, P06, P08

**Ergebnis** Korrelationsregeln, Schreibschutzpolicy, begrenzter Versionsspeicher und Reparaturplan

**Freigabe** Simulierte Massenschreibvorgänge werden in der vereinbarten Schadensgrenze gestoppt; Wiederherstellung und ihre Grenzen sind bewiesen.

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

Weitere Einfallstore durch getrennte und benannte Schutzfunktionen abdecken.

**Voraussetzungen** P03, P04, P06, P08

**Ergebnis** Browseranbindung, Reputation, WFP Policies, USB Dateiscans und Attachment Prüfung

**Freigabe** IPv4 IPv6, Browser, Netzlaufwerke und Wechselmedien sind getestet; HTTPS und E Mail Grenzen werden korrekt angezeigt.

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

Manipulation begrenzen und AXSafe nur mit belegter Funktion als primären Schutz integrieren.

**Voraussetzungen** P04, P07, P08, P09, P10

**Ergebnis** Selbstschutz, ELAM PPL Prüfung, Signiernachweise, WSC Integrationsweg und Notfallausbau

**Freigabe** Alle beanspruchten Schutzstufen sind technisch und organisatorisch belegt; fremder Schutz wird nicht vorzeitig deaktiviert.

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

Optionale Cloudfunktionen und vertiefte Analysen mit getrennten Vertrauensgrenzen aufbauen.

**Voraussetzungen** P03, P04, P06

**Ergebnis** Hash Reputation, explizite Sample Freigabe, isolierte Sandbox und reproduzierbare Modellbewertung

**Freigabe** Lokaler Schutz läuft ohne Cloud weiter; kein Dateiinhalt verlässt den Rechner ohne Freigabe; Modelle bleiben ohne Eignungsnachweis im Forschungsmodus.

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

Die dunkle AXSafe Oberfläche mit echten Daten und verständlichen Zuständen vervollständigen.

**Voraussetzungen** P02, P05, P06

**Ergebnis** WPF Desktop App, Navigation, Dashboard, Scanansichten, Quarantäne und Fehlerzustände

**Freigabe** Jeder aktive Schalter hat eine getestete Wirkung; UI und Dienst stimmen bei Ausfall, Neustart und veralteten Daten überein.

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

Schutzwirkung, Fehlalarme, Systemverträglichkeit und Betriebsstabilität getrennt bewerten.

**Voraussetzungen** P04, P05, P07, P08, P09, P10, P11, P12, P13

**Ergebnis** Funktions und Schutzberichte, Leistungsdaten, Fuzzing Befunde, externer Review und Abdeckungsmatrix

**Freigabe** Alle V1 Pflichtnachweise liegen vor; kritische Fehler und nicht belegte Schutzversprechen blockieren die Freigabe.

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

Ein betreubares Produkt mit signierter Auslieferung, Support und Schwachstellenmanagement freigeben.

**Voraussetzungen** P00, P04, P11, P14

**Ergebnis** Releasepaket, Betriebsanleitung, Supportprozess, Notfallplan und dokumentierter Supportzeitraum

**Freigabe** Releasecheckliste vollständig, Rollback geprobt, Meldewege einsatzbereit, rechtliche und lizenzbezogene Prüfungen abgeschlossen.

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

## Harte Abschlussbedingungen

Keine ungetesteten Produktionstreiber, keine Bootschleifen oder kritischen Datenverlustfehler, keine offenen kritischen Sicherheitslücken, keine stillen Inhaltsuploads und keine grünen Schutzanzeigen ohne funktionierende Schutzpipeline. Primärschutz und starker Selbstschutz benötigen reale Integrationsnachweise. Umfangreiche Plattform und Firmwareversprechen werden nicht aus Einzeltests abgeleitet.

Performance und Schadensbudgets werden vor dem betreffenden Testlauf auf einer benannten Referenzhardware festgelegt. Ohne Messung werden keine Erkennungsraten Speicherbudgets oder Latenzversprechen veröffentlicht. Betrieb Update Recovery Fehlalarm und Schwachstellenbearbeitung sind Teil der V1 Abnahme.

## Synchronisation

Anforderungsquelle AXSafe_V1_Spezifikation.json Revision 1.0. SHA256 7ef3d464b593f5e67b72cbd3839d68524d2867b1bc21529fa18c33af0e3d209d

Der Masterprompt wiederholt dieselben 16 Phasen 100 Anforderungen und Testkennungen. Bei späteren Änderungen werden beide neu aus der Spezifikation erzeugt. Die hier aufgeführten Planungen sind noch keine implementierte Software.


# Entwicklungsauftrag und Masterprompt

Der separat bereitgestellte AXSafe_V1_Masterprompt.md ist der vollständig kopierbare Entwicklungsauftrag. Er enthält dieselben 16 Phasen 100 Anforderungen und 100 Abnahmekennungen wie dieser Plan sowie Regeln für Architektur UI Forschung Labor Sicherheit und Betriebsnachweise. Er kann allein verwendet werden; für Hintergrund und Quellenbewertung ist dieses Konzept zusätzlich hilfreich.

Die identischen Anforderungs und Testtexte werden aus AXSafe_V1_Spezifikation.json erzeugt. Der gemeinsame SHA256 Bezug steht in Plan und Prompt. Die Übereinstimmung wird vor Ausgabe maschinell geprüft. Ein Prompt ist eine Arbeitsanweisung und keine Garantie für korrekt erzeugten Sicherheitscode. Der erste konkrete Umsetzungsschritt bleibt P00 und P01 auf einem geeigneten Entwicklungs und Laborsystem.
