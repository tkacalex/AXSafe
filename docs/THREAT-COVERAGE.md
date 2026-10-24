# Bedrohungsmatrix (AXS-002, T-002)

Status: **Entwurf – Review durch Produktverantwortung offen.**

Jede Klasse hat eine geplante Schutzschicht, einen geplanten Test und eine **benannte Grenze**. „Heute“ beschreibt ehrlich, was die aktuelle Vorversion leistet. Es gibt **keine universelle Erkennungsgarantie**.

Legende Heute: ✅ Pfad vorhanden und getestet · 🟡 teilweise · ⛔ nicht vorhanden

| # | Bedrohung | Schicht (Anforderung) | Geplanter Test | Grenze | Heute |
| --- | --- | --- | --- | --- | --- |
| 1 | Dateiviren / File Infector | Inhaltsprüfung, Signaturen (AXS-021, 022) | Signaturtest + gutartige Gegenfälle | Desinfektion nicht immer verlustfrei | 🟡 Scan auf Anforderung |
| 2 | Würmer | Datei + Netzwerk + Persistenz (AXS-041, 068) | Simulierte Ausbreitung im Labornetz | Ungepatchte Dienste bleiben Risiko | ⛔ |
| 3 | Trojaner, Backdoors | Datei, Verhalten, Herkunft (AXS-025, 044) | Simulator + signierte Gegenfälle | Gültiger Signer ≠ harmlos | 🟡 nur Dateiinhalt |
| 4 | RAT / missbrauchte Fernwartung | Prozesskontext, Netz (AXS-043, 072) | Legitime Fernwartung als Gegenfall | Fernwartung nicht pauschal Malware | ⛔ |
| 5 | Dropper, Loader, Downloader | Prozessbaum, Downloadfolge (AXS-043, 044) | Mehrstufige Simulation | Erste Datei allein reicht nicht | ⛔ |
| 6 | Ransomware | Schreibkontrolle, Korrelation, Versionen (AXS-061–063) | Simulator auf Wegwerfdateien, Schadensbudget | Schaden vor Erkennung möglich | ⛔ |
| 7 | Wiper / Massenlöschung | Löschschutz, Recovery (AXS-064) | Löschsimulation | Recovery braucht Originale | ⛔ |
| 8 | Stealer, Keylogger, Spyware | Verhalten, sensible Zugriffe (AXS-044, 049) | Kontrollierte Zugriffssimulation | Offengelegte Geheimnisse extern ersetzen | ⛔ |
| 9 | Banking-Trojaner | Browser-/Prozesskontext (AXS-067) | Labor-Testseite | Getäuschte Freigaben nicht voll erkennbar | ⛔ |
| 10 | Botnetze, C2 | Netzindikatoren mit Kontext (AXS-072) | Testziel + CDN-Gegenfälle | Geteilte Cloud-Infrastruktur | ⛔ |
| 11 | Cryptominer | Herkunft, Persistenz, Ressourcen (AXS-044) | Benigner Lastgenerator als Gegenfall | Hohe Last ≠ Schadcode | ⛔ |
| 12 | Skript- und Makromalware | AMSI-Provider, Regeln (AXS-047, 052) | AMSI-Testhost, PowerShell 5.1/7 | Nur angebundene Hosts liefern Inhalte | 🟡 Skriptdateien per Regel |
| 13 | Schädliche PDF/Office-Dokumente | Sichere Parser, eingebettete Inhalte (AXS-023, 024) | Formatkorpus + EICAR in Containern | Verschlüsselte Inhalte teils ungeprüft | 🟡 Typerkennung + ClamAV |
| 14 | Dateilose / speicherbasierte Angriffe | AMSI, Korrelation, Speicher (AXS-048–050) | Kontrollierter Testprozess | Dateiscanner sieht nicht jeden Inhalt | ⛔ |
| 15 | Living off the Land (LOLBins) | Sequenzen und Kontext (AXS-044) | Admin-Gegenfälle | Systemwerkzeuge nicht grundsätzlich böse | ⛔ |
| 16 | Injection, Hollowing | Prozess-/Speicherindikatoren (AXS-049, 050) | Testinjektion im Labor | Geschützte Prozesse begrenzen Sicht | ⛔ |
| 17 | Rootkits, schädliche Treiber | Treiberinventar, Offlineanalyse (AXS-077, 066) | Bekannte Testindikatoren | Kompromittierter Kernel täuscht Prüfer | ⛔ |
| 18 | BYOVD | Blocklisten, Integritätszustand (AXS-077) | Blocklistenstatus auf LTSC | Signierter Treiber kann verwundbar sein | ⛔ |
| 19 | Bootkits, UEFI, Firmware | Secure-Boot-Status, Herstellerweg (AXS-077) | Statusmeldung (Secure Boot aus = gemessen) | Kein Firmware-Reinheitsbeweis | ⛔ |
| 20 | Polymorph / gepackt | Generische Muster, Verhalten (AXS-025) | Gepackte gutartige Gegenfälle | Entropie allein rechtfertigt nichts | ⛔ |
| 21 | Exploits, Zero-Days | Updates, Verhalten (AXS-044) | Exploitindikator-Simulation | Keine Garantie gegen neue Lücken | ⛔ |
| 22 | PUA, Adware | Eigene Klasse `PUA` (AXS-015) | PUA-Signaturen + Policy | Unerwünscht ≠ schädlich | 🟡 Ergebnisklasse vorhanden |
| 23 | Schädliche Browsererweiterungen | Browserintegration (AXS-067) | Testerweiterung | Keine Vollkontrolle jedes Browsers | ⛔ |
| 24 | Manipulierte Updates / Lieferkette | Signatur, Herkunft (AXS-029, 025) | Manipuliertes Testpaket | Herstellerzertifikat ersetzt keine Prüfung | ⛔ |
| 25 | Paket- und Entwicklerangriffe | Downloads, Archive, Skripte (AXS-024) | Präparierte Testpakete | Kein Vollaudit aller Abhängigkeiten | ⛔ |
| 26 | LNK, MSI, ISO, VHD | Typ nach Inhalt, Container (AXS-023) | Formatkorpus | Enginefähigkeit begrenzt | 🟡 Typerkennung LNK/ISO/VHDX/CFB |
| 27 | Phishing-Webseiten | Browser + Reputation (AXS-067) | Labor-Testseite | Betrug braucht nicht immer Malware | ⛔ |
| 28 | BEC, MFA-Täuschung | Warnungen, Websignale | – | Lokaler AV ersetzt keine Identitätssicherheit | ⛔ |
| 29 | E-Mail-Anhänge | Anhangprüfung (AXS-070) | Gespeicherte Testanhänge | Ohne Integration kein Postfachschutz | 🟡 gespeicherte Anhänge per Scan |
| 30 | USB-Malware | Datei- und Zugriffsprüfung (AXS-071) | USB-Testmedium im Labor | BadUSB ist eine andere Klasse | 🟡 manueller Scan des Laufwerks |
| 31 | Netzwerk-/Remoteangriffe | Firewall, Verbindungen (AXS-068) | Testverbindungen IPv4/IPv6 | Signatur verhindert keinen Dienstexploit | ⛔ |
| 32 | Manipulation von AXSafe | Rechte, Signaturen, Selbstschutz (AXS-073) | Manipulation als Standardbenutzer | Admin-/Kernelgegner stärker | ⛔ |
| 33 | Angriffe auf Modelle/Analyse | Datenherkunft, Isolation (AXS-083) | Poisoning-/Evasion-Tests | Mehr KI ≠ mehr Schutz | ⛔ (kein Modell im Produkt) |

Die Matrix wird mit neuen Erkenntnissen fortgeschrieben. Eine feste Zahl von Familien ist kein Vollständigkeitskriterium.
