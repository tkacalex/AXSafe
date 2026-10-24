# Produktauftrag AXSafe V1

Stand 24.10.2026 · Spezifikation Revision 1.0 (SHA-256 `7ef3d464…09d`, siehe [`spec/`](spec/))

## Ziel

AXSafe V1 ist ein **mehrschichtiger Endpoint-Schutz für Windows 10 Enterprise LTSC 2021 (x64)** mit eigener deutscher Oberfläche. „Mehrschichtig“ heißt: lokale Inhaltsprüfung, Verhaltens-, Skript- und Speicherprüfung, echter Dateizugriffsschutz, Ransomware-Eindämmung, Quarantäne mit Wiederherstellung, sichere Updates und ein betreubarer Fehlalarmprozess.

## Was V1 ausdrücklich nicht verspricht

* Keine Garantie, jede Schadsoftware zu erkennen. Das kann kein Antivirus.
* Kein Schutz gegen jede Kontotäuschung, jede ungepatchte Lücke oder Firmwarekompromittierung.
* Keine Erkennungsquote, solange sie nicht in einem dokumentierten, rechtmäßigen Test gemessen wurde.

## Wann V1 „fertig“ ist

V1 darf erst freigegeben werden, wenn

1. alle **100 Anforderungen** (AXS-001 bis AXS-100) mit ihren **100 Abnahmen** (T-001 bis T-100) mit echten Belegen bestanden sind ([`REQUIREMENTS.md`](REQUIREMENTS.md)),
2. rechtliche und lizenzbezogene Voraussetzungen geklärt sind ([`LEGAL-REVIEW.md`](LEGAL-REVIEW.md), [`adr/ADR-0003-lizenzen.md`](adr/ADR-0003-lizenzen.md)),
3. Betrieb, Support, Updates und Recovery einsatzbereit sind ([`RELEASE-CHECKLIST.md`](RELEASE-CHECKLIST.md)).

Bis dahin ist jeder Stand eine **klar benannte Vorversion**. Fehlende Punkte stehen im [Blockerregister](BLOCKERS.md), nicht stillschweigend in „V2“.

## Aktueller Stand (Vorversion 0.1)

Ein **Datei-Scanner auf Anforderung** mit ehrlichem Ergebnismodell, YARA-X- und ClamAV-Adapter, Kommandozeile und einer ersten Oberfläche. **Kein Echtzeitschutz, keine Quarantäne.** Microsoft Defender bleibt aktiv.

## Rollen

| Rolle | Person | Hinweis |
| --- | --- | --- |
| Produktverantwortung, Freigaben | Alex (Repository-Inhaber) | entscheidet offene Punkte in [`DECISIONS.md`](DECISIONS.md) |
| Entwicklung | Alex + KI-Entwicklungsagent | Agent arbeitet nur mit Belegen, keine Freigaben |
| Windows-Kernel, Signierung, Malwareanalyse, Recht | **offen** | siehe [`BUDGET.md`](BUDGET.md) |
