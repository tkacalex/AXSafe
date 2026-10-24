# Releasecheckliste (AXS-097, AXS-100)

Ein Release darf nur erscheinen, wenn jeder Punkt mit Beleg abgehakt ist. Aktuelle Stände sind **Vorversionen** und tragen das im Namen (`0.x`, „Vorversion“).

## Für jede Vorversion (0.x)

- [ ] CI grün auf Linux und Windows (Build, Tests, Clippy, Format, cargo-deny, Gitleaks)
- [ ] `scripts/check_release_inventory.py` bestanden: keine Laborprobe, kein Testschlüssel, keine EICAR-Datei im Paket
- [ ] SBOM (CycloneDX) als Release-Asset
- [ ] SHA-256-Prüfsummen aller Assets
- [ ] README nennt klar: kein Echtzeitschutz, Defender aktiv lassen
- [ ] CHANGELOG aktualisiert
- [ ] [`REQUIREMENTS.md`](REQUIREMENTS.md) neu erzeugt (`python3 scripts/gen_docs.py`)

## Zusätzlich für V1 (nicht erreicht)

- [ ] Alle 100 Abnahmen T-001 bis T-100 mit echten Belegen bestanden
- [ ] Signierte Pakete (Authenticode), Treiber regulär signiert
- [ ] Installation, Upgrade, autorisierter Ausbau auf der Zielmatrix getestet
- [ ] Rollback geprobt, Meldewege einsatzbereit (AXS-098)
- [ ] Rechtliche und Lizenzprüfung abgeschlossen ([`LEGAL-REVIEW.md`](LEGAL-REVIEW.md))
- [ ] Supportzeitraum dokumentiert
- [ ] Freigabeverantwortung benannt und unterschrieben

Freigabeverantwortung: **Alex** (Repository-Inhaber).
