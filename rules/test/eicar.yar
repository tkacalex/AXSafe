// AXSafe Funktions-Testregel: EICAR Anti-Malware-Testdatei
//
// Die EICAR-Datei ist KEINE Schadsoftware. Sie ist ein vereinbarter,
// ungefährlicher Teststring, mit dem sich prüfen lässt, ob ein Erkennungspfad
// funktioniert. Ein Treffer belegt nur den Pfad, keine Schutzwirkung.
// Quelle: https://www.eicar.org/download-anti-malware-testfile/
//
// Der Teststring steht hier bewusst nur als Hex-Folge, damit diese
// Regeldatei selbst nicht von Virenscannern als Testdatei gemeldet wird.
//
// Pflicht-Metadaten jeder AXSafe-Regel (wird beim Laden geprüft):
//   id, verdict, severity, confidence, author, license, source, min_engine

rule AXSafe_Test_EICAR
{
    meta:
        id = "AXS-TEST-0001"
        name = "AXSafe.Test.EICAR"
        verdict = "malicious"
        severity = "low"
        confidence = "high"
        test = true
        author = "AXSafe Projekt"
        license = "CC0-1.0"
        source = "EICAR Standard Anti-Virus Test File (eicar.org)"
        min_engine = "1.22.0"
        description = "Ungefaehrliche EICAR-Testdatei am Dateianfang (max. 128 Bytes)"

    strings:
        $eicar = {
            58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E
            29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41
            52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49
            4C 45 21 24 48 2B 48 2A
        }

    condition:
        $eicar at 0 and filesize <= 128
}
