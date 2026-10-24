# ADR-0006: Isolierter Scanworker und Broker-IPC (Entwurf für P02)

* Status: **Entwurf** – löst Blocker B-05, B-11, B-12 nach Umsetzung und Windows-Test
* Datum: 2026-10-24
* Anforderungen: AXS-013, AXS-014, AXS-020, AXS-021, AXS-022, AXS-028

## Problem

Heute laufen YARA-X und die Typerkennung im selben Prozess wie die CLI; ClamAV läuft als Kindprozess mit denselben Rechten. Ein Parserfehler in untrusted Dateien könnte damit alles erreichen, was der aufrufende Benutzer darf. Außerdem fehlen ein hartes Speicherlimit und das sichere Beenden ganzer Prozessbäume.

## Entscheidung (geplant)

```
AXSafe Desktop (Benutzer) ──Named Pipe v1 (ACL)──► axsafe-service (LocalSystem, minimal)
                                                      │ öffnet Datei selbst (Handle, Identität)
                                                      │ übergibt NUR Bytes/Section, keinen Pfad
                                                      ▼
                                       axsafe-worker.exe (pro Auftrag)
                                       · Restricted Token / AppContainer ohne Fähigkeiten
                                       · Job Object: Speicherlimit, CPU-Zeit, KILL_ON_JOB_CLOSE,
                                         ActiveProcessLimit, keine UI-Handles
                                       · Process Mitigations: kein dynamischer Code (außer
                                         YARA-X/wasmtime – zu prüfen), Image-Load nur signiert,
                                         Child-Process-Policy (ClamAV-Ausnahme dokumentiert)
                                       · kein Netzwerk (AppContainer ohne internetClient)
```

### IPC-Vertrag `axsafe.ipc/1`

* Named Pipe `\\.\pipe\AXSafe.v1`, `PIPE_REJECT_REMOTE_CLIENTS`, DACL: SYSTEM + interaktive Benutzer nur Lesen/Schreiben auf die Pipe.
* Clientidentität über `GetNamedPipeClientProcessId` + Token-SID, Sitzungs-ID muss zur Sitzung des Aufrufers passen.
* Nachrichten: Längenpräfix, Höchstgröße 64 KiB, JSON mit Schema-Version, Nonce + monoton steigende Sequenz gegen Replay mutierender Anfragen.
* Erlaubte Aufträge: `ScanPaths`, `CancelJob`, `GetHealth`, `GetReport`. **Keine** freien Lösch-, Kopier- oder Shell-Befehle.
* Rollen: Standardbenutzer darf scannen und eigene Berichte lesen; Policies/Ausnahmen nur Administrator (AXS-017).

## Tests, die vor „erfüllt“ bestehen müssen

| Abnahme | Test |
| --- | --- |
| T-013 | Testworker versucht `C:\Windows\System32\drivers\etc\hosts` zu schreiben und `example.com:443` zu verbinden → beides scheitert, Job wird beendet, Status `Error` |
| T-014 | Fremde Sitzung, anderer Benutzer, 1-MiB-Nachricht, wiederholte Nonce → abgewiesen und protokolliert |
| T-021 | Worker-Absturz (Testmodus) → `Error`, Dienst läuft weiter |
| T-022 | Regel mit hohem Speicherbedarf → Job-Speicherlimit greift → `Error`/`Timeout`, Host bleibt bedienbar |
| B-11 | Hängende Engine mit Enkelprozess → gesamter Baum über Job Object beendet |

## Offene Fragen

* Verträgt sich wasmtime (YARA-X) mit `ProhibitDynamicCode`? Falls nein: eigene Ausnahme nur für den YARA-Worker, dokumentiert.
* ClamAV unter AppContainer: Zugriff auf Signaturdatenbank über explizite ACL.
* Alles muss auf Windows 10 LTSC 19044 im Labor (B-02) nachgewiesen werden.
