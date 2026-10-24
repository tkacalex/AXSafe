# Zielplattform (AXS-001)

Maschinenlesbare Fassung: [`platform-matrix.json`](platform-matrix.json)

## Gemessen am 24.10.2026 auf dem Zielgerät

| Merkmal | Wert | Quelle |
| --- | --- | --- |
| Betriebssystem | Microsoft Windows 10 Enterprise LTSC | msinfo32 |
| Version | 10.0.19044 Build 19044 (21H2) | msinfo32 |
| Build-Revision | 19044.7807 | Nutzerscreenshot (winver) |
| Architektur | **x64-based PC** – Annahme x64 damit **bestätigt** | msinfo32, Geräteinfo |
| Firmware | UEFI | msinfo32 |
| Secure Boot | **Aus** | msinfo32 |
| Virtualisierungsbasierte Sicherheit | läuft, aber **keine VBS-Dienste** (Speicherintegrität/HVCI nicht aktiv) | msinfo32 |
| Kernel-DMA-Schutz | Ein | msinfo32 |
| WDAC-Richtlinie | Erzwungen (Kernel), User-Mode aus | msinfo32 |
| Hardware | Alienware m15 R3, Core i7-10750H, 32 GB RAM | msinfo32 |

Die Edition ist **Enterprise LTSC**, nicht IoT Enterprise LTSC. Microsoft nennt für diese Edition den **12.01.2027** als reguläres Supportende [Q02]. Vor einer längerfristigen Veröffentlichung wird die Supportlage erneut geprüft (Blocker B-01).

## Was das für AXSafe bedeutet

* **x64 ist bestätigt.** Trotzdem muss AXSafe später auch 32-Bit-Programme und 32-Bit-Skripthosts prüfen können (AXS-047, AXS-049).
* **Secure Boot ist aus.** AXSafe setzt Secure Boot nicht voraus und schaltet nie Schutzfunktionen ab. Für die spätere Plattformprüfung (AXS-077) meldet AXSafe diesen Zustand als Risiko. *Empfehlung an den Besitzer:* Secure Boot im UEFI-Setup aktivieren, sofern keine Bootloader/Treiber das verhindern. Das ist eine Entscheidung des Besitzers und wird von AXSafe nicht automatisch geändert.
* **Speicherintegrität (HVCI) ist nicht aktiv.** Ein späterer AXSafe-Treiber muss trotzdem HVCI-kompatibel sein (T-058) und auf einem System *mit* aktiver Speicherintegrität laden.
* **Dieses Gerät ist der Alltagsrechner.** Treiberexperimente, Testsignierung und echte Malwareproben sind hier **verboten** (siehe [`lab/LAB-RULES.md`](../lab/LAB-RULES.md)). Dafür wird das getrennte Labor (AXS-008) benötigt.

## Nicht freigegeben

Windows 10 Home/Pro, andere LTSC-Stände, IoT Enterprise LTSC, ARM64, x86-Betriebssysteme sowie macOS, Linux, Android und iOS. Jede Kombination braucht eine eigene Supportentscheidung mit eigenen Tests.
