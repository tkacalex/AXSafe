//! Rechtebeschränkung des Workers.
//!
//! * **Windows (Zielplattform):** Der Host startet den Worker in einem
//!   AppContainer ohne Fähigkeiten und im Job Object. Der Worker prüft beim
//!   Start, dass sein Token tatsächlich ein AppContainer-Token ohne
//!   Fähigkeiten ist; sonst arbeitet er nicht (fail closed).
//! * **Linux (Entwicklung/CI):** Der Worker beschränkt sich selbst mit
//!   Landlock, bevor er irgendeine Eingabe liest: kein Dateizugriff,
//!   kein Programmstart, keine TCP-Verbindungen (ab Landlock-ABI 4).
//!   UDP wird von Landlock nicht erfasst – das ist eine bekannte Grenze.
//!
//! Ob die Beschränkung greift, wird zusätzlich vom Host mit einer Probe
//! nachgewiesen (Schreib-, Lese-, Verbindungs- und Startversuch).

use crate::protocol::SandboxReport;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// Wendet die Beschränkung an (Linux) bzw. stellt sie fest (Windows).
pub fn apply() -> SandboxReport {
    #[cfg(target_os = "linux")]
    {
        linux::apply()
    }
    #[cfg(windows)]
    {
        windows::verify()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        SandboxReport {
            kind: "none".into(),
            filesystem: false,
            network: false,
            detail: "keine Rechtebeschränkung auf dieser Plattform".into(),
        }
    }
}

/// Unter Windows ist ein nicht abgeschotteter Worker unzulässig.
pub fn required() -> bool {
    cfg!(windows)
}
