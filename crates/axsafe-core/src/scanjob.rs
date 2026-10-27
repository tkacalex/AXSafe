//! Scanarten (AXS-026): Schnell, Voll, Benutzerdefiniert, Wechseldatenträger
//! sowie der Auslöser (manuell, Kontextmenü, Zeitplan, Dienst).
//!
//! Die Scanart bestimmt nur die **Ziele**. Was sie nicht abdeckt, steht im
//! Bericht (`scope.kind_note`) – eine Schnellprüfung ist keine Vollprüfung.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    /// Typische Ablage- und Autostartorte des Benutzers.
    Quick,
    /// Alle festen Laufwerke.
    Full,
    /// Vom Benutzer gewählte Dateien und Ordner.
    #[default]
    Custom,
    /// Angeschlossene Wechseldatenträger.
    Removable,
}

impl ScanKind {
    pub fn label(self) -> &'static str {
        match self {
            ScanKind::Quick => "Schnellprüfung",
            ScanKind::Full => "Vollständige Prüfung",
            ScanKind::Custom => "Benutzerdefinierte Prüfung",
            ScanKind::Removable => "Wechseldatenträger",
        }
    }

    /// Ehrliche Angabe, was diese Scanart NICHT abdeckt.
    pub fn coverage_note(self) -> &'static str {
        match self {
            ScanKind::Quick => {
                "Schnellprüfung: nur Dateien in Downloads, Desktop, Temp-Ordnern und \
                 Autostart-Ordnern. Nicht geprüft: übrige Ordner und Laufwerke, \
                 Autostart-Einträge der Registrierung, Dienste, Arbeitsspeicher."
            }
            ScanKind::Full => {
                "Vollständige Prüfung aller festen Laufwerke im Rahmen der Grenzen. \
                 Nicht geprüft: Arbeitsspeicher, Registrierung, Netzlaufwerke, \
                 Wechseldatenträger, Links/Junctions (nicht verfolgt)."
            }
            ScanKind::Custom => "Nur die angegebenen Dateien und Ordner.",
            ScanKind::Removable => {
                "Nur die zum Zeitpunkt des Starts angeschlossenen Wechseldatenträger. \
                 Kein automatischer Scan beim Anschließen."
            }
        }
    }

    pub fn parse(s: &str) -> Option<ScanKind> {
        match s.to_ascii_lowercase().as_str() {
            "schnell" | "quick" => Some(ScanKind::Quick),
            "voll" | "full" => Some(ScanKind::Full),
            "benutzer" | "custom" => Some(ScanKind::Custom),
            "wechsel" | "wechseldatentraeger" | "removable" => Some(ScanKind::Removable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    #[default]
    Manual,
    ContextMenu,
    Schedule,
    Service,
}

impl Trigger {
    pub fn parse(s: &str) -> Option<Trigger> {
        match s.to_ascii_lowercase().as_str() {
            "manuell" | "manual" => Some(Trigger::Manual),
            "kontextmenue" | "context_menu" => Some(Trigger::ContextMenu),
            "zeitplan" | "schedule" => Some(Trigger::Schedule),
            "dienst" | "service" => Some(Trigger::Service),
            _ => None,
        }
    }
}

/// Ergebnis der Zielermittlung: vorhandene Ziele und fehlende Orte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Targets {
    pub roots: Vec<PathBuf>,
    /// Orte, die zur Scanart gehören, aber nicht existieren (kein Fehler).
    pub missing: Vec<String>,
}

/// Schnellprüfung: Orte aus Umgebungsvariablen (für Tests austauschbar).
pub fn quick_targets(env: &dyn Fn(&str) -> Option<String>) -> Targets {
    let mut cand: Vec<PathBuf> = Vec::new();
    if cfg!(windows) {
        if let Some(home) = env("USERPROFILE") {
            cand.push(Path::new(&home).join("Downloads"));
            cand.push(Path::new(&home).join("Desktop"));
        }
        for v in ["TEMP", "TMP"] {
            if let Some(t) = env(v) {
                cand.push(PathBuf::from(t));
            }
        }
        if let Some(a) = env("APPDATA") {
            cand.push(Path::new(&a).join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
        }
        if let Some(p) = env("ProgramData") {
            cand.push(Path::new(&p).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"));
        }
        if let Some(pub_) = env("PUBLIC") {
            cand.push(Path::new(&pub_).join("Desktop"));
        }
    } else {
        if let Some(home) = env("HOME") {
            cand.push(Path::new(&home).join("Downloads"));
            cand.push(Path::new(&home).join("Desktop"));
            cand.push(Path::new(&home).join(".config/autostart"));
        }
        cand.push(PathBuf::from(
            env("TMPDIR").unwrap_or_else(|| "/tmp".into()),
        ));
    }
    let mut t = Targets::default();
    for c in cand {
        let key = c.to_string_lossy().to_lowercase();
        if t.roots
            .iter()
            .any(|r| r.to_string_lossy().to_lowercase() == key)
        {
            continue;
        }
        if c.is_dir() {
            t.roots.push(c);
        } else {
            t.missing.push(c.display().to_string());
        }
    }
    t
}

/// Laufwerke einer Art (Windows `GetDriveTypeW`): 2 = Wechsel, 3 = fest.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn drives_of_type(wanted: u32) -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    // SAFETY: einfache Abfragen ohne Zeiger außer dem nullterminierten Pfad.
    let mask = unsafe { GetLogicalDrives() };
    let mut out = Vec::new();
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let root = format!("{}:\\", (b'A' + i as u8) as char);
        let wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
        let t = unsafe { GetDriveTypeW(wide.as_ptr()) };
        if t == wanted {
            out.push(PathBuf::from(root));
        }
    }
    out
}

pub const DRIVE_REMOVABLE: u32 = 2;
pub const DRIVE_FIXED: u32 = 3;

/// Ziele einer Scanart. Benutzerdefiniert: die übergebenen Pfade.
pub fn targets(kind: ScanKind, custom: &[PathBuf]) -> Result<Targets, String> {
    match kind {
        ScanKind::Custom => Ok(Targets {
            roots: custom.to_vec(),
            missing: Vec::new(),
        }),
        ScanKind::Quick => Ok(quick_targets(&|k| std::env::var(k).ok())),
        #[cfg(windows)]
        ScanKind::Full => Ok(Targets {
            roots: drives_of_type(DRIVE_FIXED),
            missing: Vec::new(),
        }),
        #[cfg(windows)]
        ScanKind::Removable => Ok(Targets {
            roots: drives_of_type(DRIVE_REMOVABLE),
            missing: Vec::new(),
        }),
        #[cfg(not(windows))]
        ScanKind::Full | ScanKind::Removable => Err(format!(
            "{} wird nur unter Windows unterstützt; bitte Ordner angeben",
            kind.label()
        )),
    }
}

/// Zählt Dateien vorab für eine Fortschrittsanzeige. `None`, wenn Grenze
/// oder Zeitbudget erreicht wurde – dann wird kein Prozentwert angezeigt.
/// Links werden nicht verfolgt.
pub fn count_files(roots: &[PathBuf], cap: u64, budget: Duration) -> Option<u64> {
    let deadline = Instant::now() + budget;
    let mut n = 0u64;
    let mut stack: Vec<PathBuf> = roots.to_vec();
    while let Some(p) = stack.pop() {
        if n > cap || Instant::now() > deadline {
            return None;
        }
        let Ok(m) = std::fs::symlink_metadata(&p) else {
            n += 1;
            continue;
        };
        if m.file_type().is_symlink() || crate::scan::is_reparse_point(&m) {
            n += 1;
        } else if m.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                stack.extend(rd.flatten().map(|e| e.path()));
            } else {
                n += 1;
            }
        } else {
            n += 1;
        }
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_targets_only_existing_and_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("Downloads")).unwrap();
        let tmp = dir.path().join("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let h = home.display().to_string();
        let t = tmp.display().to_string();
        let env = move |k: &str| -> Option<String> {
            match k {
                "HOME" | "USERPROFILE" => Some(h.clone()),
                "TMPDIR" | "TEMP" | "TMP" => Some(t.clone()),
                _ => None,
            }
        };
        let r = quick_targets(&env);
        assert!(r.roots.contains(&home.join("Downloads")));
        assert!(r.roots.contains(&tmp));
        assert_eq!(r.roots.iter().filter(|p| **p == tmp).count(), 1);
        assert!(r.missing.iter().any(|m| m.contains("Desktop")));
    }

    #[test]
    fn kinds_parse_and_say_what_they_miss() {
        assert_eq!(ScanKind::parse("schnell"), Some(ScanKind::Quick));
        assert_eq!(ScanKind::parse("voll"), Some(ScanKind::Full));
        assert_eq!(ScanKind::parse("wechsel"), Some(ScanKind::Removable));
        assert_eq!(ScanKind::parse("x"), None);
        assert!(ScanKind::Quick.coverage_note().contains("Nicht geprüft"));
        assert!(ScanKind::Full.coverage_note().contains("Arbeitsspeicher"));
        assert_eq!(Trigger::parse("zeitplan"), Some(Trigger::Schedule));
    }

    #[test]
    fn count_stops_at_cap() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..20 {
            std::fs::write(dir.path().join(format!("{i}.txt")), b"x").unwrap();
        }
        let roots = vec![dir.path().to_path_buf()];
        assert_eq!(count_files(&roots, 100, Duration::from_secs(5)), Some(20));
        assert_eq!(count_files(&roots, 5, Duration::from_secs(5)), None);
    }

    #[cfg(windows)]
    #[test]
    fn full_scan_targets_include_system_drive() {
        let t = targets(ScanKind::Full, &[]).unwrap();
        let sys = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        assert!(
            t.roots.iter().any(|r| r
                .display()
                .to_string()
                .eq_ignore_ascii_case(&format!("{sys}\\"))),
            "{t:?}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn full_scan_is_honestly_unsupported_off_windows() {
        assert!(targets(ScanKind::Full, &[]).is_err());
    }
}
