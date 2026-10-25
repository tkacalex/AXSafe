//! Einfaches, größenbegrenztes Protokoll des Dienstes (abgewiesene
//! Verbindungen, Start/Stopp). Keine Nutzdaten, keine Dateiinhalte.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Log {
    path: Option<PathBuf>,
    lock: Mutex<()>,
    max_bytes: u64,
}

impl Log {
    pub fn new(path: Option<PathBuf>) -> Self {
        Log {
            path,
            lock: Mutex::new(()),
            max_bytes: 1024 * 1024,
        }
    }

    pub fn line(&self, msg: &str) {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let line = format!(
            "{} {}\n",
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            msg.replace(['\r', '\n'], " ")
        );
        let Some(p) = &self.path else {
            eprint!("{line}");
            return;
        };
        if std::fs::metadata(p)
            .map(|m| m.len() > self.max_bytes)
            .unwrap_or(false)
        {
            let _ = std::fs::rename(p, p.with_extension("log.1"));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}
