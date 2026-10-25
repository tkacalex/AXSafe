//! Einfaches, größenbegrenztes Protokoll des Dienstes (abgewiesene
//! Verbindungen, Start/Stopp). Keine Nutzdaten, keine Dateiinhalte.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Höchstlänge einer Protokollzeile (Datenmenge begrenzen, AXS-016/020).
pub const MAX_LINE_CHARS: usize = 4096;

/// Eine Zeile für das Protokoll: keine Zeilenumbrüche (keine gefälschten
/// Zeilen), Steuerzeichen entfernt, Länge begrenzt, und Werte hinter
/// typischen Geheimnis-Schlüsseln geschwärzt (AXS-020).
pub fn sanitize(msg: &str) -> String {
    let mut s: String = msg
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    for key in [
        "password",
        "passwort",
        "kennwort",
        "token",
        "secret",
        "apikey",
        "api_key",
        "authorization",
        "bearer",
    ] {
        let mut from = 0;
        loop {
            let lower = s.to_ascii_lowercase();
            let Some(i) = lower[from..].find(key).map(|i| i + from) else {
                break;
            };
            let mut j = i + key.len();
            let bytes = s.as_bytes();
            while j < s.len() && matches!(bytes[j], b' ' | b'=' | b':' | b'"' | b'\'') {
                j += 1;
            }
            let end = s[j..]
                .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\'' | '&'))
                .map(|k| j + k)
                .unwrap_or(s.len());
            if end > j {
                s.replace_range(j..end, "***");
                from = j + 3;
            } else {
                from = j;
            }
            if from >= s.len() {
                break;
            }
        }
    }
    if s.chars().count() > MAX_LINE_CHARS {
        s = s.chars().take(MAX_LINE_CHARS).collect();
        s.push_str(" …[gekürzt]");
    }
    s
}

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
            sanitize(msg)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// T-020: keine Geheimnisse, keine eingeschleusten Zeilen, begrenzte Länge.
    #[test]
    fn log_lines_are_sanitized() {
        let s = sanitize("Login password=Hunter2 token: abc.def\nGEFÄLSCHT 2026 Auftrag ok");
        assert!(!s.contains("Hunter2") && !s.contains("abc.def"), "{s}");
        assert!(s.contains("password=***"), "{s}");
        assert!(!s.contains('\n'));
        let long = "x".repeat(10_000);
        assert!(sanitize(&long).chars().count() < MAX_LINE_CHARS + 20);
        assert_eq!(sanitize("Auftrag 1 für Dima"), "Auftrag 1 für Dima");
    }

    #[test]
    fn log_rotates_at_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("service.log");
        let mut l = Log::new(Some(p.clone()));
        l.max_bytes = 200;
        for i in 0..20 {
            l.line(&format!("Zeile {i} mit etwas Text zum Füllen"));
        }
        assert!(std::fs::metadata(&p).unwrap().len() <= 400);
        assert!(p.with_extension("log.1").exists());
    }
}
