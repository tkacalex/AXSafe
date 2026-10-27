//! Fortsetzen abgebrochener Aufträge (AXS-026).
//!
//! Während eines Scans wird jede fertige Datei als JSON-Zeile in eine
//! Fortsetzungsdatei geschrieben (Kopfzeile mit Versionsschlüssel). Beim
//! Fortsetzen wird ein früheres Ergebnis nur übernommen, wenn
//!
//! * der Versionsschlüssel gleich ist (AXSafe, Engines, Regel-/Signaturstand,
//!   Heuristik, Richtlinie, Grenzen) – sonst wird **alles** neu geprüft,
//! * die Datei erneut gelesen wurde und ihr **SHA-256 gleich** ist (an den
//!   Inhalt gebunden, nicht an Zeitstempel),
//! * das frühere Ergebnis vollständig war (keine Lücke).
//!
//! Die Datei liegt beim Benutzer (CLI) bzw. im Dienstordner; wer sie
//! verändern kann, hat ohnehin die Rechte des Auftraggebers. Kaputte Zeilen
//! werden gezählt und ignoriert, nie als Ergebnis übernommen.

use crate::engine::EngineInfo;
use crate::report::{FileResult, ObjectStatus};
use crate::scan::Progress;
use crate::scanjob::{ScanKind, Trigger};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub const CHECKPOINT_SCHEMA: &str = "axsafe.fortsetzung/1";
pub const MAX_CHECKPOINT_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 1024 * 1024;
/// Höchstalter einer Fortsetzungsdatei.
pub const MAX_AGE_DAYS: i64 = 7;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointHeader {
    pub schema: String,
    pub job_id: String,
    pub kind: ScanKind,
    #[serde(default)]
    pub trigger: Trigger,
    pub roots: Vec<String>,
    pub version_key: String,
    pub created_utc: String,
}

/// Schlüssel über alles, was ein Ergebnis beeinflusst.
pub fn version_key(
    infos: &[EngineInfo],
    policy_version: &str,
    limits: &crate::report::ScanLimits,
) -> String {
    let mut h = Sha256::new();
    h.update(crate::AXSAFE_VERSION.as_bytes());
    h.update(b"\0");
    h.update(crate::heuristics::HEURISTICS_VERSION.as_bytes());
    for i in infos {
        h.update(b"\0engine\0");
        h.update(i.name.as_bytes());
        h.update(b"\0");
        h.update(i.engine_version.as_bytes());
        h.update(b"\0");
        h.update(i.content_version.as_bytes());
        h.update(b"\0");
        h.update(format!("{:?}", i.health).as_bytes());
    }
    h.update(b"\0policy\0");
    h.update(policy_version.as_bytes());
    h.update(b"\0limits\0");
    h.update(serde_json::to_vec(limits).unwrap_or_default());
    hex::encode(h.finalize())
}

/// Schreibt Kopf und jedes Ergebnis sofort (mit `flush`) – überlebt einen
/// Abbruch oder Absturz bis zur letzten vollständigen Zeile.
pub struct CheckpointWriter<'a> {
    file: File,
    inner: &'a mut dyn Progress,
    pub error: Option<String>,
}

impl<'a> CheckpointWriter<'a> {
    /// Legt die Datei NEU an (bestehende werden nie überschrieben).
    pub fn create(
        path: &Path,
        header: &CheckpointHeader,
        inner: &'a mut dyn Progress,
    ) -> std::io::Result<Self> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let mut line = serde_json::to_vec(header).map_err(std::io::Error::other)?;
        line.push(b'\n');
        file.write_all(&line)?;
        file.flush()?;
        Ok(CheckpointWriter {
            file,
            inner,
            error: None,
        })
    }
}

impl Progress for CheckpointWriter<'_> {
    fn on_result(&mut self, r: &FileResult) {
        self.inner.on_result(r);
        if self.error.is_some() {
            return;
        }
        let res = serde_json::to_vec(r)
            .map_err(std::io::Error::other)
            .and_then(|mut l| {
                l.push(b'\n');
                self.file.write_all(&l)?;
                self.file.flush()
            });
        if let Err(e) = res {
            self.error = Some(format!("Fortsetzungsdatei nicht schreibbar: {e}"));
        }
    }
}

/// Geladener Fortsetzungsstand.
#[derive(Debug)]
pub struct Resume {
    pub header: CheckpointHeader,
    entries: HashMap<String, FileResult>,
    pub version_mismatch: bool,
    pub ignored_lines: u64,
    reused: AtomicU64,
}

/// Angaben für den Bericht.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeInfo {
    pub from_job_id: String,
    pub previous_results: u64,
    pub reused: u64,
    pub version_mismatch: bool,
    pub ignored_lines: u64,
    pub note: String,
}

impl Resume {
    /// Liest eine Fortsetzungsdatei begrenzt ein.
    pub fn load(path: &Path, current_key: &str) -> Result<Resume, String> {
        let f = File::open(path).map_err(|e| format!("Fortsetzungsdatei nicht lesbar: {e}"))?;
        let mut r = BufReader::new(f.take(MAX_CHECKPOINT_BYTES));
        let mut first = String::new();
        r.read_line(&mut first)
            .map_err(|e| format!("Kopfzeile nicht lesbar: {e}"))?;
        let header: CheckpointHeader = serde_json::from_str(first.trim_end())
            .map_err(|e| format!("Kopfzeile ungültig: {e}"))?;
        if header.schema != CHECKPOINT_SCHEMA {
            return Err(format!("unbekanntes Schema {:?}", header.schema));
        }
        // Alte Fortsetzungsdateien nicht verwenden: je länger eine Datei
        // liegt, desto eher wurde sie verändert oder ist der Stand überholt.
        let created = chrono::DateTime::parse_from_rfc3339(&header.created_utc)
            .map_err(|e| format!("Erstellzeit ungültig: {e}"))?;
        let age = chrono::Utc::now().signed_duration_since(created);
        if age > chrono::Duration::days(MAX_AGE_DAYS) || age < chrono::Duration::minutes(-5) {
            return Err(format!(
                "Fortsetzungsdatei ist älter als {MAX_AGE_DAYS} Tage oder liegt in der Zukunft – bitte neu prüfen"
            ));
        }
        let mut entries = HashMap::new();
        let mut ignored = 0u64;
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n = (&mut r)
                .take(MAX_LINE_BYTES as u64 + 1)
                .read_until(b'\n', &mut buf)
                .map_err(|e| format!("Fortsetzungsdatei nicht lesbar: {e}"))?;
            if n == 0 {
                break;
            }
            if buf.len() > MAX_LINE_BYTES || buf.last() != Some(&b'\n') {
                // Zu lang oder abgeschnitten (Abbruch mitten im Schreiben).
                ignored += 1;
                if buf.len() > MAX_LINE_BYTES {
                    // Rest der überlangen Zeile verwerfen.
                    let mut skip = Vec::new();
                    let _ = r.read_until(b'\n', &mut skip);
                }
                continue;
            }
            match serde_json::from_slice::<FileResult>(&buf) {
                Ok(fr) => {
                    entries.insert(fr.path.clone(), fr);
                }
                Err(_) => ignored += 1,
            }
        }
        let version_mismatch = header.version_key != current_key;
        Ok(Resume {
            header,
            entries,
            version_mismatch,
            ignored_lines: ignored,
            reused: AtomicU64::new(0),
        })
    }

    /// Früheres Ergebnis, wenn es für genau diesen Inhalt übernommen werden darf.
    pub fn reusable(&self, path: &str, sha256: &str) -> Option<&FileResult> {
        if self.version_mismatch {
            return None;
        }
        let prev = self.entries.get(path)?;
        let ok = prev.sha256.as_deref() == Some(sha256)
            && prev.gaps.is_empty()
            && matches!(
                prev.status,
                ObjectStatus::NoDetection | ObjectStatus::Detection
            );
        if ok {
            self.reused.fetch_add(1, Ordering::Relaxed);
            Some(prev)
        } else {
            None
        }
    }

    pub fn info(&self) -> ResumeInfo {
        let reused = self.reused.load(Ordering::Relaxed);
        ResumeInfo {
            from_job_id: self.header.job_id.clone(),
            previous_results: self.entries.len() as u64,
            reused,
            version_mismatch: self.version_mismatch,
            ignored_lines: self.ignored_lines,
            note: if self.version_mismatch {
                "Engine-, Regel-, Richtlinien- oder Programmstand hat sich geändert: \
                 kein früheres Ergebnis übernommen, alles neu geprüft"
                    .into()
            } else {
                format!(
                    "{reused} Ergebnis(se) übernommen (gleicher Inhalt per SHA-256, gleicher \
                     Engine-/Regelstand, früher vollständig); geänderte, neue oder früher \
                     unvollständige Objekte neu geprüft"
                )
            },
        }
    }
}
