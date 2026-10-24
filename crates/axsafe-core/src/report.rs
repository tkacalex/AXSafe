//! Maschinenlesbarer Scanbericht (AXS-015, AXS-016 Teil, AXS-026 Teil).
//!
//! Jeder Bericht nennt Umfang, Engines, Inhaltsstände, Policy, Zeit und alle
//! Prüflücken. Zählungen stammen ausschließlich aus den tatsächlich
//! verarbeiteten Objekten.

use crate::engine::{EngineInfo, EngineOutcome};
use crate::filetype::FileKind;
use crate::identity::FileIdentity;
use crate::verdict::{Action, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Hinweis, der in jedem Bericht steht.
pub const DISCLAIMER_DE: &str =
    "AXSafe Vorversion: Ergebnis gilt nur für den angegebenen Umfang, die \
genannten Engines und Inhaltsstände. 'Nichts erkannt' ist kein Beweis für Harmlosigkeit. \
Kein Echtzeitschutz, keine Quarantäne, kein Ersatz für einen aktiven Virenschutz.";

/// Grenzen des Scanauftrags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanLimits {
    /// Größere Dateien werden nicht gelesen und als `Unsupported` gemeldet.
    pub max_file_size: u64,
    /// Zeitbudget je Engine und Objekt in Millisekunden.
    pub engine_timeout_ms: u64,
    /// Maximale Verzeichnistiefe.
    pub max_depth: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        ScanLimits {
            max_file_size: 256 * 1024 * 1024,
            engine_timeout_ms: 30_000,
            max_depth: 64,
        }
    }
}

/// Umfang eines Scanauftrags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanScope {
    pub roots: Vec<String>,
    pub engines: Vec<EngineInfo>,
    pub limits: ScanLimits,
    /// Links und Reparsepunkte werden nicht verfolgt.
    pub follows_links: bool,
}

/// Art des Objekts im Dateisystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    File,
    Directory,
    Link,
    Other,
    Unknown,
}

/// Ergebnis für ein einzelnes Objekt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileResult {
    pub path: String,
    pub object_type: ObjectType,
    pub verdict: Verdict,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub file_kind: Option<FileKind>,
    pub identity: Option<FileIdentity>,
    pub engines: Vec<EngineOutcome>,
    pub notes: Vec<String>,
    pub action: Action,
    pub scanned_utc: String,
}

/// Zusammenfassung, ausschließlich aus `files` berechnet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub objects: u64,
    pub bytes_read: u64,
    pub detections: u64,
    pub incomplete: u64,
    pub no_detection: u64,
    pub by_verdict: BTreeMap<String, u64>,
}

impl Summary {
    pub fn from_files(files: &[FileResult]) -> Self {
        let mut s = Summary::default();
        for v in Verdict::ALL {
            s.by_verdict.insert(format!("{v:?}"), 0);
        }
        for f in files {
            s.objects += 1;
            if f.sha256.is_some() {
                s.bytes_read += f.size.unwrap_or(0);
            }
            *s.by_verdict.entry(format!("{:?}", f.verdict)).or_default() += 1;
            if f.verdict.is_detection() {
                s.detections += 1;
            } else if f.verdict.is_incomplete() {
                s.incomplete += 1;
            } else {
                s.no_detection += 1;
            }
        }
        s
    }
}

/// Vollständiger Scanbericht.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema: String,
    pub job_id: String,
    pub axsafe_version: String,
    pub policy_version: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub duration_ms: u64,
    pub scope: ScanScope,
    /// `true` nur, wenn der Auftrag nicht abgebrochen wurde und kein Objekt
    /// unvollständig geprüft blieb.
    pub complete: bool,
    pub cancelled: bool,
    /// Gesamtbewertung: Funde vor Prüflücken vor „nichts erkannt“.
    pub overall: Verdict,
    pub summary: Summary,
    pub files: Vec<FileResult>,
    pub disclaimer: String,
}

/// Gesamtbewertung über viele Objekte.
///
/// Anders als [`crate::verdict::aggregate`] (ein Objekt) stehen hier Funde an
/// erster Stelle, damit ein Fund in einem großen Verzeichnis nicht hinter einer
/// einzelnen geänderten Datei verschwindet. Prüflücken stehen vor „nichts
/// erkannt“.
pub fn overall_verdict(files: &[FileResult]) -> Verdict {
    let order = [
        Verdict::Malicious,
        Verdict::Suspicious,
        Verdict::Pua,
        Verdict::ChangedDuringScan,
        Verdict::Error,
        Verdict::Timeout,
        Verdict::AccessDenied,
        Verdict::Encrypted,
        Verdict::Unsupported,
    ];
    for v in order {
        if files.iter().any(|f| f.verdict == v) {
            return v;
        }
    }
    Verdict::NoDetection
}
