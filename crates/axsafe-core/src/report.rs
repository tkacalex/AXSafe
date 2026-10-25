//! Maschinenlesbarer Scanbericht, Schema `axsafe.scan-report/2`.
//!
//! Grundsatz (Befund 2): **Fund** und **Vollständigkeit** sind unabhängig.
//! Ein Objekt kann gleichzeitig einen Fund *und* Prüflücken haben; beides
//! wird getrennt ausgewiesen und gezählt.
//!
//! ## Zähler (eindeutig definiert)
//!
//! | Feld | Bedeutung |
//! | --- | --- |
//! | `objects_total` | alle Einträge in `files` |
//! | `objects_read` | Objekte, deren Inhalt gelesen und mindestens einer Engine übergeben wurde |
//! | `with_detection` | Objekte mit mindestens einem Fund |
//! | `incomplete` | Objekte mit mindestens einer Prüflücke (unabhängig vom Fund) |
//! | `detection_and_incomplete` | Schnittmenge der beiden vorigen |
//! | `no_detection_complete` | ohne Fund **und** ohne Lücke |
//! | `objects_by_gap_state` | Objekte je Lückenzustand; ein Objekt kann in mehreren Zeilen stehen |
//!
//! Invariante (getestet): `with_detection + incomplete − detection_and_incomplete
//! + no_detection_complete = objects_total`.

use crate::engine::{EngineInfo, EngineOutcome, Gap};
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
    /// Größere Dateien werden nicht gelesen und als Lücke gemeldet.
    pub max_file_size: u64,
    /// Gemeinsames Zeitbudget je Engine-Aufruf und Objekt in Millisekunden.
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

/// Bewusst vom Auftrag ausgenommenes Objekt (z. B. die eigene Berichtsdatei).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExcludedObject {
    pub path: String,
    pub reason: String,
}

/// Umfang eines Scanauftrags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanScope {
    /// Angeforderte Pfade, exakt wie übergeben.
    pub roots: Vec<String>,
    pub engines: Vec<EngineInfo>,
    pub limits: ScanLimits,
    /// Links und Reparsepunkte werden nicht verfolgt.
    pub follows_links: bool,
    #[serde(default)]
    pub excluded: Vec<ExcludedObject>,
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

/// Zusammengefasster Objektstatus aus Fund und Vollständigkeit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectStatus {
    /// Fund, vollständig geprüft.
    Detection,
    /// Fund **und** mindestens eine Prüflücke.
    DetectionIncomplete,
    /// Kein Fund, vollständig geprüft (im angegebenen Umfang).
    NoDetection,
    /// Kein Fund, aber mindestens eine Prüflücke.
    Incomplete,
}

impl ObjectStatus {
    pub fn from_parts(detection: Verdict, gaps: &[Gap]) -> Self {
        match (detection.is_detection(), gaps.is_empty()) {
            (true, true) => ObjectStatus::Detection,
            (true, false) => ObjectStatus::DetectionIncomplete,
            (false, true) => ObjectStatus::NoDetection,
            (false, false) => ObjectStatus::Incomplete,
        }
    }

    pub fn label_de(self) -> &'static str {
        match self {
            ObjectStatus::Detection => "Fund",
            ObjectStatus::DetectionIncomplete => "Fund vorhanden; zusätzliche Prüflücke",
            ObjectStatus::NoDetection => "Ohne Fund (im geprüften Umfang)",
            ObjectStatus::Incomplete => "Nicht vollständig geprüft",
        }
    }
}

/// Ergebnis für ein einzelnes Objekt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileResult {
    pub path: String,
    pub object_type: ObjectType,
    /// Höchste Fundbewertung: `Malicious`, `Suspicious`, `PUA` oder `NoDetection`.
    pub detection: Verdict,
    /// Alle Prüflücken dieses Objekts (leer = vollständig geprüft).
    pub gaps: Vec<Gap>,
    pub status: ObjectStatus,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub file_kind: Option<FileKind>,
    pub identity: Option<FileIdentity>,
    pub engines: Vec<EngineOutcome>,
    pub notes: Vec<String>,
    pub action: Action,
    pub scanned_utc: String,
}

impl FileResult {
    /// `true`, wenn der Inhalt gelesen und an mindestens eine Engine übergeben wurde.
    pub fn content_read(&self) -> bool {
        self.sha256.is_some() && !self.engines.is_empty()
    }
}

/// Zusammenfassung, ausschließlich aus `files` berechnet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub objects_total: u64,
    pub objects_read: u64,
    pub bytes_read: u64,
    pub with_detection: u64,
    pub incomplete: u64,
    pub detection_and_incomplete: u64,
    pub no_detection_complete: u64,
    pub objects_by_detection: BTreeMap<String, u64>,
    pub objects_by_gap_state: BTreeMap<String, u64>,
}

impl Summary {
    pub fn from_files(files: &[FileResult]) -> Self {
        let mut s = Summary::default();
        for v in [Verdict::Malicious, Verdict::Suspicious, Verdict::Pua] {
            s.objects_by_detection.insert(format!("{v:?}"), 0);
        }
        for v in Verdict::ALL.into_iter().filter(|v| v.is_incomplete()) {
            s.objects_by_gap_state.insert(format!("{v:?}"), 0);
        }
        for f in files {
            s.objects_total += 1;
            if f.content_read() {
                s.objects_read += 1;
                s.bytes_read += f.size.unwrap_or(0);
            }
            let det = f.detection.is_detection();
            let inc = !f.gaps.is_empty();
            if det {
                s.with_detection += 1;
                *s.objects_by_detection
                    .entry(format!("{:?}", f.detection))
                    .or_default() += 1;
            }
            if inc {
                s.incomplete += 1;
                let mut states: Vec<Verdict> = f.gaps.iter().map(|g| g.state).collect();
                states.sort_by_key(|v| format!("{v:?}"));
                states.dedup();
                for st in states {
                    *s.objects_by_gap_state.entry(format!("{st:?}")).or_default() += 1;
                }
            }
            if det && inc {
                s.detection_and_incomplete += 1;
            }
            if !det && !inc {
                s.no_detection_complete += 1;
            }
        }
        s
    }

    /// Prüft die dokumentierte Zählinvariante.
    pub fn is_consistent(&self) -> bool {
        self.with_detection + self.incomplete - self.detection_and_incomplete
            + self.no_detection_complete
            == self.objects_total
            && self.detection_and_incomplete <= self.with_detection.min(self.incomplete)
    }
}

/// Ergebnis des gesamten Auftrags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobOutcome {
    /// Mindestens ein Fund, Auftrag vollständig.
    Detection,
    /// Mindestens ein Fund **und** Prüflücken oder Auftragsfehler.
    DetectionIncomplete,
    /// Kein Fund, vollständig geprüft.
    NoDetection,
    /// Kein Fund, aber Prüflücken oder Auftragsfehler.
    Incomplete,
    /// Der Umfang enthielt keine prüfbaren Objekte. Keine Aussage über Schutzwirkung.
    NothingScanned,
}

impl JobOutcome {
    /// Stabiler Exitcode der CLI.
    pub fn exit_code(self) -> u8 {
        match self {
            JobOutcome::NoDetection => 0,
            JobOutcome::Detection => 1,
            JobOutcome::Incomplete => 2,
            JobOutcome::DetectionIncomplete => 4,
            JobOutcome::NothingScanned => 5,
        }
    }

    pub fn label_de(self) -> &'static str {
        match self {
            JobOutcome::Detection => "Fund",
            JobOutcome::DetectionIncomplete => "Fund vorhanden; zusätzlich unvollständig geprüft",
            JobOutcome::NoDetection => {
                "Nichts erkannt (nur im geprüften Umfang, kein Beweis für Harmlosigkeit)"
            }
            JobOutcome::Incomplete => "Unvollständig geprüft, kein Fund im geprüften Teil",
            JobOutcome::NothingScanned => "Keine prüfbaren Objekte – es wurde nichts geprüft",
        }
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
    pub outcome: JobOutcome,
    /// Höchste Fundbewertung über alle Objekte.
    pub detection: Verdict,
    /// `true` nur, wenn mindestens ein Objekt geprüft wurde, kein Objekt eine
    /// Lücke hat, keine Auftragslücke besteht und nicht abgebrochen wurde.
    pub complete: bool,
    pub cancelled: bool,
    /// Lücken, die den ganzen Auftrag betreffen (z. B. beauftragte Engine
    /// nicht verfügbar, Abbruch), unabhängig von einzelnen Dateiergebnissen.
    pub job_gaps: Vec<Gap>,
    pub summary: Summary,
    pub files: Vec<FileResult>,
    pub disclaimer: String,
}

/// Höchste Fundbewertung über viele Werte.
pub fn highest_detection<I: IntoIterator<Item = Verdict>>(it: I) -> Verdict {
    let rank = |v: Verdict| match v {
        Verdict::Malicious => 3,
        Verdict::Suspicious => 2,
        Verdict::Pua => 1,
        _ => 0,
    };
    it.into_iter()
        .filter(|v| v.is_detection())
        .max_by_key(|v| rank(*v))
        .unwrap_or(Verdict::NoDetection)
}

/// Bestimmt das Auftragsergebnis aus Zählern, Auftragslücken und Abbruch.
pub fn job_outcome(summary: &Summary, job_gaps: &[Gap], cancelled: bool) -> (JobOutcome, bool) {
    let job_incomplete = cancelled || !job_gaps.is_empty();
    let outcome = if summary.with_detection > 0 {
        if job_incomplete || summary.incomplete > 0 {
            JobOutcome::DetectionIncomplete
        } else {
            JobOutcome::Detection
        }
    } else if summary.objects_total == 0 && !cancelled {
        // Befund 6: leerer Umfang. Ein Abbruch vor dem ersten Objekt ist
        // dagegen nicht „keine prüfbaren Objekte“, sondern unvollständig.
        JobOutcome::NothingScanned
    } else if job_incomplete || summary.incomplete > 0 {
        JobOutcome::Incomplete
    } else {
        JobOutcome::NoDetection
    };
    let complete = matches!(outcome, JobOutcome::Detection | JobOutcome::NoDetection);
    (outcome, complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::GapReason;

    fn file(detection: Verdict, gaps: Vec<Gap>) -> FileResult {
        FileResult {
            path: "x".into(),
            object_type: ObjectType::File,
            status: ObjectStatus::from_parts(detection, &gaps),
            detection,
            gaps,
            size: Some(1),
            sha256: Some("00".into()),
            file_kind: None,
            identity: None,
            engines: vec![],
            notes: vec![],
            action: Action::ReportOnly,
            scanned_utc: String::new(),
        }
    }

    fn g(state: Verdict) -> Gap {
        Gap::new(state, GapReason::EngineError, "test", "t")
    }

    #[test]
    fn detection_with_gap_is_both_counted_and_not_complete() {
        // Befund 2: Fund + Engine-Fehler → beides sichtbar, nicht vollständig.
        let files = vec![file(Verdict::Malicious, vec![g(Verdict::Error)])];
        let s = Summary::from_files(&files);
        assert_eq!(s.with_detection, 1);
        assert_eq!(s.incomplete, 1);
        assert_eq!(s.detection_and_incomplete, 1);
        assert!(s.is_consistent());
        let (o, complete) = job_outcome(&s, &[], false);
        assert_eq!(o, JobOutcome::DetectionIncomplete);
        assert!(!complete);
        assert_eq!(o.exit_code(), 4);
        assert_eq!(files[0].status, ObjectStatus::DetectionIncomplete);
    }

    #[test]
    fn combinations_keep_invariant() {
        let det = [
            Verdict::Malicious,
            Verdict::Suspicious,
            Verdict::Pua,
            Verdict::NoDetection,
        ];
        let gaps = [
            vec![],
            vec![g(Verdict::Error)],
            vec![g(Verdict::Timeout)],
            vec![g(Verdict::Unsupported)],
            vec![
                g(Verdict::Error),
                g(Verdict::Timeout),
                g(Verdict::Unsupported),
            ],
            vec![g(Verdict::Encrypted), g(Verdict::ChangedDuringScan)],
        ];
        let mut files = Vec::new();
        for d in det {
            for gs in &gaps {
                files.push(file(d, gs.clone()));
            }
        }
        let s = Summary::from_files(&files);
        assert!(s.is_consistent(), "{s:?}");
        assert_eq!(s.objects_total, 24);
        assert_eq!(s.with_detection, 18);
        assert_eq!(s.incomplete, 20);
        assert_eq!(s.detection_and_incomplete, 15);
        assert_eq!(s.no_detection_complete, 1);
        // Mehrfachlücken zählen pro Zustand, Objekte können überlappen.
        assert_eq!(s.objects_by_gap_state["Error"], 8);
        assert_eq!(s.objects_by_gap_state["Timeout"], 8);
        assert_eq!(s.objects_by_gap_state["Unsupported"], 8);
        assert_eq!(s.objects_by_detection["Malicious"], 6);
    }

    #[test]
    fn outcome_table() {
        let clean = Summary::from_files(&[file(Verdict::NoDetection, vec![])]);
        assert_eq!(
            job_outcome(&clean, &[], false),
            (JobOutcome::NoDetection, true)
        );
        assert_eq!(job_outcome(&clean, &[], true).0, JobOutcome::Incomplete);
        assert_eq!(
            job_outcome(&clean, &[g(Verdict::Error)], false).0,
            JobOutcome::Incomplete
        );
        let hit = Summary::from_files(&[file(Verdict::Pua, vec![])]);
        assert_eq!(job_outcome(&hit, &[], false), (JobOutcome::Detection, true));
        assert_eq!(
            job_outcome(&hit, &[g(Verdict::Error)], false).0,
            JobOutcome::DetectionIncomplete
        );
        // Befund 6: leerer Umfang ist nie „vollständig ohne Fund“.
        let empty = Summary::from_files(&[]);
        assert_eq!(
            job_outcome(&empty, &[], false),
            (JobOutcome::NothingScanned, false)
        );
        assert_eq!(
            job_outcome(&empty, &[g(Verdict::Error)], false),
            (JobOutcome::NothingScanned, false)
        );
        assert_eq!(JobOutcome::NothingScanned.exit_code(), 5);
        // Abbruch vor dem ersten Objekt: unvollständig, nicht „nichts zu prüfen“
        // (im Windows-Systemtest aufgefallen).
        assert_eq!(
            job_outcome(&empty, &[], true),
            (JobOutcome::Incomplete, false)
        );
        // Nur Lückenobjekte (z. B. nicht lesbare Datei): unvollständig, nicht „nichts geprüft“.
        let gap_only =
            Summary::from_files(&[file(Verdict::NoDetection, vec![g(Verdict::AccessDenied)])]);
        assert_eq!(job_outcome(&gap_only, &[], false).0, JobOutcome::Incomplete);
    }

    #[test]
    fn highest_detection_ignores_gaps() {
        assert_eq!(
            highest_detection([Verdict::Error, Verdict::Pua, Verdict::Malicious]),
            Verdict::Malicious
        );
        assert_eq!(
            highest_detection([Verdict::Error, Verdict::Timeout]),
            Verdict::NoDetection
        );
        assert_eq!(highest_detection([]), Verdict::NoDetection);
    }
}
