//! Scan-Orchestrierung (AXS-026 Teil: eigener Scan mit Abbruch).
//!
//! Ablauf je Datei:
//! 1. Objektart ohne Linkverfolgung bestimmen (Links/Reparsepunkte: Prüflücke).
//! 2. Datei öffnen (ohne Linkverfolgung, ohne Blockieren), Identität über das
//!    Handle lesen.
//! 3. Inhalt über **dasselbe** Handle lesen, SHA-256 bilden, Typ bestimmen.
//! 4. Alle Engines prüfen denselben Schnappschuss.
//! 5. Identität erneut lesen und Pfad erneut auflösen. Abweichung:
//!    [`Verdict::ChangedDuringScan`].
//!
//! Der Scanner **liest nur**. Er löscht, verschiebt oder startet nichts.

use crate::engine::{Engine, EngineHealth, EngineOutcome, ScanInput};
use crate::filetype;
use crate::identity::FileIdentity;
use crate::report::{
    overall_verdict, FileResult, ObjectType, ScanLimits, ScanReport, ScanScope, Summary,
    DISCLAIMER_DE,
};
use crate::verdict::{aggregate, Action, Verdict};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Fortschrittsmeldung an den Aufrufer (z. B. CLI oder Dienst).
pub trait Progress {
    fn on_result(&mut self, _result: &FileResult) {}
}

/// Kein Fortschritt.
pub struct NoProgress;
impl Progress for NoProgress {}

/// Ein Scanner mit festen Engines und Grenzen.
pub struct Scanner {
    engines: Vec<Box<dyn Engine>>,
    limits: ScanLimits,
}

fn now_utc() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn io_verdict(e: &io::Error) -> Verdict {
    match e.kind() {
        io::ErrorKind::PermissionDenied => Verdict::AccessDenied,
        _ => Verdict::Error,
    }
}

impl Scanner {
    pub fn new(engines: Vec<Box<dyn Engine>>, limits: ScanLimits) -> Self {
        Scanner { engines, limits }
    }

    pub fn limits(&self) -> &ScanLimits {
        &self.limits
    }

    /// Prüft die angegebenen Pfade. `cancel` kann jederzeit gesetzt werden.
    pub fn scan_paths(
        &self,
        roots: &[PathBuf],
        cancel: &AtomicBool,
        progress: &mut dyn Progress,
    ) -> ScanReport {
        let started = Instant::now();
        let started_utc = now_utc();
        let mut files = Vec::new();
        for root in roots {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            self.visit(root, 0, cancel, &mut files, progress);
        }
        let cancelled = cancel.load(Ordering::SeqCst);
        let summary = Summary::from_files(&files);
        let overall = overall_verdict(&files);
        ScanReport {
            schema: crate::REPORT_SCHEMA_VERSION.into(),
            job_id: uuid::Uuid::new_v4().to_string(),
            axsafe_version: crate::AXSAFE_VERSION.into(),
            policy_version: crate::POLICY_VERSION.into(),
            started_utc,
            finished_utc: now_utc(),
            duration_ms: started.elapsed().as_millis() as u64,
            scope: ScanScope {
                roots: roots.iter().map(|p| p.display().to_string()).collect(),
                engines: self.engines.iter().map(|e| e.info()).collect(),
                limits: self.limits.clone(),
                follows_links: false,
            },
            complete: !cancelled && summary.incomplete == 0,
            cancelled,
            overall,
            summary,
            files,
            disclaimer: DISCLAIMER_DE.into(),
        }
    }

    fn push(&self, out: &mut Vec<FileResult>, progress: &mut dyn Progress, r: FileResult) {
        progress.on_result(&r);
        out.push(r);
    }

    fn visit(
        &self,
        path: &Path,
        depth: usize,
        cancel: &AtomicBool,
        out: &mut Vec<FileResult>,
        progress: &mut dyn Progress,
    ) {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                let r = gap(
                    path,
                    ObjectType::Unknown,
                    io_verdict(&e),
                    format!("Metadaten nicht lesbar: {e}"),
                );
                return self.push(out, progress, r);
            }
        };
        let ft = meta.file_type();
        if ft.is_symlink() || is_reparse_point(&meta) {
            let r = gap(
                path,
                ObjectType::Link,
                Verdict::Unsupported,
                "Link oder Reparsepunkt: wird nicht verfolgt, Ziel nicht geprüft".into(),
            );
            return self.push(out, progress, r);
        }
        if ft.is_dir() {
            if depth >= self.limits.max_depth {
                let r = gap(
                    path,
                    ObjectType::Directory,
                    Verdict::Unsupported,
                    format!(
                        "Maximale Verzeichnistiefe {} erreicht: Inhalt nicht geprüft",
                        self.limits.max_depth
                    ),
                );
                return self.push(out, progress, r);
            }
            let entries = match fs::read_dir(path) {
                Ok(it) => it,
                Err(e) => {
                    let r = gap(
                        path,
                        ObjectType::Directory,
                        io_verdict(&e),
                        format!("Verzeichnis nicht lesbar: {e}"),
                    );
                    return self.push(out, progress, r);
                }
            };
            let mut children: Vec<PathBuf> = Vec::new();
            for entry in entries {
                match entry {
                    Ok(en) => children.push(en.path()),
                    Err(e) => {
                        let r = gap(
                            path,
                            ObjectType::Directory,
                            io_verdict(&e),
                            format!("Eintrag nicht lesbar: {e}"),
                        );
                        self.push(out, progress, r);
                    }
                }
            }
            children.sort();
            for child in children {
                self.visit(&child, depth + 1, cancel, out, progress);
            }
            return;
        }
        if !ft.is_file() {
            let r = gap(
                path,
                ObjectType::Other,
                Verdict::Unsupported,
                "Kein reguläres Dateiobjekt (Gerät, Pipe, Socket): nicht geprüft".into(),
            );
            return self.push(out, progress, r);
        }
        let r = self.scan_file(path);
        self.push(out, progress, r);
    }

    /// Prüft genau eine reguläre Datei.
    pub fn scan_file(&self, path: &Path) -> FileResult {
        let mut result = FileResult {
            path: path.display().to_string(),
            object_type: ObjectType::File,
            verdict: Verdict::Error,
            size: None,
            sha256: None,
            file_kind: None,
            identity: None,
            engines: Vec::new(),
            notes: Vec::new(),
            action: Action::ReportOnly,
            scanned_utc: now_utc(),
        };

        let file = match open_no_follow(path) {
            Ok(f) => f,
            Err(e) => {
                result.verdict = io_verdict(&e);
                result.notes.push(format!("Öffnen fehlgeschlagen: {e}"));
                return result;
            }
        };
        // Nach dem Öffnen erneut prüfen: zwischen Metadaten und Öffnen kann
        // der Pfad ausgetauscht worden sein.
        match file.metadata() {
            Ok(m) if m.is_file() => {}
            Ok(_) => {
                result.verdict = Verdict::ChangedDuringScan;
                result
                    .notes
                    .push("Objektart hat sich vor dem Lesen geändert".into());
                return result;
            }
            Err(e) => {
                result.verdict = io_verdict(&e);
                result
                    .notes
                    .push(format!("Metadaten über Handle nicht lesbar: {e}"));
                return result;
            }
        }
        let before = match FileIdentity::from_file(&file) {
            Ok(id) => id,
            Err(e) => {
                result.verdict = io_verdict(&e);
                result
                    .notes
                    .push(format!("Dateiidentität nicht lesbar: {e}"));
                return result;
            }
        };
        result.size = Some(before.size);
        result.identity = Some(before.clone());

        if before.size > self.limits.max_file_size {
            result.verdict = Verdict::Unsupported;
            result.notes.push(format!(
                "Datei größer als Limit ({} > {} Bytes): nicht gelesen, nicht geprüft",
                before.size, self.limits.max_file_size
            ));
            return result;
        }

        let mut data = Vec::with_capacity(before.size as usize);
        if let Err(e) = (&file)
            .take(self.limits.max_file_size + 1)
            .read_to_end(&mut data)
        {
            result.verdict = io_verdict(&e);
            result.notes.push(format!("Lesen fehlgeschlagen: {e}"));
            return result;
        }
        let sha = hex::encode(Sha256::digest(&data));
        let kind = filetype::detect(&data);
        result.sha256 = Some(sha.clone());
        result.file_kind = Some(kind.clone());

        let timeout = Duration::from_millis(self.limits.engine_timeout_ms);
        let input = ScanInput {
            data: &data,
            kind: &kind,
            sha256: &sha,
            timeout,
        };
        let mut verdicts = Vec::new();
        for engine in &self.engines {
            let outcome = match engine.info().health {
                EngineHealth::Ready => engine.scan(&input),
                EngineHealth::Unavailable { reason } => EngineOutcome {
                    engine: engine.name().into(),
                    engine_version: "unbekannt".into(),
                    content_version: "unbekannt".into(),
                    verdict: Verdict::Error,
                    detections: Vec::new(),
                    note: Some(format!("Engine nicht verfügbar: {reason}")),
                    duration_ms: 0,
                },
            };
            verdicts.push(outcome.verdict);
            result.engines.push(outcome);
        }
        if self.engines.is_empty() {
            result
                .notes
                .push("Keine Engine konfiguriert: keine Aussage möglich".into());
        }
        if kind.is_container() {
            result.notes.push(
                "Container: Tiefe der Prüfung hängt von der Engine ab (siehe Fähigkeitsmatrix)"
                    .into(),
            );
        }

        // Identität nach dem Lesen und der Prüfung erneut vergleichen.
        let changed = match FileIdentity::from_file(&file) {
            Ok(after) => !before.unchanged(&after) || data.len() as u64 != before.size,
            Err(_) => true,
        };
        let path_moved = match open_no_follow(path).and_then(|f| FileIdentity::from_file(&f)) {
            Ok(now) => !before.same_object(&now),
            Err(_) => true,
        };
        if changed || path_moved {
            verdicts.push(Verdict::ChangedDuringScan);
            result.notes.push(
                "Datei oder Pfad hat sich während der Prüfung geändert: Ergebnis verworfen, neu prüfen"
                    .into(),
            );
        }
        result.verdict = aggregate(verdicts);
        result
    }
}

fn gap(path: &Path, object_type: ObjectType, verdict: Verdict, note: String) -> FileResult {
    FileResult {
        path: path.display().to_string(),
        object_type,
        verdict,
        size: None,
        sha256: None,
        file_kind: None,
        identity: None,
        engines: Vec::new(),
        notes: vec![note],
        action: Action::ReportOnly,
        scanned_utc: now_utc(),
    }
}

/// Öffnet eine Datei nur zum Lesen, ohne Links zu folgen und ohne zu blockieren.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

/// Öffnet eine Datei nur zum Lesen; Reparsepunkte werden selbst geöffnet,
/// nicht ihr Ziel (`FILE_FLAG_OPEN_REPARSE_POINT`).
#[cfg(windows)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
    // Freigabe für Lesen/Schreiben/Löschen, damit AXSafe andere Programme
    // nicht blockiert; Änderungen werden über die Identität erkannt.
    OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2 | 0x4)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(windows)]
fn is_reparse_point(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_meta: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Detection, EngineInfo};
    use crate::verdict::{Confidence, Severity};

    /// Test-Engine für die Orchestrierung: meldet einen Fund, wenn der
    /// Inhalt mit `BAD` beginnt. Nur in Tests, nie im Produkt.
    struct PrefixEngine;
    impl Engine for PrefixEngine {
        fn name(&self) -> &str {
            "test-prefix"
        }
        fn info(&self) -> EngineInfo {
            EngineInfo {
                name: "test-prefix".into(),
                engine_version: "0".into(),
                content_version: "0".into(),
                health: EngineHealth::Ready,
                license: "n/a".into(),
            }
        }
        fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
            let hit = input.data.starts_with(b"BAD");
            EngineOutcome {
                engine: "test-prefix".into(),
                engine_version: "0".into(),
                content_version: "0".into(),
                verdict: if hit {
                    Verdict::Malicious
                } else {
                    Verdict::NoDetection
                },
                detections: if hit {
                    vec![Detection {
                        name: "Test.Prefix".into(),
                        verdict: Verdict::Malicious,
                        severity: Severity::High,
                        confidence: Confidence::High,
                        rule_id: None,
                        evidence: vec!["Präfix BAD".into()],
                        test_signature: true,
                    }]
                } else {
                    vec![]
                },
                note: None,
                duration_ms: 0,
            }
        }
    }

    struct BrokenEngine;
    impl Engine for BrokenEngine {
        fn name(&self) -> &str {
            "broken"
        }
        fn info(&self) -> EngineInfo {
            EngineInfo {
                name: "broken".into(),
                engine_version: "?".into(),
                content_version: "?".into(),
                health: EngineHealth::Unavailable {
                    reason: "Testausfall".into(),
                },
                license: "n/a".into(),
            }
        }
        fn scan(&self, _: &ScanInput<'_>) -> EngineOutcome {
            unreachable!("nicht bereit")
        }
    }

    fn scanner(engines: Vec<Box<dyn Engine>>) -> Scanner {
        Scanner::new(engines, ScanLimits::default())
    }

    fn run(s: &Scanner, p: &Path) -> ScanReport {
        s.scan_paths(&[p.to_path_buf()], &AtomicBool::new(false), &mut NoProgress)
    }

    #[test]
    fn positive_benign_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.bin"), b"BAD stuff").unwrap();
        fs::write(dir.path().join("b.txt"), b"good stuff").unwrap();
        fs::write(dir.path().join("BAD.txt"), b"name is not content").unwrap();
        let rep = run(&scanner(vec![Box::new(PrefixEngine)]), dir.path());
        assert_eq!(rep.summary.objects, 3);
        assert_eq!(rep.summary.detections, 1);
        assert_eq!(rep.summary.no_detection, 2);
        assert_eq!(rep.overall, Verdict::Malicious);
        assert!(rep.complete);
        assert_eq!(rep.summary.bytes_read, 9 + 10 + 19);
    }

    #[test]
    fn unavailable_engine_never_yields_clean() {
        // T-019/T-015: Eine ausgefallene Engine erzeugt nie ein sauberes Ergebnis.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.txt"), b"good stuff").unwrap();
        let rep = run(
            &scanner(vec![Box::new(PrefixEngine), Box::new(BrokenEngine)]),
            dir.path(),
        );
        assert_eq!(rep.files[0].verdict, Verdict::Error);
        assert!(!rep.complete);
        assert_eq!(rep.overall, Verdict::Error);
    }

    #[test]
    fn no_engine_is_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.txt"), b"x").unwrap();
        let rep = run(&scanner(vec![]), dir.path());
        assert_eq!(rep.files[0].verdict, Verdict::Error);
    }

    #[test]
    fn size_limit_is_reported_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.bin"), vec![b'x'; 2048]).unwrap();
        let limits = ScanLimits {
            max_file_size: 1024,
            ..ScanLimits::default()
        };
        let s = Scanner::new(vec![Box::new(PrefixEngine)], limits);
        let rep = run(&s, dir.path());
        assert_eq!(rep.files[0].verdict, Verdict::Unsupported);
        assert!(!rep.complete);
    }

    #[test]
    fn missing_path_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let rep = run(
            &scanner(vec![Box::new(PrefixEngine)]),
            &dir.path().join("fehlt"),
        );
        assert_eq!(rep.files[0].verdict, Verdict::Error);
    }

    #[test]
    fn cancel_marks_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.txt"), b"x").unwrap();
        let rep = scanner(vec![Box::new(PrefixEngine)]).scan_paths(
            &[dir.path().to_path_buf()],
            &AtomicBool::new(true),
            &mut NoProgress,
        );
        assert!(rep.cancelled);
        assert!(!rep.complete);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t.bin");
        fs::write(&target, b"BAD").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let rep = run(&scanner(vec![Box::new(PrefixEngine)]), &link);
        assert_eq!(rep.files[0].verdict, Verdict::Unsupported);
        assert_eq!(rep.files[0].object_type, ObjectType::Link);
    }

    #[cfg(unix)]
    #[test]
    fn fifo_does_not_block_and_is_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !matches!(status, Ok(s) if s.success()) {
            eprintln!("mkfifo nicht verfügbar, Test übersprungen");
            return;
        }
        let rep = run(&scanner(vec![Box::new(PrefixEngine)]), dir.path());
        assert_eq!(rep.files[0].verdict, Verdict::Unsupported);
    }

    #[cfg(unix)]
    #[test]
    fn access_denied_is_reported_when_enforced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret.bin");
        fs::write(&p, b"x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(&p).is_ok() {
            // Als root greifen Dateirechte nicht. Ehrlich überspringen.
            eprintln!(
                "Rechte werden in dieser Umgebung nicht durchgesetzt (root), Test übersprungen"
            );
            return;
        }
        let rep = run(&scanner(vec![Box::new(PrefixEngine)]), &p);
        assert_eq!(rep.files[0].verdict, Verdict::AccessDenied);
    }
}
