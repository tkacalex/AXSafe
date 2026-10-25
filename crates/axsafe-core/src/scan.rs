//! Scan-Orchestrierung (AXS-026 Teil: eigener Scan mit Abbruch).
//!
//! Ablauf je Datei:
//! 1. Objektart ohne Linkverfolgung bestimmen (Links/Reparsepunkte: Prüflücke).
//! 2. Datei öffnen (ohne Linkverfolgung, ohne Blockieren), Identität über das
//!    Handle lesen. Ausgeschlossene Identitäten (z. B. die eigene
//!    Berichtsdatei) werden übersprungen und im Umfang dokumentiert.
//! 3. Inhalt über **dasselbe** Handle lesen, SHA-256 bilden, Typ bestimmen.
//! 4. Alle bereiten Engines prüfen denselben Schnappschuss.
//! 5. Fund und Lücken getrennt sammeln (Befund 2). Containerinhalte, die
//!    keine aktive Engine inhaltlich prüft, werden als Lücke gemeldet (Befund 3).
//! 6. Identität erneut lesen und Pfad erneut auflösen. Abweichung: Lücke
//!    `ChangedDuringScan` – ein bereits gefundener Fund bleibt sichtbar.
//!
//! Auftragslücken (nicht verfügbare beauftragte Engine, Abbruch) werden
//! unabhängig von Dateiergebnissen geführt (Befund 6).
//!
//! Der Scanner **liest nur**. Er löscht, verschiebt oder startet nichts.

use crate::engine::{Engine, EngineHealth, EngineInfo, EngineOutcome, Gap, GapReason, ScanInput};
use crate::filetype::{self, FileKind};
use crate::identity::FileIdentity;
use crate::report::{
    highest_detection, job_outcome, ExcludedObject, FileResult, ObjectStatus, ObjectType,
    ScanLimits, ScanReport, ScanScope, Summary, DISCLAIMER_DE,
};
use crate::verdict::{Action, Verdict};
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
    excluded: Vec<(FileIdentity, String)>,
    access: std::sync::Arc<dyn FileAccess>,
    classify_in_engine: bool,
}

/// Mit wessen Rechten auf Dateien zugegriffen wird.
///
/// Der Dienst (P02) setzt hier die Identität des Auftraggebers ein
/// (Windows-Impersonation); Verzeichnisse lesen, Öffnen, Metadaten und
/// Lesen laufen dann mit dessen Rechten. Engines laufen außerhalb davon.
/// Scheitert der Wechsel, wird das Objekt NICHT mit eigenen Rechten
/// gelesen, sondern als Lücke gemeldet.
pub trait FileAccess: Send + Sync {
    /// Wechselt für die Dauer des Wächters in die Zugriffsidentität.
    fn enter(&self) -> io::Result<Box<dyn AccessGuard>>;
    /// Beschreibung für Berichte, z. B. „Rechte von DOMAIN\\alex“.
    fn describe(&self) -> String;
}

/// Wächter: beim Verwerfen wird die vorherige Identität wiederhergestellt.
pub trait AccessGuard {}

/// Zugriff mit den Rechten des eigenen Prozesses (CLI).
pub struct ProcessAccess;
struct NoGuard;
impl AccessGuard for NoGuard {}
impl FileAccess for ProcessAccess {
    fn enter(&self) -> io::Result<Box<dyn AccessGuard>> {
        Ok(Box::new(NoGuard))
    }
    fn describe(&self) -> String {
        "Rechte des aufrufenden Prozesses".into()
    }
}

fn access_gap(e: &io::Error) -> Gap {
    Gap::new(
        Verdict::AccessDenied,
        GapReason::AccessDenied,
        AXSAFE,
        format!("Zugriff mit den Rechten des Auftraggebers nicht möglich: {e}"),
    )
}

pub(crate) fn now_utc() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

const AXSAFE: &str = "axsafe";

fn io_gap(e: &io::Error, what: &str) -> Gap {
    match e.kind() {
        io::ErrorKind::PermissionDenied => Gap::new(
            Verdict::AccessDenied,
            GapReason::AccessDenied,
            AXSAFE,
            format!("{what}: Zugriff verweigert ({e})"),
        ),
        _ => Gap::new(
            Verdict::Error,
            GapReason::IoError,
            AXSAFE,
            format!("{what}: {e}"),
        ),
    }
}

/// Wandelt einen Engine-Lückenzustand ohne eigene Lückenliste in eine Lücke um.
fn outcome_gap(o: &EngineOutcome, unavailable: bool) -> Gap {
    let reason = match o.verdict {
        Verdict::Timeout => GapReason::EngineTimeout,
        Verdict::Encrypted => GapReason::Encrypted,
        Verdict::Unsupported => GapReason::EngineLimitExceeded,
        Verdict::AccessDenied => GapReason::AccessDenied,
        Verdict::ChangedDuringScan => GapReason::ChangedDuringScan,
        _ if unavailable => GapReason::EngineUnavailable,
        _ => GapReason::EngineError,
    };
    Gap::new(
        o.verdict,
        reason,
        &o.engine,
        o.note
            .clone()
            .unwrap_or_else(|| "keine Angabe der Engine".into()),
    )
}

enum FileOutcome {
    Result(Box<FileResult>),
    Excluded(ExcludedObject),
}

impl Scanner {
    pub fn new(engines: Vec<Box<dyn Engine>>, limits: ScanLimits) -> Self {
        Scanner {
            engines,
            limits,
            excluded: Vec::new(),
            access: std::sync::Arc::new(ProcessAccess),
            classify_in_engine: false,
        }
    }

    /// Dateizugriff mit einer anderen Identität (Dienst: Auftraggeber).
    pub fn with_file_access(mut self, access: std::sync::Arc<dyn FileAccess>) -> Self {
        self.access = access;
        self
    }

    /// Dateityp NICHT im eigenen Prozess bestimmen, sondern durch eine
    /// Engine, die das kann (abgeschotteter Worker). Fehlt sie oder
    /// scheitert sie, wird das Objekt als nicht vollständig geprüft gemeldet.
    pub fn classify_in_engine(mut self, on: bool) -> Self {
        self.classify_in_engine = on;
        self
    }

    /// Schließt ein Dateiobjekt anhand seiner **Identität** (nicht des Pfads)
    /// vom Scan aus, z. B. die vom Auftrag selbst angelegte Berichtsdatei.
    /// Greift auch bei Hardlinks und bei Pfaden über Junctions/Symlinks.
    pub fn exclude_identity(&mut self, id: FileIdentity, reason: impl Into<String>) {
        self.excluded.push((id, reason.into()));
    }

    pub fn limits(&self) -> &ScanLimits {
        &self.limits
    }

    /// Informationen aller Engines (Bereitschaft, Inhalt, Fähigkeiten).
    pub fn engine_infos(&self) -> Vec<EngineInfo> {
        self.engines.iter().map(|e| e.info()).collect()
    }

    /// Prüft die angegebenen Pfade mit zufälliger Auftragskennung.
    pub fn scan_paths(
        &self,
        roots: &[PathBuf],
        cancel: &AtomicBool,
        progress: &mut dyn Progress,
    ) -> ScanReport {
        self.scan_job(uuid::Uuid::new_v4().to_string(), roots, cancel, progress)
    }

    /// Prüft die angegebenen Pfade unter einer vorgegebenen Auftragskennung.
    pub fn scan_job(
        &self,
        job_id: String,
        roots: &[PathBuf],
        cancel: &AtomicBool,
        progress: &mut dyn Progress,
    ) -> ScanReport {
        let started = Instant::now();
        let started_utc = now_utc();
        let infos = self.engine_infos();

        // Auftragslücken, unabhängig von einzelnen Dateien (Befund 6).
        let mut job_gaps = Vec::new();
        if self.engines.is_empty() {
            job_gaps.push(Gap::new(
                Verdict::Error,
                GapReason::NoEngine,
                AXSAFE,
                "Keine Engine konfiguriert: keine Aussage möglich",
            ));
        }
        for i in &infos {
            if let EngineHealth::Unavailable { reason } = &i.health {
                job_gaps.push(Gap::new(
                    Verdict::Error,
                    GapReason::EngineUnavailable,
                    &i.name,
                    format!("Beauftragte Engine nicht verfügbar: {reason}"),
                ));
            }
        }

        let mut files = Vec::new();
        let mut excluded = Vec::new();
        for root in roots {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            self.visit(root, 0, cancel, &infos, &mut files, &mut excluded, progress);
        }
        let cancelled = cancel.load(Ordering::SeqCst);
        if cancelled {
            job_gaps.push(Gap::new(
                Verdict::Error,
                GapReason::Cancelled,
                AXSAFE,
                "Auftrag abgebrochen: weitere Objekte wurden nicht geprüft",
            ));
        }
        let summary = Summary::from_files(&files);
        debug_assert!(summary.is_consistent());
        let (outcome, complete) = job_outcome(&summary, &job_gaps, cancelled);
        ScanReport {
            schema: crate::REPORT_SCHEMA_VERSION.into(),
            job_id,
            axsafe_version: crate::AXSAFE_VERSION.into(),
            policy_version: crate::POLICY_VERSION.into(),
            started_utc,
            finished_utc: now_utc(),
            duration_ms: started.elapsed().as_millis() as u64,
            scope: ScanScope {
                roots: roots.iter().map(|p| p.display().to_string()).collect(),
                engines: infos,
                limits: self.limits.clone(),
                follows_links: false,
                excluded,
            },
            outcome,
            detection: highest_detection(files.iter().map(|f| f.detection)),
            complete,
            cancelled,
            job_gaps,
            summary,
            files,
            disclaimer: DISCLAIMER_DE.into(),
            executed_by: None,
        }
    }

    fn push(&self, out: &mut Vec<FileResult>, progress: &mut dyn Progress, r: FileResult) {
        progress.on_result(&r);
        out.push(r);
    }

    #[allow(clippy::too_many_arguments)]
    fn visit(
        &self,
        path: &Path,
        depth: usize,
        cancel: &AtomicBool,
        infos: &[EngineInfo],
        out: &mut Vec<FileResult>,
        excluded: &mut Vec<ExcludedObject>,
        progress: &mut dyn Progress,
    ) {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let guard = match self.access.enter() {
            Ok(g) => g,
            Err(e) => {
                let r = gap_result(path, ObjectType::Unknown, access_gap(&e));
                return self.push(out, progress, r);
            }
        };
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                let r = gap_result(
                    path,
                    ObjectType::Unknown,
                    io_gap(&e, "Metadaten nicht lesbar"),
                );
                return self.push(out, progress, r);
            }
        };
        let ft = meta.file_type();
        if ft.is_symlink() || is_reparse_point(&meta) {
            let r = gap_result(
                path,
                ObjectType::Link,
                Gap::new(
                    Verdict::Unsupported,
                    GapReason::LinkNotFollowed,
                    AXSAFE,
                    "Link, Junction oder Reparsepunkt: wird nicht verfolgt, Ziel nicht geprüft",
                ),
            );
            return self.push(out, progress, r);
        }
        if ft.is_dir() {
            if depth >= self.limits.max_depth {
                let r = gap_result(
                    path,
                    ObjectType::Directory,
                    Gap::new(
                        Verdict::Unsupported,
                        GapReason::DepthLimit,
                        AXSAFE,
                        format!(
                            "Maximale Verzeichnistiefe {} erreicht: Inhalt nicht geprüft",
                            self.limits.max_depth
                        ),
                    ),
                );
                return self.push(out, progress, r);
            }
            let entries = match fs::read_dir(path) {
                Ok(it) => it,
                Err(e) => {
                    let r = gap_result(
                        path,
                        ObjectType::Directory,
                        io_gap(&e, "Verzeichnis nicht lesbar"),
                    );
                    return self.push(out, progress, r);
                }
            };
            let mut children: Vec<PathBuf> = Vec::new();
            for entry in entries {
                match entry {
                    Ok(en) => children.push(en.path()),
                    Err(e) => {
                        let r = gap_result(
                            path,
                            ObjectType::Directory,
                            io_gap(&e, "Eintrag nicht lesbar"),
                        );
                        self.push(out, progress, r);
                    }
                }
            }
            drop(guard);
            children.sort();
            for child in children {
                self.visit(&child, depth + 1, cancel, infos, out, excluded, progress);
            }
            return;
        }
        if !ft.is_file() {
            let r = gap_result(
                path,
                ObjectType::Other,
                Gap::new(
                    Verdict::Unsupported,
                    GapReason::NotRegularFile,
                    AXSAFE,
                    "Kein reguläres Dateiobjekt (Gerät, Pipe, Socket): nicht geprüft",
                ),
            );
            return self.push(out, progress, r);
        }
        drop(guard);
        match self.scan_file_inner(path, infos) {
            FileOutcome::Result(r) => self.push(out, progress, *r),
            FileOutcome::Excluded(x) => excluded.push(x),
        }
    }

    /// Prüft genau eine reguläre Datei (ohne Ausschlussliste der Auftragsebene).
    pub fn scan_file(&self, path: &Path) -> FileResult {
        match self.scan_file_inner(path, &self.engine_infos()) {
            FileOutcome::Result(r) => *r,
            FileOutcome::Excluded(x) => gap_result(
                path,
                ObjectType::File,
                Gap::new(
                    Verdict::Unsupported,
                    GapReason::NotRegularFile,
                    AXSAFE,
                    x.reason,
                ),
            ),
        }
    }

    fn scan_file_inner(&self, path: &Path, infos: &[EngineInfo]) -> FileOutcome {
        let mut result = FileResult {
            path: path.display().to_string(),
            object_type: ObjectType::File,
            detection: Verdict::NoDetection,
            gaps: Vec::new(),
            status: ObjectStatus::Incomplete,
            size: None,
            sha256: None,
            file_kind: None,
            identity: None,
            engines: Vec::new(),
            notes: Vec::new(),
            action: Action::ReportOnly,
            scanned_utc: now_utc(),
        };
        let fail = |mut r: FileResult, g: Gap| {
            r.gaps.push(g);
            r.status = ObjectStatus::from_parts(r.detection, &r.gaps);
            FileOutcome::Result(Box::new(r))
        };

        let guard = match self.access.enter() {
            Ok(g) => g,
            Err(e) => return fail(result, access_gap(&e)),
        };
        let file = match open_no_follow(path) {
            Ok(f) => f,
            Err(e) => return fail(result, io_gap(&e, "Öffnen fehlgeschlagen")),
        };
        // Nach dem Öffnen erneut prüfen: zwischen Metadaten und Öffnen kann
        // der Pfad ausgetauscht worden sein (z. B. gegen einen Link).
        match file.metadata() {
            Ok(m) if m.is_file() && !is_reparse_point(&m) => {}
            Ok(_) => {
                return fail(
                    result,
                    Gap::new(
                        Verdict::ChangedDuringScan,
                        GapReason::ChangedDuringScan,
                        AXSAFE,
                        "Objektart hat sich vor dem Lesen geändert",
                    ),
                )
            }
            Err(e) => return fail(result, io_gap(&e, "Metadaten über Handle nicht lesbar")),
        }
        let before = match FileIdentity::from_file(&file) {
            Ok(id) => id,
            Err(e) => return fail(result, io_gap(&e, "Dateiidentität nicht lesbar")),
        };
        if let Some((_, reason)) = self.excluded.iter().find(|(id, _)| id.same_object(&before)) {
            return FileOutcome::Excluded(ExcludedObject {
                path: path.display().to_string(),
                reason: reason.clone(),
            });
        }
        result.size = Some(before.size);
        result.identity = Some(before.clone());

        if before.size > self.limits.max_file_size {
            let detail = format!(
                "Datei größer als Limit ({} > {} Bytes): nicht gelesen, nicht geprüft",
                before.size, self.limits.max_file_size
            );
            return fail(
                result,
                Gap::new(Verdict::Unsupported, GapReason::SizeLimit, AXSAFE, detail),
            );
        }

        let mut data = Vec::with_capacity(before.size as usize);
        if let Err(e) = (&file)
            .take(self.limits.max_file_size + 1)
            .read_to_end(&mut data)
        {
            return fail(result, io_gap(&e, "Lesen fehlgeschlagen"));
        }
        // Ab hier keine Dateizugriffe mehr über Pfade: Rechte zurückgeben,
        // bevor Engines laufen.
        drop(guard);
        let sha = hex::encode(Sha256::digest(&data));
        let timeout = Duration::from_millis(self.limits.engine_timeout_ms);

        // Dateityp: im eigenen Prozess oder (Dienst) im abgeschotteten Worker.
        let mut pre: Option<(usize, EngineOutcome)> = None;
        let kind = if self.classify_in_engine {
            let classifier = self
                .engines
                .iter()
                .zip(infos)
                .position(|(e, i)| e.classifies() && i.health == EngineHealth::Ready);
            match classifier {
                Some(idx) => {
                    let unknown = FileKind::Unknown;
                    let input = ScanInput {
                        data: &data,
                        kind: &unknown,
                        sha256: &sha,
                        timeout,
                    };
                    let (outcome, kind) = self.engines[idx].scan_and_classify(&input);
                    pre = Some((idx, outcome));
                    match kind {
                        Some(Ok(k)) => k,
                        Some(Err(e)) => {
                            result.gaps.push(Gap::new(
                                Verdict::Error,
                                GapReason::EngineError,
                                AXSAFE,
                                format!("Typerkennung im Worker fehlgeschlagen: {e}"),
                            ));
                            FileKind::Unknown
                        }
                        None => {
                            result.gaps.push(Gap::new(
                                Verdict::Error,
                                GapReason::EngineError,
                                AXSAFE,
                                "Typerkennung im Worker lieferte kein Ergebnis",
                            ));
                            FileKind::Unknown
                        }
                    }
                }
                None => {
                    result.gaps.push(Gap::new(
                        Verdict::Error,
                        GapReason::EngineUnavailable,
                        AXSAFE,
                        "Typerkennung nur im abgeschotteten Worker zulässig, Worker nicht \
                         verfügbar: Typ unbekannt, Containerprüfung nicht beurteilbar",
                    ));
                    FileKind::Unknown
                }
            }
        } else {
            filetype::detect(&data)
        };
        result.sha256 = Some(sha.clone());
        result.file_kind = Some(kind.clone());

        let input = ScanInput {
            data: &data,
            kind: &kind,
            sha256: &sha,
            timeout,
        };
        let content_fmt = filetype::content_format(&kind);
        let mut content_inspected = false;
        let mut detections = Vec::new();
        for (idx, (engine, info)) in self.engines.iter().zip(infos).enumerate() {
            let (outcome, unavailable) = match &info.health {
                EngineHealth::Ready => match pre.take() {
                    Some((p, o)) if p == idx => (o, false),
                    other => {
                        pre = other;
                        (engine.scan(&input), false)
                    }
                },
                EngineHealth::Unavailable { reason } => (
                    EngineOutcome {
                        engine: info.name.clone(),
                        engine_version: info.engine_version.clone(),
                        content_version: info.content_version.clone(),
                        verdict: Verdict::Error,
                        detections: Vec::new(),
                        gaps: Vec::new(),
                        note: Some(format!("Engine nicht verfügbar: {reason}")),
                        duration_ms: 0,
                    },
                    true,
                ),
            };
            detections.extend(outcome.detections.iter().map(|d| d.verdict));
            if outcome.verdict.is_detection() {
                detections.push(outcome.verdict);
            }
            if outcome.gaps.is_empty() {
                if outcome.verdict.is_incomplete() {
                    result.gaps.push(outcome_gap(&outcome, unavailable));
                }
            } else {
                result.gaps.extend(outcome.gaps.iter().cloned());
            }
            if let Some(fmt) = content_fmt {
                let ran =
                    !unavailable && !matches!(outcome.verdict, Verdict::Error | Verdict::Timeout);
                if ran && info.inspects_contents_of.contains(&fmt) {
                    content_inspected = true;
                }
            }
            result.engines.push(outcome);
        }
        if self.engines.is_empty() {
            result.gaps.push(Gap::new(
                Verdict::Error,
                GapReason::NoEngine,
                AXSAFE,
                "Keine Engine konfiguriert: keine Aussage möglich",
            ));
        }
        if let Some(fmt) = content_fmt {
            if !content_inspected {
                let raw_only: Vec<&str> = infos
                    .iter()
                    .filter(|i| i.health == EngineHealth::Ready)
                    .map(|i| i.name.as_str())
                    .collect();
                result.gaps.push(Gap::new(
                    Verdict::Unsupported,
                    GapReason::ContentNotInspected,
                    AXSAFE,
                    format!(
                        "Inhalt des Formats {} wurde nicht geprüft: keine aktive Engine prüft diesen \
                         Containerinhalt (aktiv: {}; nur äußere Bytes geprüft)",
                        fmt.label(),
                        if raw_only.is_empty() { "keine".to_string() } else { raw_only.join(", ") }
                    ),
                ));
            }
        }

        // Identität nach dem Lesen und der Prüfung erneut vergleichen.
        let changed = match FileIdentity::from_file(&file) {
            Ok(after) => !before.unchanged(&after) || data.len() as u64 != before.size,
            Err(_) => true,
        };
        let path_moved = match self
            .access
            .enter()
            .and_then(|_g| open_no_follow(path).and_then(|f| FileIdentity::from_file(&f)))
        {
            Ok(now) => !before.same_object(&now),
            Err(_) => true,
        };
        if changed || path_moved {
            result.gaps.push(Gap::new(
                Verdict::ChangedDuringScan,
                GapReason::ChangedDuringScan,
                AXSAFE,
                "Datei oder Pfad hat sich während der Prüfung geändert: neu prüfen. \
                 Ein Fund bezieht sich auf den gelesenen Stand.",
            ));
        }
        result.detection = highest_detection(detections);
        result.status = ObjectStatus::from_parts(result.detection, &result.gaps);
        FileOutcome::Result(Box::new(result))
    }
}

fn gap_result(path: &Path, object_type: ObjectType, gap: Gap) -> FileResult {
    let gaps = vec![gap];
    FileResult {
        path: path.display().to_string(),
        object_type,
        detection: Verdict::NoDetection,
        status: ObjectStatus::from_parts(Verdict::NoDetection, &gaps),
        gaps,
        size: None,
        sha256: None,
        file_kind: None,
        identity: None,
        engines: Vec::new(),
        notes: Vec::new(),
        action: Action::ReportOnly,
        scanned_utc: now_utc(),
    }
}

/// Öffnet eine Datei nur zum Lesen, ohne Links zu folgen und ohne zu blockieren.
#[cfg(unix)]
pub(crate) fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

/// Öffnet eine Datei nur zum Lesen; Reparsepunkte werden selbst geöffnet,
/// nicht ihr Ziel (`FILE_FLAG_OPEN_REPARSE_POINT`).
#[cfg(windows)]
pub(crate) fn open_no_follow(path: &Path) -> io::Result<File> {
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
pub(crate) fn open_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(crate) fn is_reparse_point(_meta: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{ContentKind, Detection};
    use crate::filetype::ContentFormat;
    use crate::report::JobOutcome;
    use crate::verdict::{Confidence, Severity};

    /// Konfigurierbare Test-Engine für die Orchestrierung. Nur in Tests.
    /// Meldet einen Fund, wenn der Inhalt mit `BAD` beginnt; kann zusätzlich
    /// einen festen Lückenzustand liefern und Containerformate „können“.
    struct TestEngine {
        name: &'static str,
        ready: bool,
        extra: Option<Verdict>,
        caps: Vec<ContentFormat>,
    }

    impl TestEngine {
        fn prefix() -> Self {
            TestEngine {
                name: "test-prefix",
                ready: true,
                extra: None,
                caps: vec![],
            }
        }
        fn failing(v: Verdict) -> Self {
            TestEngine {
                name: "test-fail",
                ready: true,
                extra: Some(v),
                caps: vec![],
            }
        }
        fn unavailable() -> Self {
            TestEngine {
                name: "test-down",
                ready: false,
                extra: None,
                caps: vec![],
            }
        }
        fn container_capable() -> Self {
            TestEngine {
                name: "test-unpack",
                ready: true,
                extra: None,
                caps: vec![ContentFormat::Zip],
            }
        }
    }

    impl Engine for TestEngine {
        fn name(&self) -> &str {
            self.name
        }
        fn info(&self) -> EngineInfo {
            EngineInfo {
                name: self.name.into(),
                engine_version: "0".into(),
                content_version: "0".into(),
                health: if self.ready {
                    EngineHealth::Ready
                } else {
                    EngineHealth::Unavailable {
                        reason: "Testausfall".into(),
                    }
                },
                license: "n/a".into(),
                content_kind: ContentKind::TestOnly,
                content_note: "Test".into(),
                inspects_contents_of: self.caps.clone(),
                isolation: crate::engine::Isolation::in_process(),
            }
        }
        fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
            assert!(self.ready, "nicht bereite Engine darf nicht scannen");
            if let Some(v) = self.extra {
                return EngineOutcome {
                    engine: self.name.into(),
                    engine_version: "0".into(),
                    content_version: "0".into(),
                    verdict: v,
                    detections: vec![],
                    gaps: vec![],
                    note: Some(format!("Testzustand {v:?}")),
                    duration_ms: 0,
                };
            }
            let hit = input.data.starts_with(b"BAD");
            EngineOutcome {
                engine: self.name.into(),
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
                gaps: vec![],
                note: None,
                duration_ms: 0,
            }
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
        let rep = run(&scanner(vec![Box::new(TestEngine::prefix())]), dir.path());
        assert_eq!(rep.summary.objects_total, 3);
        assert_eq!(rep.summary.objects_read, 3);
        assert_eq!(rep.summary.with_detection, 1);
        assert_eq!(rep.summary.no_detection_complete, 2);
        assert_eq!(rep.outcome, JobOutcome::Detection);
        assert_eq!(rep.detection, Verdict::Malicious);
        assert!(rep.complete);
        assert_eq!(rep.summary.bytes_read, 9 + 10 + 19);
        assert!(rep.summary.is_consistent());
    }

    #[test]
    fn detection_and_engine_gap_are_both_visible() {
        // Befund 2: Engine A findet, Engine B scheitert. Beides muss sichtbar sein.
        for failure in [
            Verdict::Error,
            Verdict::Timeout,
            Verdict::Unsupported,
            Verdict::Encrypted,
        ] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("a.bin"), b"BAD").unwrap();
            let rep = run(
                &scanner(vec![
                    Box::new(TestEngine::prefix()),
                    Box::new(TestEngine::failing(failure)),
                ]),
                dir.path(),
            );
            let f = &rep.files[0];
            assert_eq!(f.detection, Verdict::Malicious, "{failure:?}");
            assert_eq!(f.gaps.len(), 1);
            assert_eq!(f.gaps[0].state, failure);
            assert_eq!(f.status, ObjectStatus::DetectionIncomplete);
            assert!(!rep.complete);
            assert_eq!(rep.outcome, JobOutcome::DetectionIncomplete);
            assert_eq!(rep.summary.detection_and_incomplete, 1);
            assert_eq!(rep.outcome.exit_code(), 4);
        }
    }

    #[test]
    fn gap_without_detection_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.txt"), b"good").unwrap();
        let rep = run(
            &scanner(vec![
                Box::new(TestEngine::prefix()),
                Box::new(TestEngine::failing(Verdict::Timeout)),
            ]),
            dir.path(),
        );
        assert_eq!(rep.files[0].status, ObjectStatus::Incomplete);
        assert_eq!(rep.outcome, JobOutcome::Incomplete);
        assert_eq!(rep.files[0].gaps[0].reason, GapReason::EngineTimeout);
    }

    #[test]
    fn unavailable_engine_never_yields_clean_and_is_job_gap() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.txt"), b"good stuff").unwrap();
        let rep = run(
            &scanner(vec![
                Box::new(TestEngine::prefix()),
                Box::new(TestEngine::unavailable()),
            ]),
            dir.path(),
        );
        assert_eq!(rep.files[0].status, ObjectStatus::Incomplete);
        assert_eq!(rep.files[0].gaps[0].reason, GapReason::EngineUnavailable);
        assert_eq!(rep.job_gaps.len(), 1);
        assert_eq!(rep.job_gaps[0].reason, GapReason::EngineUnavailable);
        assert!(!rep.complete);
        assert_eq!(rep.outcome, JobOutcome::Incomplete);
    }

    #[test]
    fn empty_scope_is_nothing_scanned_even_with_engine_failure() {
        // Befund 6
        let dir = tempfile::tempdir().unwrap();
        let rep = run(
            &scanner(vec![
                Box::new(TestEngine::prefix()),
                Box::new(TestEngine::unavailable()),
            ]),
            dir.path(),
        );
        assert_eq!(rep.outcome, JobOutcome::NothingScanned);
        assert!(!rep.complete);
        assert_eq!(rep.job_gaps.len(), 1);
        let ok = run(&scanner(vec![Box::new(TestEngine::prefix())]), dir.path());
        assert_eq!(ok.outcome, JobOutcome::NothingScanned);
        assert!(!ok.complete);
    }

    #[test]
    fn no_engine_is_gap() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.txt"), b"x").unwrap();
        let rep = run(&scanner(vec![]), dir.path());
        assert_eq!(rep.files[0].gaps[0].reason, GapReason::NoEngine);
        assert_eq!(rep.job_gaps[0].reason, GapReason::NoEngine);
        assert_eq!(rep.outcome, JobOutcome::Incomplete);
    }

    fn zip_bytes() -> Vec<u8> {
        let mut z = b"PK\x03\x04".to_vec();
        z.extend_from_slice(&[0u8; 60]);
        z
    }

    #[test]
    fn container_without_capable_engine_is_content_gap() {
        // Befund 3: Rohbytes-Engine allein prüft keinen Containerinhalt.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.zip"), zip_bytes()).unwrap();
        let rep = run(&scanner(vec![Box::new(TestEngine::prefix())]), dir.path());
        let f = &rep.files[0];
        assert_eq!(f.detection, Verdict::NoDetection);
        assert_eq!(f.gaps.len(), 1);
        assert_eq!(f.gaps[0].reason, GapReason::ContentNotInspected);
        assert_eq!(
            f.gaps[0].state,
            Verdict::Unsupported,
            "ohne Nachweis nie Encrypted"
        );
        assert_eq!(rep.outcome, JobOutcome::Incomplete);
        assert!(!rep.complete);
    }

    #[test]
    fn container_with_capable_engine_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.zip"), zip_bytes()).unwrap();
        let rep = run(
            &scanner(vec![
                Box::new(TestEngine::prefix()),
                Box::new(TestEngine::container_capable()),
            ]),
            dir.path(),
        );
        assert!(rep.files[0].gaps.is_empty(), "{:?}", rep.files[0].gaps);
        assert_eq!(rep.outcome, JobOutcome::NoDetection);
    }

    #[test]
    fn capable_engine_that_fails_does_not_count_as_inspected() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.zip"), zip_bytes()).unwrap();
        let failing_unpacker = TestEngine {
            name: "test-unpack",
            ready: true,
            extra: Some(Verdict::Error),
            caps: vec![ContentFormat::Zip],
        };
        let rep = run(
            &scanner(vec![
                Box::new(TestEngine::prefix()),
                Box::new(failing_unpacker),
            ]),
            dir.path(),
        );
        let reasons: Vec<GapReason> = rep.files[0].gaps.iter().map(|g| g.reason).collect();
        assert!(reasons.contains(&GapReason::EngineError));
        assert!(reasons.contains(&GapReason::ContentNotInspected));
    }

    #[test]
    fn excluded_identity_is_skipped_and_documented() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("bericht.json");
        fs::write(&report, b"").unwrap();
        let link = dir.path().join("hardlink.json");
        fs::hard_link(&report, &link).unwrap();
        fs::write(dir.path().join("b.txt"), b"x").unwrap();
        let mut s = scanner(vec![Box::new(TestEngine::prefix())]);
        s.exclude_identity(
            FileIdentity::from_file(&File::open(&report).unwrap()).unwrap(),
            "Berichtsdatei dieses Auftrags",
        );
        let rep = run(&s, dir.path());
        assert_eq!(rep.summary.objects_total, 1, "nur b.txt");
        assert_eq!(rep.scope.excluded.len(), 2, "Original und Hardlink");
    }

    #[test]
    fn size_limit_is_reported_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.bin"), vec![b'x'; 2048]).unwrap();
        let limits = ScanLimits {
            max_file_size: 1024,
            ..ScanLimits::default()
        };
        let s = Scanner::new(vec![Box::new(TestEngine::prefix())], limits);
        let rep = run(&s, dir.path());
        assert_eq!(rep.files[0].gaps[0].reason, GapReason::SizeLimit);
        assert_eq!(rep.outcome, JobOutcome::Incomplete);
    }

    #[test]
    fn missing_path_is_gap() {
        let dir = tempfile::tempdir().unwrap();
        let rep = run(
            &scanner(vec![Box::new(TestEngine::prefix())]),
            &dir.path().join("fehlt"),
        );
        assert_eq!(rep.files[0].gaps[0].reason, GapReason::IoError);
        assert_eq!(rep.outcome, JobOutcome::Incomplete);
    }

    #[test]
    fn cancel_marks_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.txt"), b"x").unwrap();
        let rep = scanner(vec![Box::new(TestEngine::prefix())]).scan_paths(
            &[dir.path().to_path_buf()],
            &AtomicBool::new(true),
            &mut NoProgress,
        );
        assert!(rep.cancelled);
        assert!(!rep.complete);
        assert!(rep
            .job_gaps
            .iter()
            .any(|g| g.reason == GapReason::Cancelled));
    }

    #[test]
    fn job_id_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let rep = scanner(vec![Box::new(TestEngine::prefix())]).scan_job(
            "11111111-2222-4333-8444-555555555555".into(),
            &[dir.path().to_path_buf()],
            &AtomicBool::new(false),
            &mut NoProgress,
        );
        assert_eq!(rep.job_id, "11111111-2222-4333-8444-555555555555");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t.bin");
        fs::write(&target, b"BAD").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let rep = run(&scanner(vec![Box::new(TestEngine::prefix())]), &link);
        assert_eq!(rep.files[0].gaps[0].reason, GapReason::LinkNotFollowed);
        assert_eq!(rep.files[0].object_type, ObjectType::Link);
    }

    #[cfg(unix)]
    #[test]
    fn fifo_does_not_block_and_is_gap() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status();
        assert!(matches!(status, Ok(s) if s.success()), "mkfifo nötig");
        let rep = run(&scanner(vec![Box::new(TestEngine::prefix())]), dir.path());
        assert_eq!(rep.files[0].gaps[0].reason, GapReason::NotRegularFile);
    }

    /// Benötigt einen Benutzer ohne Leserechte auf die Testdatei, also nicht root.
    #[cfg(unix)]
    #[test]
    #[ignore = "benötigt Nicht-root-Benutzer; in CI mit --include-ignored ausgeführt"]
    fn access_denied_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret.bin");
        fs::write(&p, b"x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(
            File::open(&p).is_err(),
            "Vorbedingung verletzt: Datei ohne Rechte ist lesbar (läuft der Test als root?)"
        );
        let rep = run(&scanner(vec![Box::new(TestEngine::prefix())]), &p);
        assert_eq!(rep.files[0].gaps[0].state, Verdict::AccessDenied);
    }

    // --- P02: Dateizugriff mit fremder Identität, Typerkennung im Worker ---

    struct DenyAccess;
    impl FileAccess for DenyAccess {
        fn enter(&self) -> io::Result<Box<dyn AccessGuard>> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Impersonation verweigert",
            ))
        }
        fn describe(&self) -> String {
            "Test: verweigert".into()
        }
    }

    #[test]
    fn failed_identity_switch_never_reads_with_own_rights() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"x").unwrap();
        let s = scanner(vec![Box::new(TestEngine::prefix())])
            .with_file_access(std::sync::Arc::new(DenyAccess));
        let rep = run(&s, dir.path());
        assert_eq!(rep.files.len(), 1, "{:?}", rep.files);
        let f = &rep.files[0];
        assert_eq!(f.gaps[0].reason, GapReason::AccessDenied, "{f:?}");
        assert!(f.sha256.is_none(), "Datei darf nicht gelesen worden sein");
        assert_eq!(rep.outcome, JobOutcome::Incomplete);
    }

    struct Classifier {
        kind: Result<FileKind, String>,
    }
    impl Engine for Classifier {
        fn name(&self) -> &str {
            "klassifizierer"
        }
        fn info(&self) -> EngineInfo {
            let mut i = TestEngine::prefix().info();
            i.name = "klassifizierer".into();
            i
        }
        fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
            TestEngine::prefix().scan(input)
        }
        fn classifies(&self) -> bool {
            true
        }
        fn scan_and_classify(
            &self,
            input: &ScanInput<'_>,
        ) -> (EngineOutcome, Option<Result<FileKind, String>>) {
            (self.scan(input), Some(self.kind.clone()))
        }
    }

    #[test]
    fn classification_in_engine_drives_container_logic() {
        let dir = tempfile::tempdir().unwrap();
        // Inhalt ist Text; der „Worker“ meldet ZIP → Containerlücke, und der
        // Host hat den Typ NICHT selbst bestimmt.
        fs::write(dir.path().join("a.bin"), b"nur text").unwrap();
        let s = scanner(vec![Box::new(Classifier {
            kind: Ok(FileKind::Zip),
        })])
        .classify_in_engine(true);
        let rep = run(&s, dir.path());
        let f = &rep.files[0];
        assert_eq!(f.file_kind, Some(FileKind::Zip));
        assert!(
            f.gaps
                .iter()
                .any(|g| g.reason == GapReason::ContentNotInspected),
            "{f:?}"
        );
        assert_eq!(f.engines.len(), 1, "Engine darf nur einmal prüfen");
    }

    #[test]
    fn classification_failure_or_missing_classifier_is_gap() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"x").unwrap();
        let s = scanner(vec![Box::new(Classifier {
            kind: Err("Absturz".into()),
        })])
        .classify_in_engine(true);
        let f = &run(&s, dir.path()).files[0];
        assert!(
            f.gaps
                .iter()
                .any(|g| g.detail.contains("Typerkennung im Worker fehlgeschlagen")),
            "{f:?}"
        );
        assert_eq!(f.status, ObjectStatus::Incomplete);

        let s = scanner(vec![Box::new(TestEngine::prefix())]).classify_in_engine(true);
        let f = &run(&s, dir.path()).files[0];
        assert!(
            f.gaps
                .iter()
                .any(|g| g.detail.contains("nur im abgeschotteten Worker")),
            "{f:?}"
        );
        assert_eq!(f.file_kind, Some(FileKind::Unknown));
    }
}
