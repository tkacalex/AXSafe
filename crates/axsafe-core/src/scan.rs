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

/// Höchstzahl geprüfter benannter Datenströme je Datei.
pub const MAX_STREAMS: usize = 16;

/// Ein Scanner mit festen Engines und Grenzen.
pub struct Scanner {
    engines: Vec<Box<dyn Engine>>,
    limits: ScanLimits,
    excluded: Vec<(FileIdentity, String)>,
    access: std::sync::Arc<dyn FileAccess>,
    classify_in_engine: bool,
    policy: Option<std::sync::Arc<crate::policy::Policy>>,
    resume: Option<std::sync::Arc<crate::resume::Resume>>,
    cache: Option<std::sync::Arc<crate::cache::ScanCache>>,
    kind: crate::scanjob::ScanKind,
    trigger: crate::scanjob::Trigger,
    missing_targets: Vec<String>,
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

/// Je Auftrag feste Angaben: Engines und Versionsschlüssel.
struct JobCtx {
    infos: Vec<EngineInfo>,
    version_key: String,
    cache_hits: std::sync::atomic::AtomicU64,
    cache_misses: std::sync::atomic::AtomicU64,
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
            policy: None,
            resume: None,
            cache: None,
            kind: crate::scanjob::ScanKind::Custom,
            trigger: crate::scanjob::Trigger::Manual,
            missing_targets: Vec::new(),
        }
    }

    /// Scanart und Auslöser für den Bericht; `missing` sind Orte der
    /// Scanart, die es nicht gibt.
    pub fn with_kind(
        mut self,
        kind: crate::scanjob::ScanKind,
        trigger: crate::scanjob::Trigger,
        missing: Vec<String>,
    ) -> Self {
        self.kind = kind;
        self.trigger = trigger;
        self.missing_targets = missing;
        self
    }

    /// Früheren Stand fortsetzen (nur inhaltsgleiche, vollständige
    /// Ergebnisse mit gleichem Versionsschlüssel werden übernommen).
    pub fn with_resume(mut self, r: std::sync::Arc<crate::resume::Resume>) -> Self {
        self.resume = Some(r);
        self
    }

    /// Ergebnis-Cache (AXS-027): an Inhalt und Versionsschlüssel gebunden.
    pub fn with_cache(mut self, c: std::sync::Arc<crate::cache::ScanCache>) -> Self {
        self.cache = Some(c);
        self
    }

    /// Richtlinienstand, wie er im Bericht steht.
    pub fn policy_version(&self) -> String {
        match &self.policy {
            Some(p) => format!("{}+{}", crate::POLICY_VERSION, p.version),
            None => crate::POLICY_VERSION.into(),
        }
    }

    /// Versionsschlüssel (Engines, Regeln, Heuristik, Richtlinie, Grenzen).
    pub fn version_key(&self) -> String {
        crate::resume::version_key(&self.engine_infos(), &self.policy_version(), &self.limits)
    }

    /// Richtlinie mit Ausnahmen (AXS-017). Ausgenommene Objekte werden im
    /// Bericht genannt und machen den Auftrag unvollständig.
    pub fn with_policy(mut self, policy: std::sync::Arc<crate::policy::Policy>) -> Self {
        self.policy = Some(policy);
        self
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
        let version_key = crate::resume::version_key(&infos, &self.policy_version(), &self.limits);

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

        let ctx = JobCtx {
            infos,
            version_key,
            cache_hits: Default::default(),
            cache_misses: Default::default(),
        };
        let mut files = Vec::new();
        let mut excluded = Vec::new();
        for root in roots {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            self.visit(root, 0, cancel, &ctx, &mut files, &mut excluded, progress);
        }
        let by_policy = excluded
            .iter()
            .filter(|x| x.reason.starts_with(crate::policy::EXCLUSION_PREFIX))
            .count();
        if by_policy > 0 {
            job_gaps.push(Gap::new(
                Verdict::Unsupported,
                GapReason::ExcludedByPolicy,
                AXSAFE,
                format!(
                    "{by_policy} Objekt(e)/Ordner durch Ausnahmen der Richtlinie nicht geprüft – \
                     verringerte Abdeckung (siehe scope.excluded)"
                ),
            ));
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
            policy_version: self.policy_version(),
            started_utc,
            finished_utc: now_utc(),
            utc_offset: chrono::Local::now().format("%:z").to_string(),
            duration_ms: started.elapsed().as_millis() as u64,
            scope: ScanScope {
                roots: roots.iter().map(|p| p.display().to_string()).collect(),
                engines: ctx.infos,
                limits: self.limits.clone(),
                follows_links: false,
                excluded,
                kind: self.kind,
                trigger: self.trigger,
                kind_note: self.kind.coverage_note().into(),
                missing_targets: self.missing_targets.clone(),
                version_key: ctx.version_key,
                resume: self.resume.as_ref().map(|r| r.info()),
                cache: self.cache.as_ref().map(|c| {
                    // Treffer und Fehlversuche genau dieses Auftrags.
                    let mut i = c.info();
                    i.hits = ctx.cache_hits.load(Ordering::Relaxed);
                    i.misses = ctx.cache_misses.load(Ordering::Relaxed);
                    i
                }),
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
        ctx: &JobCtx,
        out: &mut Vec<FileResult>,
        excluded: &mut Vec<ExcludedObject>,
        progress: &mut dyn Progress,
    ) {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        if let Some(pol) = &self.policy {
            let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
            if let Some(reason) = pol.exclusion_for(&abs) {
                excluded.push(ExcludedObject {
                    path: path.display().to_string(),
                    reason,
                });
                return;
            }
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
                self.visit(&child, depth + 1, cancel, ctx, out, excluded, progress);
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
        // Benannte Datenströme (Windows-ADS) mit den Rechten des Auftraggebers
        // ermitteln; jeder wird als eigenes Objekt „Datei:Strom“ geprüft
        // (AXS-018). Mehr als MAX_STREAMS: Lücke statt stilles Auslassen.
        let streams = fs::File::open(path).and_then(|f| crate::identity::alternate_streams(&f));
        drop(guard);
        let main_excluded = match self.scan_file_inner(path, ctx) {
            FileOutcome::Result(r) => {
                self.push(out, progress, *r);
                false
            }
            FileOutcome::Excluded(x) => {
                excluded.push(x);
                true
            }
        };
        if main_excluded {
            return;
        }
        match streams {
            Ok(names) => {
                for (i, n) in names.iter().enumerate() {
                    if cancel.load(Ordering::SeqCst) {
                        return;
                    }
                    let sp = PathBuf::from(format!("{}:{n}", path.display()));
                    if i >= MAX_STREAMS {
                        let r = gap_result(
                            &sp,
                            ObjectType::File,
                            Gap::new(
                                Verdict::Unsupported,
                                GapReason::NotRegularFile,
                                AXSAFE,
                                format!(
                                    "mehr als {MAX_STREAMS} Datenströme: weitere nicht geprüft"
                                ),
                            ),
                        );
                        self.push(out, progress, r);
                        break;
                    }
                    match self.scan_file_inner(&sp, ctx) {
                        FileOutcome::Result(r) => self.push(out, progress, *r),
                        FileOutcome::Excluded(x) => excluded.push(x),
                    }
                }
            }
            Err(e) => {
                let r = gap_result(
                    path,
                    ObjectType::File,
                    io_gap(&e, "Datenströme (ADS) nicht ermittelbar"),
                );
                self.push(out, progress, r);
            }
        }
    }

    /// Prüft genau eine reguläre Datei (ohne Ausschlussliste der Auftragsebene).
    pub fn scan_file(&self, path: &Path) -> FileResult {
        let infos = self.engine_infos();
        let ctx = JobCtx {
            version_key: crate::resume::version_key(&infos, &self.policy_version(), &self.limits),
            infos,
            cache_hits: Default::default(),
            cache_misses: Default::default(),
        };
        match self.scan_file_inner(path, &ctx) {
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

    fn scan_file_inner(&self, path: &Path, ctx: &JobCtx) -> FileOutcome {
        let infos = &ctx.infos[..];
        let mut result = FileResult {
            path: path.display().to_string(),
            object_type: ObjectType::File,
            detection: Verdict::NoDetection,
            gaps: Vec::new(),
            status: ObjectStatus::Incomplete,
            size: None,
            sha256: None,
            file_kind: None,
            static_features: None,
            sha1: None,
            md5: None,
            origin: None,
            authenticode: None,
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
        // Herkunft und Authenticode noch unter dem Wächter: Datenstrom bzw.
        // derselbe Handle, nichts wird ausgeführt, kein Netzzugriff.
        let origin = crate::trust::read_origin(path);
        let authenticode = data
            .starts_with(b"MZ")
            .then(|| crate::trust::authenticode(&file, path));
        // Ab hier keine Dateizugriffe mehr über Pfade: Rechte zurückgeben,
        // bevor Engines laufen.
        drop(guard);
        let sha = hex::encode(Sha256::digest(&data));
        let timeout = Duration::from_millis(self.limits.engine_timeout_ms);

        // Fortsetzen: früheres Ergebnis nur für denselben Inhalt (SHA-256)
        // bei gleichem Versionsschlüssel übernehmen. Identität, Herkunft und
        // Zeitpunkt werden aktuell gesetzt; Änderungen während des Lesens
        // werden unten wie sonst geprüft.
        let reused = self
            .resume
            .as_ref()
            .and_then(|r| r.reusable(&result.path, &sha).cloned());
        if let Some(prev) = reused {
            let mut r = prev;
            r.identity = result.identity.take();
            r.size = result.size;
            r.origin = origin;
            r.scanned_utc = now_utc();
            r.notes.push(
                "aus Fortsetzung übernommen: Inhalt (SHA-256) und Engine-/Regelstand unverändert"
                    .into(),
            );
            if self.changed_after_read(&file, path, &before, data.len()) {
                r.gaps.push(changed_gap());
            }
            r.status = ObjectStatus::from_parts(r.detection, &r.gaps);
            return FileOutcome::Result(Box::new(r));
        }

        // Cache (AXS-027): nur derselbe Inhalt unter demselben
        // Versionsschlüssel; sonst normale Prüfung.
        let cached = self
            .cache
            .as_ref()
            .and_then(|c| c.get(&ctx.version_key, &sha));
        if self.cache.is_some() {
            let counter = if cached.is_some() {
                &ctx.cache_hits
            } else {
                &ctx.cache_misses
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }

        // Dateityp: im eigenen Prozess oder (Dienst) im abgeschotteten Worker.
        let mut pre: Option<(usize, EngineOutcome)> = None;
        let mut features = None;
        let kind = if let Some(c) = &cached {
            features = c.features.clone();
            c.kind.clone()
        } else if self.classify_in_engine {
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
                        Some(Ok(c)) => {
                            features = c.features;
                            c.kind
                        }
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
            let k = filetype::detect(&data);
            features = Some(crate::features::analyze(&data, &k));
            k
        };
        result.sha256 = Some(sha.clone());
        {
            use md5::Digest as _;
            result.sha1 = Some(hex::encode(sha1::Sha1::digest(&data)));
            result.md5 = Some(hex::encode(md5::Md5::digest(&data)));
        }
        result.file_kind = Some(kind.clone());
        result.static_features = features;

        let input = ScanInput {
            data: &data,
            kind: &kind,
            sha256: &sha,
            timeout,
        };
        let content_fmt = filetype::content_format(&kind);
        let mut content_inspected = false;
        let mut detections = Vec::new();
        let from_cache = cached.is_some();
        if let Some(c) = cached {
            // Nur vollständige Ergebnisse liegen im Cache (Inhalt wurde damals
            // geprüft); Engines laufen nicht erneut.
            for o in c.engines {
                detections.extend(o.detections.iter().map(|d| d.verdict));
                if o.verdict.is_detection() {
                    detections.push(o.verdict);
                }
                result.engines.push(o);
            }
            content_inspected = true;
            result.notes.push(
                "Engine-Ergebnis aus dem Cache: gleicher Inhalt (SHA-256) bei gleichem Engine-, \
                 Regel- und Richtlinienstand; Heuristik, Herkunft und Signatur neu bestimmt"
                    .into(),
            );
        }
        for (idx, (engine, info)) in self
            .engines
            .iter()
            .zip(infos)
            .enumerate()
            .filter(|_| !from_cache)
        {
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
        if self.changed_after_read(&file, path, &before, data.len()) {
            result.gaps.push(changed_gap());
        }
        // Nur vollständige, frisch geprüfte Ergebnisse in den Cache.
        if let (Some(c), false, true) = (&self.cache, from_cache, result.gaps.is_empty()) {
            c.put(
                &ctx.version_key,
                &sha,
                crate::cache::CachedScan {
                    kind: kind.clone(),
                    features: result.static_features.clone(),
                    engines: result.engines.clone(),
                },
            );
        }
        // Heuristiken: Funde nur bei eindeutigen Täuschungsmustern, sonst
        // Hinweise. Belege stehen im Fund.
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (hdets, hints) = crate::heuristics::evaluate(
            &name,
            &kind,
            result.static_features.as_ref(),
            origin.as_ref(),
            authenticode.as_ref(),
        );
        detections.extend(hdets.iter().map(|d| d.verdict));
        result
            .engines
            .push(crate::heuristics::outcome(hdets, &hints));
        result.origin = origin;
        result.authenticode = authenticode;

        result.detection = highest_detection(detections);
        result.status = ObjectStatus::from_parts(result.detection, &result.gaps);
        FileOutcome::Result(Box::new(result))
    }
}

fn changed_gap() -> Gap {
    Gap::new(
        Verdict::ChangedDuringScan,
        GapReason::ChangedDuringScan,
        AXSAFE,
        "Datei oder Pfad hat sich während der Prüfung geändert: neu prüfen. \
         Ein Fund bezieht sich auf den gelesenen Stand.",
    )
}

impl Scanner {
    /// Hat sich die Datei (Handle) oder das Objekt hinter dem Pfad seit dem
    /// ersten Öffnen geändert?
    fn changed_after_read(
        &self,
        file: &File,
        path: &Path,
        before: &FileIdentity,
        read_len: usize,
    ) -> bool {
        let changed = match FileIdentity::from_file(file) {
            Ok(after) => !before.unchanged(&after) || read_len as u64 != before.size,
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
        changed || path_moved
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
        static_features: None,
        sha1: None,
        md5: None,
        origin: None,
        authenticode: None,
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
                content_time_utc: None,
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
                        rule_version: None,
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

    /// AXS-025: Heuristik-Fund mit Belegen im Bericht; gutartiges Programm
    /// mit gleicher Struktur bleibt ohne Fund, Merkmale stehen im Bericht.
    #[test]
    fn heuristics_and_static_features_in_report() {
        let dir = tempfile::tempdir().unwrap();
        let pe = crate::features::tests::tiny_pe(0x90, 0);
        fs::write(dir.path().join("Rechnung.pdf.exe"), &pe).unwrap();
        fs::write(dir.path().join("werkzeug.exe"), &pe).unwrap();
        let rep = run(&scanner(vec![Box::new(TestEngine::prefix())]), dir.path());
        let by = |n: &str| rep.files.iter().find(|f| f.path.ends_with(n)).unwrap();
        let bad = by("Rechnung.pdf.exe");
        assert_eq!(bad.detection, Verdict::Suspicious, "{bad:?}");
        let h = bad
            .engines
            .iter()
            .find(|e| e.engine == crate::heuristics::HEURISTICS_ENGINE)
            .unwrap();
        assert_eq!(h.detections[0].rule_id.as_deref(), Some("AXS-HEUR-0002"));
        assert!(!h.detections[0].evidence.is_empty());
        let good = by("werkzeug.exe");
        assert_eq!(good.detection, Verdict::NoDetection, "{good:?}");
        let pe_f = good.static_features.as_ref().unwrap().pe.as_ref().unwrap();
        assert!(!pe_f.sections.is_empty());
        assert_eq!(good.sha1.as_ref().map(|h| h.len()), Some(40));
        assert_eq!(good.md5.as_ref().map(|h| h.len()), Some(32));
        #[cfg(not(windows))]
        assert!(good.authenticode.as_ref().unwrap().status == "nicht_pruefbar");
        #[cfg(windows)]
        assert_eq!(good.authenticode.as_ref().unwrap().status, "unsigniert");
    }

    /// Zählt Engine-Aufrufe (für Fortsetzen: übernommene Dateien werden
    /// nicht erneut an Engines gegeben).
    struct Counting {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        content: &'static str,
    }
    impl Engine for Counting {
        fn name(&self) -> &str {
            "zaehler"
        }
        fn info(&self) -> EngineInfo {
            let mut i = TestEngine::prefix().info();
            i.name = "zaehler".into();
            i.content_version = self.content.into();
            i
        }
        fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut o = TestEngine::prefix().scan(input);
            o.engine = "zaehler".into();
            o.content_version = self.content.into();
            o
        }
    }

    fn counting(
        content: &'static str,
    ) -> (Scanner, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let s = scanner(vec![Box::new(Counting {
            calls: calls.clone(),
            content,
        })]);
        (s, calls)
    }

    fn header(s: &Scanner, roots: &[PathBuf]) -> crate::resume::CheckpointHeader {
        crate::resume::CheckpointHeader {
            schema: crate::resume::CHECKPOINT_SCHEMA.into(),
            job_id: "vorher".into(),
            kind: crate::scanjob::ScanKind::Custom,
            trigger: crate::scanjob::Trigger::Manual,
            roots: roots.iter().map(|p| p.display().to_string()).collect(),
            version_key: s.version_key(),
            created_utc: now_utc(),
        }
    }

    /// AXS-026: Abbruch, Änderung, Fortsetzen. Unveränderte Dateien werden
    /// übernommen, geänderte und neue neu geprüft, eine halbe Zeile
    /// (Abbruch beim Schreiben) ignoriert.
    #[test]
    fn resume_reuses_only_unchanged_content() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("daten");
        fs::create_dir(&data).unwrap();
        for (n, c) in [("a.txt", "eins"), ("b.txt", "zwei"), ("c.bin", "BAD drei")] {
            fs::write(data.join(n), c).unwrap();
        }
        let roots = vec![data.clone()];
        let cp = dir.path().join("fortsetzung.jsonl");
        let (s1, calls1) = counting("1");
        {
            let mut np = NoProgress;
            let mut w = crate::resume::CheckpointWriter::create(&cp, &header(&s1, &roots), &mut np)
                .unwrap();
            s1.scan_paths(&roots, &AtomicBool::new(false), &mut w);
            assert!(w.error.is_none());
        }
        assert_eq!(calls1.load(Ordering::SeqCst), 3);
        // Abbruch simulieren: letzte Zeile halb geschrieben.
        let text = fs::read_to_string(&cp).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        let last = lines.pop().unwrap();
        let cut = format!("{}\n{}", lines.join("\n"), &last[..last.len() / 2]);
        fs::write(&cp, cut).unwrap();
        // Änderung nach dem Abbruch und eine neue Datei.
        fs::write(data.join("b.txt"), "zwei geändert").unwrap();
        fs::write(data.join("d.txt"), "neu").unwrap();

        let (s2, calls2) = counting("1");
        let r = std::sync::Arc::new(crate::resume::Resume::load(&cp, &s2.version_key()).unwrap());
        assert_eq!(r.ignored_lines, 1);
        let s2 = s2.with_resume(r);
        let rep = run(&s2, &data);
        // a.txt übernommen; b geändert, c (halbe Zeile) und d neu geprüft.
        assert_eq!(calls2.load(Ordering::SeqCst), 3, "{rep:?}");
        let info = rep.scope.resume.as_ref().unwrap();
        assert_eq!(info.reused, 1);
        assert!(!info.version_mismatch);
        let a = rep
            .files
            .iter()
            .find(|f| f.path.ends_with("a.txt"))
            .unwrap();
        assert!(a.notes.iter().any(|n| n.contains("Fortsetzung")));
        let c = rep
            .files
            .iter()
            .find(|f| f.path.ends_with("c.bin"))
            .unwrap();
        assert_eq!(c.detection, Verdict::Malicious);
        assert_eq!(rep.summary.objects_total, 4);
    }

    /// Neuer Regel-/Signaturstand: nichts wird übernommen.
    #[test]
    fn resume_with_new_engine_content_rescans_everything() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "eins").unwrap();
        let roots = vec![dir.path().join("a.txt")];
        let cp = dir.path().join("cp.jsonl");
        let (s1, _) = counting("alt");
        {
            let mut np = NoProgress;
            let mut w = crate::resume::CheckpointWriter::create(&cp, &header(&s1, &roots), &mut np)
                .unwrap();
            s1.scan_paths(&roots, &AtomicBool::new(false), &mut w);
        }
        let (s2, calls) = counting("neu");
        assert_ne!(s1.version_key(), s2.version_key());
        let r = std::sync::Arc::new(crate::resume::Resume::load(&cp, &s2.version_key()).unwrap());
        assert!(r.version_mismatch);
        let rep = s2
            .with_resume(r)
            .scan_paths(&roots, &AtomicBool::new(false), &mut NoProgress);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(rep.scope.resume.as_ref().unwrap().reused, 0);
        // Eine bestehende Fortsetzungsdatei wird nie überschrieben.
        let mut np = NoProgress;
        assert!(
            crate::resume::CheckpointWriter::create(&cp, &header(&s1, &roots), &mut np).is_err()
        );
    }

    /// Früher unvollständige Ergebnisse werden nie übernommen; manipulierte
    /// Zeilen (anderer Hash) auch nicht.
    #[test]
    fn resume_never_reuses_incomplete_or_mismatching_entries() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x.txt");
        fs::write(&f, "inhalt").unwrap();
        let (s, calls) = counting("1");
        let key = s.version_key();
        let mut good = s.scan_file(&f);
        let mut incomplete = good.clone();
        incomplete.gaps.push(changed_gap());
        incomplete.status = ObjectStatus::Incomplete;
        good.sha256 = Some("00".repeat(32)); // anderer Inhalt behauptet
        for prev in [incomplete, good] {
            let cp = dir
                .path()
                .join(format!("cp-{}.jsonl", uuid::Uuid::new_v4()));
            let mut h = header(&s, std::slice::from_ref(&f));
            h.version_key = key.clone();
            let mut t = serde_json::to_string(&h).unwrap();
            t.push('\n');
            t.push_str(&serde_json::to_string(&prev).unwrap());
            t.push_str("\nkein json\n");
            fs::write(&cp, t).unwrap();
            let r = crate::resume::Resume::load(&cp, &key).unwrap();
            assert_eq!(r.ignored_lines, 1);
            assert!(r
                .reusable(&prev.path, &s.scan_file(&f).sha256.unwrap())
                .is_none());
        }
        assert!(calls.load(Ordering::SeqCst) >= 3);
    }

    #[test]
    fn stale_or_future_checkpoint_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (s, _) = counting("1");
        for when in [
            chrono::Utc::now() - chrono::Duration::days(8),
            chrono::Utc::now() + chrono::Duration::days(1),
        ] {
            let mut h = header(&s, &[]);
            h.created_utc = when.to_rfc3339();
            let p = dir.path().join(format!("{}.jsonl", uuid::Uuid::new_v4()));
            fs::write(&p, format!("{}\n", serde_json::to_string(&h).unwrap())).unwrap();
            assert!(crate::resume::Resume::load(&p, &s.version_key()).is_err());
        }
    }

    fn cached(s: Scanner, c: &std::sync::Arc<crate::cache::ScanCache>) -> Scanner {
        s.with_cache(c.clone())
    }

    /// AXS-027: Treffer sparen nur Engine-Zeit; gelesen und gehasht wird
    /// immer, Heuristik hängt am aktuellen Namen.
    #[test]
    fn cache_hit_skips_engines_but_heuristics_use_current_name() {
        let dir = tempfile::tempdir().unwrap();
        let pe = crate::features::tests::tiny_pe(0x90, 0);
        fs::write(dir.path().join("werkzeug.exe"), &pe).unwrap();
        fs::write(dir.path().join("brief.txt"), "hallo").unwrap();
        let c = std::sync::Arc::new(crate::cache::ScanCache::in_memory(100));
        let (s1, calls1) = counting("1");
        let r1 = run(&cached(s1, &c), dir.path());
        assert_eq!(calls1.load(Ordering::SeqCst), 2);
        assert_eq!(r1.scope.cache.as_ref().unwrap().hits, 0);

        // Gleicher Inhalt unter täuschendem Namen.
        fs::rename(
            dir.path().join("werkzeug.exe"),
            dir.path().join("Rechnung.pdf.exe"),
        )
        .unwrap();
        let (s2, calls2) = counting("1");
        let r2 = run(&cached(s2, &c), dir.path());
        assert_eq!(
            calls2.load(Ordering::SeqCst),
            0,
            "Engines nicht erneut aufgerufen"
        );
        assert_eq!(r2.scope.cache.as_ref().unwrap().hits, 2);
        let f = r2
            .files
            .iter()
            .find(|f| f.path.ends_with("Rechnung.pdf.exe"))
            .unwrap();
        assert!(f.notes.iter().any(|n| n.contains("Cache")));
        assert_eq!(
            f.detection,
            Verdict::Suspicious,
            "Heuristik muss den neuen Namen sehen: {f:?}"
        );
        assert!(f.sha256.is_some() && f.size == Some(pe.len() as u64));
    }

    /// Neuer Regel-/Signaturstand: keine alte Freigabe.
    #[test]
    fn cache_ignores_entries_from_older_engine_content() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "BAD erst nach Update erkannt").unwrap();
        let c = std::sync::Arc::new(crate::cache::ScanCache::in_memory(100));
        let (s1, _) = counting("alt");
        run(&cached(s1, &c), dir.path());
        let (s2, calls) = counting("neu");
        let r = run(&cached(s2, &c), dir.path());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(r.scope.cache.as_ref().unwrap().hits, 0);
    }

    /// Inhalt geändert, Größe und Änderungszeit wiederhergestellt (wie nach
    /// erneutem Einbinden oder gefälschtem Zeitstempel): Cache greift nicht.
    #[test]
    fn cache_is_bound_to_content_not_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.bin");
        fs::write(&p, "GUT-inhalt").unwrap();
        let mtime = fs::metadata(&p).unwrap().modified().unwrap();
        let c = std::sync::Arc::new(crate::cache::ScanCache::in_memory(100));
        let (s1, _) = counting("1");
        let r1 = run(&cached(s1, &c), &p);
        assert_eq!(r1.files[0].detection, Verdict::NoDetection);
        fs::write(&p, "BAD-inhalt").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        assert_eq!(fs::metadata(&p).unwrap().modified().unwrap(), mtime);
        let (s2, calls) = counting("1");
        let r2 = run(&cached(s2, &c), &p);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(r2.files[0].detection, Verdict::Malicious);
    }

    /// Unvollständige Ergebnisse (Lücken) werden nie zwischengespeichert.
    #[test]
    fn incomplete_results_are_never_cached() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x").unwrap();
        let c = std::sync::Arc::new(crate::cache::ScanCache::in_memory(100));
        let s =
            scanner(vec![Box::new(TestEngine::failing(Verdict::Timeout))]).with_cache(c.clone());
        let r = run(&s, dir.path());
        assert_eq!(r.files[0].status, ObjectStatus::Incomplete);
        assert_eq!(c.info().entries, 0);
    }

    /// T-027: andere Richtlinie ⇒ neue Bewertung statt Cache-Treffer.
    #[test]
    fn cache_misses_after_policy_change() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x").unwrap();
        let c = std::sync::Arc::new(crate::cache::ScanCache::in_memory(100));
        let mut p1 = crate::policy::Policy::default_policy("test");
        p1.version = "1".into();
        let mut p2 = p1.clone();
        p2.version = "2".into();
        let (s1, _) = counting("1");
        run(
            &cached(s1, &c).with_policy(std::sync::Arc::new(p1)),
            dir.path(),
        );
        let (s2, calls) = counting("1");
        let r = run(
            &cached(s2, &c).with_policy(std::sync::Arc::new(p2)),
            dir.path(),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(r.scope.cache.as_ref().unwrap().hits, 0);
    }

    #[test]
    fn version_key_covers_policy_and_limits() {
        let infos = TestEngine::prefix().info();
        let l = ScanLimits::default();
        let a = crate::resume::version_key(std::slice::from_ref(&infos), "p1", &l);
        assert_ne!(
            a,
            crate::resume::version_key(std::slice::from_ref(&infos), "p2", &l)
        );
        let l2 = ScanLimits {
            max_file_size: l.max_file_size + 1,
            ..l.clone()
        };
        assert_ne!(
            a,
            crate::resume::version_key(std::slice::from_ref(&infos), "p1", &l2)
        );
        let mut i2 = infos.clone();
        i2.content_version = "neu".into();
        assert_ne!(a, crate::resume::version_key(&[i2], "p1", &l));
    }

    #[test]
    fn report_states_kind_and_what_it_does_not_cover() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x").unwrap();
        let s = scanner(vec![Box::new(TestEngine::prefix())]).with_kind(
            crate::scanjob::ScanKind::Quick,
            crate::scanjob::Trigger::Schedule,
            vec!["/gibt/es/nicht".into()],
        );
        let rep = run(&s, dir.path());
        assert_eq!(rep.scope.kind, crate::scanjob::ScanKind::Quick);
        assert_eq!(rep.scope.trigger, crate::scanjob::Trigger::Schedule);
        assert!(rep.scope.kind_note.contains("Nicht geprüft"));
        assert_eq!(
            rep.scope.missing_targets,
            vec!["/gibt/es/nicht".to_string()]
        );
        assert_eq!(rep.scope.version_key.len(), 64);
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

    /// T-017: Ausnahmen der Richtlinie erscheinen als verringerte Abdeckung.
    #[test]
    fn policy_exclusion_is_reduced_coverage_never_complete() {
        use crate::policy::{Exclusion, ExclusionKind, Policy};
        let dir = tempfile::tempdir().unwrap();
        let skip = dir.path().join("build");
        fs::create_dir(&skip).unwrap();
        fs::write(skip.join("out.bin"), b"PREFIX-EICAR").unwrap();
        fs::write(dir.path().join("b.txt"), b"x").unwrap();
        let mut pol = Policy::default_policy("test");
        pol.version = "policy-file-v7".into();
        pol.exclusions.push(Exclusion {
            kind: ExclusionKind::Ordner,
            path: skip.display().to_string(),
            reason: "Build-Ausgabe".into(),
            created_by: "Administrator".into(),
            created_utc: "2026-10-20T00:00:00Z".into(),
            expires_utc: "2026-11-20T00:00:00Z".into(),
        });
        let s = scanner(vec![Box::new(TestEngine::prefix())]).with_policy(std::sync::Arc::new(pol));
        let rep = run(&s, dir.path());
        assert_eq!(rep.files.len(), 1, "nur b.txt geprüft: {:?}", rep.files);
        assert_eq!(rep.scope.excluded.len(), 1);
        assert!(rep.scope.excluded[0].reason.contains("policy-file-v7"));
        assert!(rep
            .job_gaps
            .iter()
            .any(|g| g.reason == GapReason::ExcludedByPolicy));
        assert!(!rep.complete);
        assert_eq!(rep.outcome, JobOutcome::Incomplete);
        assert!(rep.policy_version.ends_with("+policy-file-v7"));
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

    /// T-018: lange und Unicode-Pfade werden über das Handle gelesen und
    /// eindeutig identifiziert.
    #[test]
    fn long_and_unicode_paths_are_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = dir.path().to_path_buf();
        for i in 0..12 {
            p.push(format!("ordner-äöü-日本-{i:02}-xxxxxxxxxxxx"));
        }
        fs::create_dir_all(&p).unwrap();
        let f = p.join("Grüße 😀.txt");
        fs::write(&f, b"BAD-boese").unwrap();
        assert!(f.display().to_string().chars().count() > 300);
        let rep = run(&scanner(vec![Box::new(TestEngine::prefix())]), dir.path());
        let r = rep
            .files
            .iter()
            .find(|x| x.path.ends_with("Grüße 😀.txt"))
            .unwrap();
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert_eq!(r.detection, Verdict::Malicious);
        assert!(r.identity.as_ref().unwrap().file_id.is_some());
    }

    /// T-018: Alternate Data Streams werden gefunden und einzeln geprüft.
    #[cfg(windows)]
    #[test]
    fn alternate_data_streams_are_scanned_separately() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("harmlos.txt");
        fs::write(&f, b"harmlos").unwrap();
        fs::write(format!("{}:versteckt", f.display()), b"BAD-im-strom").unwrap();
        let rep = run(&scanner(vec![Box::new(TestEngine::prefix())]), dir.path());
        let main = rep
            .files
            .iter()
            .find(|x| x.path.ends_with("harmlos.txt"))
            .unwrap();
        assert_eq!(main.detection, Verdict::NoDetection);
        let ads = rep
            .files
            .iter()
            .find(|x| x.path.ends_with("harmlos.txt:versteckt"))
            .unwrap_or_else(|| panic!("ADS fehlt im Bericht: {:?}", rep.files));
        assert_eq!(ads.detection, Verdict::Malicious, "{ads:?}");
        assert_eq!(rep.outcome, JobOutcome::Detection);
    }

    /// T-018: Eine Junction im Prüfbereich wird nicht verfolgt.
    #[cfg(windows)]
    #[test]
    fn junction_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ziel");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("t.bin"), b"BAD").unwrap();
        let root = dir.path().join("bereich");
        fs::create_dir(&root).unwrap();
        let j = root.join("junction");
        let st = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&j)
            .arg(&target)
            .status()
            .unwrap();
        assert!(st.success());
        let rep = run(&scanner(vec![Box::new(TestEngine::prefix())]), &root);
        assert_eq!(rep.files.len(), 1, "{:?}", rep.files);
        assert_eq!(rep.files[0].gaps[0].reason, GapReason::LinkNotFollowed);
        assert_eq!(rep.files[0].object_type, ObjectType::Link);
    }

    /// T-018: 128-Bit-ID wird unter Windows gelesen und für den Vergleich genutzt.
    #[cfg(windows)]
    #[test]
    fn file_id_128_is_read_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.txt");
        fs::write(&p, b"x").unwrap();
        let id = FileIdentity::from_file(&File::open(&p).unwrap()).unwrap();
        assert_eq!(id.file_id_128.as_deref().map(str::len), Some(32), "{id:?}");
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
        ) -> (
            EngineOutcome,
            Option<Result<crate::engine::Classification, String>>,
        ) {
            (
                self.scan(input),
                Some(self.kind.clone().map(|kind| crate::engine::Classification {
                    kind,
                    features: None,
                })),
            )
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
        let real: Vec<_> = f
            .engines
            .iter()
            .filter(|e| e.engine != crate::heuristics::HEURISTICS_ENGINE)
            .collect();
        assert_eq!(real.len(), 1, "Engine darf nur einmal prüfen");
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
