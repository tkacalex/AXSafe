//! Host-Seite: der isolierte Worker als [`Engine`].

use crate::protocol::*;
use axsafe_core::engine::{
    ContentKind, Engine, EngineHealth, EngineInfo, EngineOutcome, Gap, GapReason, Isolation,
    IsolationKind, ScanInput,
};
use axsafe_core::verdict::Verdict;
use axsafe_engine_yarax::{describe_content, RuleSource, YARAX_VERSION};
pub use axsafe_proc::Sandbox;
use axsafe_proc::{Limits, Session, SessionError};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Konfiguration des Workers.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Pfad zu `axsafe-worker[.exe]`.
    pub worker_exe: PathBuf,
    /// Zusätzliche Argumente (nur für Testdoppel).
    pub args: Vec<String>,
    /// Regeltexte oder Ladefehler.
    pub rules: Result<Vec<RuleSource>, String>,
    /// Größte Datei, die an den Worker geht.
    pub max_scan_bytes: u64,
    /// Speichergrenze des Workers (Windows: Commit; Linux: Adressraum).
    pub memory_bytes: Option<u64>,
    /// Zeit für Start, Regelkompilierung und Probe.
    pub startup_timeout: Duration,
    /// Zuschlag je Objekt für Übertragung und Antwort.
    pub request_grace: Duration,
    /// Höchstzahl an Neustarts nach Ausfällen je Engine-Instanz.
    pub max_restarts: u32,
    /// Ohne nachgewiesene Abschottung nicht arbeiten (Windows: immer).
    pub require_isolation: bool,
    pub sandbox: Sandbox,
}

/// Speichergrenze des Workers: Grundbedarf plus zweimal die größte Nutzlast
/// (Rahmenpuffer und Kopie beim Scan).
pub fn memory_for(max_scan_bytes: u64) -> u64 {
    (512 * 1024 * 1024u64).saturating_add(max_scan_bytes.saturating_mul(2))
}

/// AppContainer-Profil des Scanworkers.
pub const APPCONTAINER_PROFILE: &str = "AXSafe.ScanWorker.v1";

impl WorkerConfig {
    pub fn new(worker_exe: PathBuf, rules: Result<Vec<RuleSource>, String>) -> Self {
        WorkerConfig {
            worker_exe,
            args: Vec::new(),
            rules,
            max_scan_bytes: 256 * 1024 * 1024,
            // Windows: Commit-Grenze im Job; Linux: Adressraum (RLIMIT_AS).
            // Gemessen: der Worker arbeitet mit den Repo-Regeln ab 128 MiB.
            memory_bytes: Some(memory_for(256 * 1024 * 1024)),
            startup_timeout: Duration::from_secs(60),
            request_grace: Duration::from_secs(5),
            max_restarts: 3,
            require_isolation: cfg!(windows),
            sandbox: if cfg!(windows) {
                Sandbox::AppContainer {
                    profile: APPCONTAINER_PROFILE.into(),
                }
            } else {
                Sandbox::None
            },
        }
    }

    fn limits(&self) -> Limits {
        Limits {
            timeout: self.startup_timeout,
            max_output_bytes: MAX_RESPONSE_BYTES,
            max_memory_bytes: self.memory_bytes,
            // Der Worker darf keine weiteren Prozesse starten.
            max_processes: Some(1),
        }
    }
}

struct State {
    session: Option<Session>,
    restarts: u32,
    disabled: Option<String>,
}

/// YARA-X im isolierten Worker.
pub struct WorkerEngine {
    cfg: WorkerConfig,
    info: EngineInfo,
    probe: Vec<ProbeCheck>,
    state: Mutex<State>,
}

fn proto_err(msg: impl Into<String>) -> String {
    msg.into()
}

/// Liest eine Antwort (Typ, Nutzdaten) bis zum Ablaufdatum.
fn read_response(s: &mut Session, deadline: Instant) -> Result<(u8, Vec<u8>), SessionError> {
    let len = s.read_exact(4, deadline)?;
    let len = u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize;
    if len == 0 || len > MAX_RESPONSE_BYTES + 1 {
        return Err(SessionError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Antwortlänge {len} unzulässig"),
        )));
    }
    let body = s.read_exact(len, deadline)?;
    Ok((body[0], body[1..].to_vec()))
}

fn session_detail(e: &SessionError, s: &Session) -> String {
    let err = s.stderr_text();
    let err = err.trim();
    if err.is_empty() {
        e.to_string()
    } else {
        format!(
            "{e}; Fehlerausgabe: {}",
            err.chars().take(300).collect::<String>()
        )
    }
}

/// Startet den Worker, sendet die Regeln und wartet auf `Ready`.
fn start_session(cfg: &WorkerConfig, rules: &[RuleSource]) -> Result<(Session, Ready), String> {
    let mut cmd = Command::new(&cfg.worker_exe);
    cmd.args(&cfg.args);
    let mut s = Session::spawn(cmd, &cfg.limits(), &cfg.sandbox)
        .map_err(|e| format!("Worker {} nicht startbar: {e}", cfg.worker_exe.display()))?;
    let deadline = Instant::now() + cfg.startup_timeout;
    let init = Init {
        protocol: PROTOCOL.into(),
        rules: rules.to_vec(),
        max_scan_bytes: cfg.max_scan_bytes,
    };
    let json = serde_json::to_vec(&init).map_err(|e| e.to_string())?;
    let frame = encode_frame(T_INIT, &json).map_err(|e| e.to_string())?;
    if let Err(e) = s.write_all(frame, deadline) {
        let d = session_detail(&e, &s);
        s.kill();
        return Err(format!("Worker nahm Regeln nicht an: {d}"));
    }
    match read_response(&mut s, deadline) {
        Ok((T_READY, p)) => match serde_json::from_slice::<Ready>(&p) {
            Ok(r) if r.protocol == PROTOCOL => Ok((s, r)),
            Ok(r) => {
                s.kill();
                Err(format!("Worker spricht {} statt {PROTOCOL}", r.protocol))
            }
            Err(e) => {
                s.kill();
                Err(proto_err(format!("Ready ungültig: {e}")))
            }
        },
        Ok((T_ERROR, p)) => {
            s.kill();
            let m = serde_json::from_slice::<ErrorMsg>(&p)
                .map(|m| m.message)
                .unwrap_or_else(|_| "unlesbare Fehlermeldung".into());
            Err(format!("Worker verweigert: {m}"))
        }
        Ok((k, _)) => {
            s.kill();
            Err(format!("unerwartete Antwort {k:#x} statt Ready"))
        }
        Err(e) => {
            let d = session_detail(&e, &s);
            s.kill();
            Err(format!("Worker antwortete nicht: {d}"))
        }
    }
}

/// Probedateien und lokaler Lauscher für den Isolationsnachweis.
struct ProbeSetup {
    dir: PathBuf,
    file: PathBuf,
    listener: std::net::TcpListener,
}

impl ProbeSetup {
    fn new() -> std::io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "axsafe-isolationsprobe-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&dir)?;
        let file = dir.join("probe.txt");
        std::fs::write(&file, b"AXSafe Isolationsprobe")?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        Ok(ProbeSetup {
            dir,
            file,
            listener,
        })
    }

    fn probe(&self, worker_exe: &std::path::Path) -> std::io::Result<Probe> {
        Ok(Probe {
            read_paths: vec![self.file.display().to_string()],
            write_paths: vec![self.file.display().to_string()],
            create_in: vec![self.dir.display().to_string()],
            connect: vec![self.listener.local_addr()?.to_string()],
            spawn: vec![worker_exe.display().to_string()],
        })
    }

    /// Ob eine Verbindung den Lauscher erreicht hat.
    fn reached(&self) -> bool {
        self.listener.accept().is_ok()
    }
}

impl Drop for ProbeSetup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn send_probe(s: &mut Session, probe: &Probe) -> Result<Vec<ProbeCheck>, String> {
    let json = serde_json::to_vec(probe).map_err(|e| e.to_string())?;
    let frame = encode_frame(T_PROBE, &json).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(20);
    s.write_all(frame, deadline)
        .map_err(|e| format!("Probe nicht gesendet: {e}"))?;
    match read_response(s, deadline) {
        Ok((T_PROBE_RESULT, p)) => {
            serde_json::from_slice(&p).map_err(|e| format!("Probeergebnis ungültig: {e}"))
        }
        Ok((k, _)) => Err(format!("unerwartete Antwort {k:#x} auf Probe")),
        Err(e) => Err(format!("Probe ohne Antwort: {}", session_detail(&e, s))),
    }
}

/// Führt die Probe aus; Rückgabe: Einzelergebnisse und ob alles verweigert wurde.
fn run_probe(s: &mut Session, cfg: &WorkerConfig) -> Result<(Vec<ProbeCheck>, bool), String> {
    let setup = ProbeSetup::new().map_err(|e| format!("Probe nicht vorbereitbar: {e}"))?;
    let probe = setup
        .probe(&cfg.worker_exe)
        .map_err(|e| format!("Probe nicht vorbereitbar: {e}"))?;
    let checks = send_probe(s, &probe)?;
    let expected = probe.read_paths.len()
        + probe.write_paths.len()
        + probe.create_in.len()
        + probe.connect.len()
        + probe.spawn.len();
    let reached = setup.reached();
    let original = std::fs::read(&setup.file).ok();
    let untouched = original.as_deref() == Some(&b"AXSafe Isolationsprobe"[..]);
    let all_denied = checks.len() == expected && checks.iter().all(|c| c.denied);
    Ok((checks, all_denied && !reached && untouched))
}

impl WorkerEngine {
    /// Startet den Worker und weist die Abschottung nach. Scheitert etwas,
    /// ist die Engine `Unavailable` mit Grund – nie still „bereit“.
    pub fn start(cfg: WorkerConfig) -> Self {
        let mut info = EngineInfo {
            name: "yara-x".into(),
            engine_version: YARAX_VERSION.into(),
            content_version: "nicht geladen".into(),
            health: EngineHealth::Unavailable {
                reason: "nicht gestartet".into(),
            },
            license: "BSD-3-Clause (Engine; Regellizenzen je Regel in meta.license)".into(),
            content_kind: ContentKind::Unknown,
            content_note: "Regelsatz nicht geladen".into(),
            inspects_contents_of: Vec::new(),
            isolation: Isolation {
                kind: IsolationKind::SandboxedWorker,
                enforced: false,
                detail: "nicht gestartet".into(),
            },
        };
        let mut state = State {
            session: None,
            restarts: 0,
            disabled: None,
        };
        let mut probe_checks = Vec::new();
        let unavailable = |info: &mut EngineInfo, reason: String| {
            info.health = EngineHealth::Unavailable { reason };
        };

        let rules = match &cfg.rules {
            Ok(r) => r.clone(),
            Err(e) => {
                unavailable(&mut info, e.clone());
                return WorkerEngine {
                    cfg,
                    info,
                    probe: probe_checks,
                    state: Mutex::new(state),
                };
            }
        };
        // Ein Wiederholungsversuch bei Startfehlern (z. B. parallele
        // AppContainer-Profilanlage); beide Fehler bleiben sichtbar.
        let first = start_session(&cfg, &rules);
        let started = match first {
            Ok(x) => Ok(x),
            Err(e1) => {
                std::thread::sleep(Duration::from_millis(250));
                start_session(&cfg, &rules).map_err(|e2| {
                    if e1 == e2 {
                        e2
                    } else {
                        format!("{e2} (erster Versuch: {e1})")
                    }
                })
            }
        };
        match started {
            Err(e) => unavailable(&mut info, e),
            Ok((mut s, ready)) => {
                info.engine_version = ready.engine_version.clone();
                match &ready.rules {
                    Err(e) => unavailable(&mut info, format!("Regelsatz abgelehnt: {e}")),
                    Ok(st) => {
                        info.content_version = st.content_version.clone();
                        let (k, n) = describe_content(st);
                        info.content_kind = k;
                        info.content_note = n;
                        match run_probe(&mut s, &cfg) {
                            Err(e) => {
                                info.isolation.detail = format!("Probe gescheitert: {e}");
                                unavailable(&mut info, format!("Isolation nicht prüfbar: {e}"));
                                s.kill();
                            }
                            Ok((checks, ok)) => {
                                let enforced =
                                    ok && ready.sandbox.filesystem && ready.sandbox.network;
                                let open: Vec<String> = checks
                                    .iter()
                                    .filter(|c| !c.denied)
                                    .map(|c| format!("{} {}", c.action, c.target))
                                    .collect();
                                info.isolation = Isolation {
                                    kind: if enforced {
                                        IsolationKind::SandboxedWorker
                                    } else {
                                        IsolationKind::ChildProcess
                                    },
                                    enforced,
                                    detail: if open.is_empty() {
                                        format!(
                                            "{}; Probe: {} verbotene Aktionen verweigert",
                                            ready.sandbox.detail,
                                            checks.len()
                                        )
                                    } else {
                                        format!(
                                            "{}; Probe: ERLAUBT war: {}",
                                            ready.sandbox.detail,
                                            open.join(", ")
                                        )
                                    },
                                };
                                probe_checks = checks;
                                if cfg.require_isolation && !enforced {
                                    let why = format!(
                                        "Isolation nicht nachgewiesen – Worker wird nicht \
                                         verwendet ({})",
                                        info.isolation.detail
                                    );
                                    unavailable(&mut info, why);
                                    s.kill();
                                } else {
                                    info.health = EngineHealth::Ready;
                                    state.session = Some(s);
                                }
                            }
                        }
                    }
                }
            }
        }
        WorkerEngine {
            cfg,
            info,
            probe: probe_checks,
            state: Mutex::new(state),
        }
    }

    /// Einzelergebnisse des Isolationsnachweises.
    pub fn probe_checks(&self) -> &[ProbeCheck] {
        &self.probe
    }

    /// Zusätzliche Probe auf dem laufenden Worker (z. B. Systemdateien,
    /// externe Adressen). Jede Aktion sollte verweigert werden.
    pub fn probe(&self, probe: &Probe) -> Result<Vec<ProbeCheck>, String> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let s = st
            .session
            .as_mut()
            .ok_or_else(|| "kein laufender Worker".to_string())?;
        send_probe(s, probe)
    }

    /// Anzahl Neustarts nach Ausfällen (Diagnose/Tests).
    pub fn restarts(&self) -> u32 {
        self.state
            .lock()
            .map(|s| s.restarts)
            .unwrap_or_else(|p| p.into_inner().restarts)
    }

    fn gap(
        &self,
        start: Instant,
        verdict: Verdict,
        reason: GapReason,
        detail: String,
    ) -> EngineOutcome {
        EngineOutcome {
            engine: "yara-x".into(),
            engine_version: self.info.engine_version.clone(),
            content_version: self.info.content_version.clone(),
            verdict,
            detections: Vec::new(),
            gaps: vec![Gap::new(verdict, reason, "yara-x", detail.clone())],
            note: Some(detail),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Worker nach einem Ausfall verwerfen und Neustart vormerken.
    fn failed(&self, st: &mut State) {
        if let Some(mut s) = st.session.take() {
            s.kill();
        }
        st.restarts += 1;
        if st.restarts > self.cfg.max_restarts {
            st.disabled = Some(format!(
                "Worker {} Mal ausgefallen; YARA-X für diesen Auftrag abgeschaltet",
                st.restarts
            ));
        }
    }
}

impl Engine for WorkerEngine {
    fn name(&self) -> &str {
        "yara-x"
    }

    fn info(&self) -> EngineInfo {
        self.info.clone()
    }

    fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
        let start = Instant::now();
        if let EngineHealth::Unavailable { reason } = &self.info.health {
            return self.gap(
                start,
                Verdict::Error,
                GapReason::EngineUnavailable,
                reason.clone(),
            );
        }
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(r) = &st.disabled {
            return self.gap(
                start,
                Verdict::Error,
                GapReason::EngineUnavailable,
                r.clone(),
            );
        }
        if input.data.len() as u64 > self.cfg.max_scan_bytes {
            return self.gap(
                start,
                Verdict::Unsupported,
                GapReason::SizeLimit,
                format!(
                    "Objekt größer als die Worker-Grenze ({} Bytes)",
                    self.cfg.max_scan_bytes
                ),
            );
        }
        if st.session.is_none() {
            let rules = self.cfg.rules.as_ref().cloned().unwrap_or_default();
            match start_session(&self.cfg, &rules) {
                Ok((s, _)) => st.session = Some(s),
                Err(e) => {
                    self.failed(&mut st);
                    return self.gap(
                        start,
                        Verdict::Error,
                        GapReason::EngineError,
                        format!("Neustart des Workers fehlgeschlagen: {e}"),
                    );
                }
            }
        }
        let budget_ms = u32::try_from(input.timeout.as_millis()).unwrap_or(u32::MAX);
        let mut payload = Vec::with_capacity(input.data.len() + 4);
        payload.extend_from_slice(&budget_ms.to_le_bytes());
        payload.extend_from_slice(input.data);
        let frame = match encode_frame(T_SCAN, &payload) {
            Ok(f) => f,
            Err(e) => {
                return self.gap(start, Verdict::Error, GapReason::EngineError, e.to_string())
            }
        };
        drop(payload);
        let deadline = start + input.timeout + self.cfg.request_grace;
        let s = st.session.as_mut().expect("Sitzung vorhanden");
        let res = s
            .write_all(frame, deadline)
            .and_then(|_| read_response(s, deadline));
        match res {
            Ok((T_RESULT, p)) => match serde_json::from_slice::<EngineOutcome>(&p) {
                Ok(mut o) if o.engine == "yara-x" => {
                    o.duration_ms = start.elapsed().as_millis() as u64;
                    o
                }
                Ok(o) => {
                    self.failed(&mut st);
                    self.gap(
                        start,
                        Verdict::Error,
                        GapReason::EngineError,
                        format!("Worker meldete fremde Engine '{}'", o.engine),
                    )
                }
                Err(e) => {
                    self.failed(&mut st);
                    self.gap(
                        start,
                        Verdict::Error,
                        GapReason::EngineError,
                        format!("Antwort des Workers ungültig: {e}"),
                    )
                }
            },
            Ok((T_ERROR, p)) => {
                let m = serde_json::from_slice::<ErrorMsg>(&p)
                    .map(|m| m.message)
                    .unwrap_or_else(|_| "unlesbare Fehlermeldung".into());
                self.failed(&mut st);
                self.gap(
                    start,
                    Verdict::Error,
                    GapReason::EngineError,
                    format!("Worker meldet Fehler: {m}"),
                )
            }
            Ok((k, _)) => {
                self.failed(&mut st);
                self.gap(
                    start,
                    Verdict::Error,
                    GapReason::EngineError,
                    format!("Protokollverletzung: Antworttyp {k:#x}"),
                )
            }
            Err(SessionError::Timeout) => {
                self.failed(&mut st);
                self.gap(
                    start,
                    Verdict::Timeout,
                    GapReason::EngineTimeout,
                    "Worker überschritt das Zeitbudget und wurde beendet".into(),
                )
            }
            Err(e) => {
                let d = session_detail(&e, s);
                self.failed(&mut st);
                self.gap(
                    start,
                    Verdict::Error,
                    GapReason::EngineError,
                    format!("Worker ausgefallen: {d}"),
                )
            }
        }
    }
}

impl Drop for WorkerEngine {
    fn drop(&mut self) {
        if let Ok(mut st) = self.state.lock() {
            if let Some(s) = st.session.take() {
                s.shutdown(Duration::from_millis(500));
            }
        }
    }
}
