//! Host-Seite: der isolierte Worker als [`Engine`].
//!
//! Jeder Worker-Prozess – der erste und jeder Neustart – wird vollständig
//! geprüft, bevor er Scandaten bekommt ([`launch`]):
//!
//! 1. Protokoll und `Ready`-Antwort,
//! 2. Regelsatz angenommen; bei Neustarts derselbe Inhaltsstand wie beim
//!    ersten Start,
//! 3. nur die ausdrücklich festgelegten Umgebungsvariablen sind sichtbar,
//! 4. Isolationsprobe (Lesen, Schreiben, Anlegen, TCP, Programmstart müssen
//!    scheitern) – ohne Nachweis gehen keine Daten an den Worker.
//!
//! Zeitgrenzen: Start inkl. Regelkompilierung `startup_timeout` (60 s),
//! Probe 20 s, je Objekt Budget + `request_grace` (5 s), geordnetes Beenden
//! 500 ms, danach wird der Prozessbaum hart beendet (Job Object bzw.
//! Prozessgruppe). Der Worker darf keine Nachkommen starten.

use crate::protocol::*;
use axsafe_core::engine::{
    ContentKind, Engine, EngineHealth, EngineInfo, EngineOutcome, Gap, GapReason, Isolation,
    IsolationKind, ScanInput,
};
use axsafe_core::filetype::FileKind;
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
    /// Zusätzliche Argumente (nur für Testdoppel; der echte Worker hat keine).
    pub args: Vec<String>,
    /// Argumente für Neustarts; `None` = wie beim ersten Start. Nur für
    /// Testdoppel (z. B. „Neustart liefert anderen Inhaltsstand“).
    pub restart_args: Option<Vec<String>>,
    /// Vollständige Umgebung des Workers. Es wird NICHTS vom Host geerbt.
    pub env: Vec<(String, String)>,
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
    /// Ohne nachgewiesene Abschottung keine Scandaten (Standard: überall an).
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

pub use axsafe_proc::minimal_env;

impl WorkerConfig {
    pub fn new(worker_exe: PathBuf, rules: Result<Vec<RuleSource>, String>) -> Self {
        WorkerConfig {
            worker_exe,
            args: Vec::new(),
            restart_args: None,
            env: minimal_env(),
            rules,
            max_scan_bytes: 256 * 1024 * 1024,
            // Windows: Commit-Grenze im Job; Linux: Adressraum (RLIMIT_AS).
            // Gemessen: der Worker arbeitet mit den Repo-Regeln ab 128 MiB.
            memory_bytes: Some(memory_for(256 * 1024 * 1024)),
            startup_timeout: Duration::from_secs(60),
            request_grace: Duration::from_secs(5),
            max_restarts: 3,
            require_isolation: true,
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
    /// Aktueller Zustand; wird nach Ausfällen und Neustarts nachgeführt.
    info: Mutex<EngineInfo>,
    probe: Mutex<Vec<ProbeCheck>>,
    /// Umgebungsvariablen-Namen, die der aktuelle Worker meldete.
    env_names: Mutex<Vec<String>>,
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
fn start_session(
    cfg: &WorkerConfig,
    rules: &[RuleSource],
    args: &[String],
) -> Result<(Session, Ready), String> {
    let mut cmd = Command::new(&cfg.worker_exe);
    cmd.args(args);
    // Keine Umgebung erben; nur die festgelegten Variablen (AppContainer-
    // Start unter Windows übernimmt ebenfalls nur diese).
    cmd.env_clear();
    cmd.envs(cfg.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
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
        // Eindeutig je Prozess und Aufruf (Zähler), Anlegen exklusiv mit
        // Wiederholung: parallele Engines im selben Prozess kollidierten
        // sonst bei gleicher Zeitmarke (in der CI beobachtet).
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut dir = PathBuf::new();
        let mut last = None;
        for _ in 0..16 {
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            dir = std::env::temp_dir().join(format!(
                "axsafe-isolationsprobe-{}-{n}-{nanos}",
                std::process::id()
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    last = None;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        if let Some(e) = last {
            return Err(e);
        }
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

/// Ein vollständig geprüfter, einsatzbereiter Worker.
struct Launched {
    session: Session,
    ready: Ready,
    checks: Vec<ProbeCheck>,
    isolation: Isolation,
}

/// Grund, warum ein Worker nicht verwendet wird.
struct Rejected {
    reason: String,
    isolation: Option<Isolation>,
    checks: Vec<ProbeCheck>,
}

impl From<String> for Rejected {
    fn from(reason: String) -> Self {
        Rejected {
            reason,
            isolation: None,
            checks: Vec::new(),
        }
    }
}

fn isolation_from(
    ready: &Ready,
    checks: &[ProbeCheck],
    probe_ok: bool,
    env_ok: Result<(), String>,
) -> Isolation {
    let enforced = probe_ok && ready.sandbox.filesystem && ready.sandbox.network && env_ok.is_ok();
    let open: Vec<String> = checks
        .iter()
        .filter(|c| !c.denied)
        .map(|c| format!("{} {}", c.action, c.target))
        .collect();
    let mut detail = if open.is_empty() {
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
    };
    if let Err(e) = env_ok {
        detail.push_str("; ");
        detail.push_str(&e);
    }
    Isolation {
        kind: if enforced {
            IsolationKind::SandboxedWorker
        } else {
            IsolationKind::ChildProcess
        },
        enforced,
        detail,
    }
}

/// Startet einen Worker und prüft ihn vollständig (siehe Moduldoku).
/// `expected_content`: Inhaltsstand, den ein Neustart liefern muss.
fn launch(
    cfg: &WorkerConfig,
    rules: &[RuleSource],
    args: &[String],
    expected_content: Option<&str>,
) -> Result<Launched, Rejected> {
    let (mut s, ready) = start_session(cfg, rules, args)?;
    let stats = match &ready.rules {
        Ok(st) => st.clone(),
        Err(e) => {
            s.kill();
            return Err(format!("Regelsatz abgelehnt: {e}").into());
        }
    };
    if let Some(exp) = expected_content {
        if stats.content_version != exp {
            s.kill();
            return Err(format!(
                "Inhaltsstand nach Neustart weicht ab ({} statt {exp}) – Worker verworfen",
                stats.content_version
            )
            .into());
        }
    }
    // Nur die ausdrücklich festgelegten Variablen dürfen sichtbar sein.
    let allowed: Vec<String> = cfg
        .env
        .iter()
        .map(|(k, _)| k.to_ascii_uppercase())
        .collect();
    let extra: Vec<&String> = ready
        .env_names
        .iter()
        .filter(|n| !allowed.contains(&n.to_ascii_uppercase()))
        .collect();
    let env_ok = if extra.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "unerwartete Umgebungsvariablen im Worker: {}",
            extra
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    };
    let (checks, probe_ok) = match run_probe(&mut s, cfg) {
        Ok(x) => x,
        Err(e) => {
            s.kill();
            return Err(Rejected {
                reason: format!("Isolation nicht prüfbar: {e}"),
                isolation: Some(Isolation {
                    kind: IsolationKind::ChildProcess,
                    enforced: false,
                    detail: format!("Probe gescheitert: {e}"),
                }),
                checks: Vec::new(),
            });
        }
    };
    #[allow(unused_mut)]
    let mut isolation = isolation_from(&ready, &checks, probe_ok, env_ok);
    // Windows: Mitigationen wurden beim Start gesetzt und vor dem Fortsetzen
    // des Prozesses geprüft (axsafe-proc, fail closed).
    #[cfg(windows)]
    if let axsafe_proc::Sandbox::AppContainer { .. } | axsafe_proc::Sandbox::Restricted =
        &cfg.sandbox
    {
        isolation.detail.push_str("; ");
        isolation
            .detail
            .push_str(axsafe_proc::mitigation_summary(matches!(
                cfg.sandbox,
                axsafe_proc::Sandbox::AppContainer { .. }
            )));
    }
    if cfg.require_isolation && !isolation.enforced {
        s.kill();
        return Err(Rejected {
            reason: format!(
                "Isolation nicht nachgewiesen – Worker erhält keine Daten ({})",
                isolation.detail
            ),
            isolation: Some(isolation),
            checks,
        });
    }
    Ok(Launched {
        session: s,
        ready,
        checks,
        isolation,
    })
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
        let mut checks = Vec::new();
        let mut env_names = Vec::new();
        match &cfg.rules {
            Err(e) => info.health = EngineHealth::Unavailable { reason: e.clone() },
            Ok(rules) => {
                // Ein Wiederholungsversuch bei Startfehlern (z. B. parallele
                // AppContainer-Profilanlage); beide Fehler bleiben sichtbar.
                let r = launch(&cfg, rules, &cfg.args, None).or_else(|e1| {
                    std::thread::sleep(Duration::from_millis(250));
                    launch(&cfg, rules, &cfg.args, None).map_err(|mut e2| {
                        if e1.reason != e2.reason {
                            e2.reason = format!("{} (erster Versuch: {})", e2.reason, e1.reason);
                        }
                        e2
                    })
                });
                match r {
                    Ok(l) => {
                        let st = l.ready.rules.as_ref().expect("in launch geprüft");
                        info.engine_version = l.ready.engine_version.clone();
                        info.content_version = st.content_version.clone();
                        let (k, n) = describe_content(st);
                        info.content_kind = k;
                        info.content_note = n;
                        info.isolation = l.isolation;
                        info.health = EngineHealth::Ready;
                        checks = l.checks;
                        env_names = l.ready.env_names.clone();
                        state.session = Some(l.session);
                    }
                    Err(rej) => {
                        if let Some(i) = rej.isolation {
                            info.isolation = i;
                        }
                        checks = rej.checks;
                        info.health = EngineHealth::Unavailable { reason: rej.reason };
                    }
                }
            }
        }
        WorkerEngine {
            cfg,
            info: Mutex::new(info),
            probe: Mutex::new(checks),
            env_names: Mutex::new(env_names),
            state: Mutex::new(state),
        }
    }

    /// Namen der Umgebungsvariablen, die der aktuelle Worker sieht.
    pub fn worker_env_names(&self) -> Vec<String> {
        self.env_names
            .lock()
            .map(|e| e.clone())
            .unwrap_or_else(|p| p.into_inner().clone())
    }

    /// Einzelergebnisse des letzten Isolationsnachweises.
    pub fn probe_checks(&self) -> Vec<ProbeCheck> {
        self.probe
            .lock()
            .map(|p| p.clone())
            .unwrap_or_else(|p| p.into_inner().clone())
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

    fn set_info(&self, f: impl FnOnce(&mut EngineInfo)) {
        let mut i = self.info.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut i);
    }

    fn current(&self) -> EngineInfo {
        self.info
            .lock()
            .map(|i| i.clone())
            .unwrap_or_else(|p| p.into_inner().clone())
    }

    /// Startet nach einem Ausfall einen neuen Worker und prüft ihn wie den
    /// ersten. Bei Ablehnung gehen keine Daten an ihn.
    fn relaunch(&self, st: &mut State) -> Result<(), String> {
        let rules = self.cfg.rules.as_ref().map_err(|e| e.clone())?;
        let expected = self.current().content_version;
        let args = self.cfg.restart_args.as_ref().unwrap_or(&self.cfg.args);
        match launch(&self.cfg, rules, args, Some(&expected)) {
            Ok(l) => {
                let n = st.restarts;
                self.set_info(|i| {
                    i.isolation = l.isolation.clone();
                    i.isolation.detail =
                        format!("{} (erneut geprüft nach Neustart {n})", i.isolation.detail);
                });
                if let Ok(mut p) = self.probe.lock() {
                    *p = l.checks;
                }
                if let Ok(mut e) = self.env_names.lock() {
                    *e = l.ready.env_names.clone();
                }
                st.session = Some(l.session);
                Ok(())
            }
            Err(rej) => {
                if let Some(i) = rej.isolation {
                    self.set_info(|info| info.isolation = i);
                }
                if let Ok(mut p) = self.probe.lock() {
                    *p = rej.checks;
                }
                self.failed(st);
                Err(rej.reason)
            }
        }
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
            engine_version: self.current().engine_version,
            content_version: self.current().content_version,
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
        if st.restarts > self.cfg.max_restarts && st.disabled.is_none() {
            let why = format!(
                "Worker {} Mal ausgefallen; YARA-X für diesen Auftrag abgeschaltet",
                st.restarts
            );
            self.set_info(|i| {
                i.health = EngineHealth::Unavailable {
                    reason: why.clone(),
                }
            });
            st.disabled = Some(why);
        }
    }
}

impl Engine for WorkerEngine {
    fn name(&self) -> &str {
        "yara-x"
    }

    fn info(&self) -> EngineInfo {
        self.current()
    }

    fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
        let mut k = None;
        self.run_scan(input, &mut k)
    }

    fn classifies(&self) -> bool {
        true
    }

    fn scan_and_classify(
        &self,
        input: &ScanInput<'_>,
    ) -> (EngineOutcome, Option<Result<FileKind, String>>) {
        let mut k = None;
        let o = self.run_scan(input, &mut k);
        let k = k.unwrap_or_else(|| {
            Err(o
                .note
                .clone()
                .unwrap_or_else(|| "Worker lieferte keinen Dateityp".into()))
        });
        (o, Some(k))
    }
}

impl WorkerEngine {
    fn run_scan(
        &self,
        input: &ScanInput<'_>,
        kind_out: &mut Option<Result<FileKind, String>>,
    ) -> EngineOutcome {
        let start = Instant::now();
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(r) = &st.disabled {
            return self.gap(
                start,
                Verdict::Error,
                GapReason::EngineUnavailable,
                r.clone(),
            );
        }
        if let EngineHealth::Unavailable { reason } = &self.current().health {
            return self.gap(
                start,
                Verdict::Error,
                GapReason::EngineUnavailable,
                reason.clone(),
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
            if let Err(e) = self.relaunch(&mut st) {
                return self.gap(
                    start,
                    Verdict::Error,
                    GapReason::EngineError,
                    format!("Neustart des Workers abgelehnt, keine Daten übergeben: {e}"),
                );
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
            Ok((T_RESULT, p)) => match serde_json::from_slice::<ScanReply>(&p) {
                Ok(ScanReply {
                    outcome: mut o,
                    file_kind,
                }) if o.engine == "yara-x" => {
                    o.duration_ms = start.elapsed().as_millis() as u64;
                    *kind_out = Some(Ok(file_kind));
                    o
                }
                Ok(ScanReply { outcome: o, .. }) => {
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
