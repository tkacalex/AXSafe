//! Dauerhaft geladene ClamAV-Engine (B-18): `axsafe-clamav-worker` lädt
//! libclamav und die Signaturen EINMAL und prüft danach beliebig viele
//! Objekte, statt für jedes Objekt `clamscan` samt Datenbank neu zu starten.
//!
//! Sicherheit (gleich streng wie der YARA-X-Worker, ADR-0006):
//! * Der Worker bekommt nur Bytes über eine anonyme Pipe – keine Pfade, keine
//!   Netzwerkschnittstelle, kein clamd. Nur dieser Prozess kann ihn erreichen.
//! * Windows: eingeschränktes Token (Integrität Niedrig) im Job Object
//!   (1 Prozess, Speichergrenze); der Worker prüft sein Token selbst.
//!   Linux: Landlock nach dem Laden der Datenbank.
//! * JEDER Start (auch nach Absturz, Leerlauf oder Signaturupdate) wird
//!   vollständig geprüft, bevor er Daten bekommt: Protokoll, Datenbank
//!   geladen, Datenbankstand passt zu den Dateiköpfen, nur festgelegte
//!   Umgebungsvariablen, Isolationsprobe.
//! * Ein Auftrag läuft synchron: genau eine Anfrage ist unterwegs, die
//!   Antwort gehört zu ihr (anonyme Pipe, keine Kennungen, die man fälschen
//!   könnte). Aufträge mehrerer Benutzer warten begrenzt in einer
//!   Warteschlange (`queue_wait`).
//! * Zeitüberschreitung, Absturz, Protokollbruch → Prüflücke, Worker wird
//!   beendet und beim nächsten Objekt neu gestartet; nach `max_restarts`
//!   Ausfällen bleibt die Engine abgeschaltet (sichtbar, nie „sauber“).
//! * Signaturupdate: Ändert sich der Datenbankstand, wird ein NEUER Worker
//!   gestartet und geprüft. Erst wenn er bereit ist, ersetzt er den alten.
//!   Scheitert das, bleibt der alte Stand aktiv und der Fehler ist in der
//!   Engine-Beschreibung sichtbar.
//! * Nach `idle_timeout` ohne Anfrage wird der Worker beendet (Speicher frei);
//!   der nächste Auftrag startet ihn neu (Kaltstart).

use crate::{classify, database_content, is_test_signature, DbContent};
use axsafe_core::engine::{
    ContentKind, Detection, Engine, EngineHealth, EngineInfo, EngineOutcome, Gap, GapReason,
    Isolation, IsolationKind, ScanInput,
};
use axsafe_core::verdict::{aggregate, Verdict};
use axsafe_proc::{Limits, Sandbox, Session, SessionError};
use axsafe_workerproto::clamav::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Einstellungen des dauerhaften Workers.
#[derive(Debug, Clone)]
pub struct WorkerSettings {
    /// Pfad zu `axsafe-clamav-worker[.exe]`.
    pub worker_exe: PathBuf,
    /// Pfad zu libclamav; `None` = neben `clamscan` (Windows) bzw. Systempfad.
    pub library: Option<PathBuf>,
    /// Signaturdatenbank; `None` = `/var/lib/clamav` (Linux).
    pub database: Option<PathBuf>,
    /// Zusätzliche Argumente (nur Testdoppel).
    pub args: Vec<String>,
    /// Vollständige Umgebung des Workers; es wird nichts geerbt.
    pub env: Vec<(String, String)>,
    pub sandbox: Sandbox,
    pub max_scan_bytes: u64,
    pub memory_bytes: u64,
    /// Laden von Bibliothek und Datenbank (offizielle DB: einige Sekunden bis Minuten).
    pub startup_timeout: Duration,
    pub request_grace: Duration,
    pub max_restarts: u32,
    pub idle_timeout: Duration,
    /// Wie oft höchstens der Datenbankstand geprüft wird.
    pub update_check: Duration,
    /// Höchste Wartezeit in der Warteschlange je Objekt.
    pub queue_wait: Duration,
    pub max_filesize: u64,
    pub max_scansize: u64,
    pub max_recursion: u32,
    pub max_files: u32,
    /// Signaturen gelten ab diesem Alter (daily) als veraltet (sichtbar).
    pub stale_after: Duration,
}

impl WorkerSettings {
    pub fn new(worker_exe: PathBuf, clamav: &crate::ClamAvConfig) -> Self {
        WorkerSettings {
            worker_exe,
            library: None,
            database: clamav.database.clone(),
            args: Vec::new(),
            env: axsafe_proc::minimal_env(),
            sandbox: clamav.sandbox.clone(),
            max_scan_bytes: 256 * 1024 * 1024,
            memory_bytes: clamav.max_memory_bytes,
            startup_timeout: Duration::from_secs(300),
            request_grace: Duration::from_secs(5),
            max_restarts: 3,
            idle_timeout: Duration::from_secs(600),
            update_check: Duration::from_secs(30),
            queue_wait: Duration::from_secs(120),
            max_filesize: u64::from(clamav.max_filesize_mb) * 1024 * 1024,
            max_scansize: u64::from(clamav.max_scansize_mb) * 1024 * 1024,
            max_recursion: clamav.max_recursion,
            max_files: 10_000,
            stale_after: Duration::from_secs(3 * 24 * 3600),
        }
    }
}

/// Standardort von libclamav.
pub fn default_library(clamscan: &Path) -> PathBuf {
    if cfg!(windows) {
        clamscan
            .parent()
            .map(|d| d.join("libclamav.dll"))
            .unwrap_or_else(|| PathBuf::from("libclamav.dll"))
    } else {
        for c in [
            "/usr/lib/x86_64-linux-gnu/libclamav.so.12",
            "/usr/lib/x86_64-linux-gnu/libclamav.so.11",
            "/usr/lib64/libclamav.so.12",
            "/usr/lib/libclamav.so.12",
            "/usr/local/lib/libclamav.so.12",
        ] {
            if Path::new(c).exists() {
                return PathBuf::from(c);
            }
        }
        PathBuf::from("libclamav.so.12")
    }
}

/// Kennzahlen für Messungen (nichts davon geht in Entscheidungen ein).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct WorkerStats {
    pub launches: u32,
    pub restarts: u32,
    pub last_load_ms: Option<u64>,
    pub signatures: Option<u64>,
    /// Höchster Speicherbedarf des aktuellen/letzten Workers (Windows: Job
    /// Object; Linux: VmHWM).
    pub peak_memory_bytes: Option<u64>,
}

struct Active {
    session: Session,
    /// Laufende Nummer des Worker-Starts (1 = erster Start).
    launch_no: u32,
    content: DbContent,
    stats: DbStats,
    ready: Ready,
}

struct Inner {
    active: Option<Active>,
    restarts: u32,
    disabled: Option<String>,
    last_update_check: Instant,
    update_error: Option<String>,
    stats: WorkerStats,
}

struct Shared {
    inner: Mutex<Inner>,
    info: Mutex<EngineInfo>,
    last_use: Mutex<Instant>,
    stop: AtomicBool,
}

/// ClamAV über den dauerhaft geladenen Worker.
pub struct ClamAvWorkerEngine {
    ws: WorkerSettings,
    clamscan: PathBuf,
    db: PathBuf,
    workdir: Option<PathBuf>,
    shared: Arc<Shared>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

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

fn detail(e: &SessionError, s: &Session) -> String {
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

#[cfg(target_os = "linux")]
fn linux_peak(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = s.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

fn peak(s: &Session) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        linux_peak(s.pid())
    }
    #[cfg(not(target_os = "linux"))]
    {
        s.peak_memory()
    }
}

/// Probedateien, Lauscher und Erwartung für den Isolationsnachweis.
struct ProbeSetup {
    dir: PathBuf,
    files: Vec<PathBuf>,
    listener: std::net::TcpListener,
}

impl ProbeSetup {
    fn new() -> std::io::Result<Self> {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "axsafe-clamav-probe-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir(&dir)?;
        let mut files = Vec::new();
        #[cfg(windows)]
        {
            // Datei eines „fremden“ Benutzers (nur SYSTEM/Administratoren) –
            // so sehen Dateien anderer Benutzer für ein Dienstkonto aus.
            let f = dir.join("fremd.txt");
            axsafe_proc::create_probe_file(
                &f,
                b"AXSafe Probe",
                axsafe_proc::ProbeOwner::SystemAndAdmins,
            )?;
            files.push(f);
            // Im Benutzerkontext: Datei, die NUR dieser Benutzer lesen darf.
            // Im Dienstkontext ist das Dienstkonto Teil des Tokens
            // (Fensterstation) – dort ist diese Prüfung nicht aussagekräftig.
            if !axsafe_proc::running_as_service_account() {
                let f = dir.join("nur-benutzer.txt");
                axsafe_proc::create_probe_file(
                    &f,
                    b"AXSafe Probe",
                    axsafe_proc::ProbeOwner::CurrentUser,
                )?;
                files.push(f);
            }
        }
        #[cfg(not(windows))]
        {
            let f = dir.join("probe.txt");
            std::fs::write(&f, b"AXSafe Probe")?;
            files.push(f);
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        Ok(ProbeSetup {
            dir,
            files,
            listener,
        })
    }

    fn probe(&self, worker_exe: &Path) -> std::io::Result<Probe> {
        let paths: Vec<String> = self.files.iter().map(|f| f.display().to_string()).collect();
        Ok(Probe {
            read_paths: paths.clone(),
            write_paths: paths,
            create_in: vec![self.dir.display().to_string()],
            connect: vec![self.listener.local_addr()?.to_string()],
            spawn: vec![worker_exe.display().to_string()],
        })
    }
}

impl Drop for ProbeSetup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Ob ein Probeergebnis die Erwartung erfüllt. Unter Windows sperrt das
/// eingeschränkte Token Loopback-TCP nicht (die Firewall erfasst Loopback
/// nicht) – das wird ausgewiesen, aber nicht als Abschottung gezählt.
fn probe_ok(c: &ProbeCheck) -> bool {
    if cfg!(windows) && c.action == "TCP-Verbindung" {
        return true;
    }
    c.denied
}

impl ClamAvWorkerEngine {
    /// Startet den Worker sofort (Kaltstart) und weist die Abschottung nach.
    pub fn start(ws: WorkerSettings, clamscan: PathBuf) -> Self {
        let db = ws
            .database
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/clamav"));
        let info = EngineInfo {
            content_time_utc: None,
            name: "clamav".into(),
            engine_version: "unbekannt".into(),
            content_version: "unbekannt".into(),
            health: EngineHealth::Unavailable {
                reason: "nicht gestartet".into(),
            },
            license: "GPL-2.0-only (libclamav, separat installiert, nicht mitgeliefert; \
                      geladen im eigenen Worker-Prozess)"
                .into(),
            content_kind: ContentKind::Unknown,
            content_note: String::new(),
            inspects_contents_of: crate::content_formats(
                &ws.library
                    .clone()
                    .unwrap_or_else(|| default_library(&clamscan)),
            ),
            isolation: Isolation {
                kind: IsolationKind::SandboxedWorker,
                enforced: false,
                detail: "noch nicht geprüft".into(),
            },
        };
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner {
                active: None,
                restarts: 0,
                disabled: None,
                last_update_check: Instant::now(),
                update_error: None,
                stats: WorkerStats::default(),
            }),
            info: Mutex::new(info),
            last_use: Mutex::new(Instant::now()),
            stop: AtomicBool::new(false),
        });
        let mut e = ClamAvWorkerEngine {
            ws,
            clamscan,
            db,
            workdir: None,
            shared,
        };
        match e.prepare_workdir() {
            Ok(w) => e.workdir = Some(w),
            Err(err) => {
                e.set_unavailable(format!(
                    "Arbeitsordner für den ClamAV-Worker nicht vorbereitbar: {err} – ClamAV wird \
                     nicht ohne Abschottung genutzt"
                ));
                return e;
            }
        }
        {
            let mut inner = lock(&e.shared.inner);
            match e.launch() {
                Ok(a) => e.activate(&mut inner, a, None),
                Err((reason, iso)) => {
                    if let Some(i) = iso {
                        lock(&e.shared.info).isolation = i;
                    }
                    e.set_unavailable(reason);
                }
            }
        }
        e.spawn_idle_monitor();
        e
    }

    #[cfg(windows)]
    fn prepare_workdir(&self) -> std::io::Result<PathBuf> {
        let dir = crate::new_restricted_work_dir()?;
        // Eigene (Test-)Datenbank lesbar machen, wenn sie uns gehört; der
        // Standardordner ist für Benutzer bereits lesbar.
        let d = if self.db.is_dir() {
            self.db.clone()
        } else {
            self.db.parent().map(PathBuf::from).unwrap_or_default()
        };
        let _ = axsafe_proc::restricted_grant_read(&d);
        // Liegt der Worker im Benutzerprofil (entpacktes Paket), darf das
        // eingeschränkte Token ihn sonst nicht starten: nur diese eine Datei
        // freigeben. Unter Program Files genügt das Leserecht der Benutzer;
        // scheitert die Freigabe dort (fremde Datei), zeigt der Start den Fehler.
        if matches!(self.ws.sandbox, Sandbox::Restricted) {
            let _ = axsafe_proc::restricted_grant_execute(&self.ws.worker_exe);
        }
        Ok(dir)
    }

    #[cfg(not(windows))]
    fn prepare_workdir(&self) -> std::io::Result<PathBuf> {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "axsafe-clamav-arbeit-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn library(&self) -> PathBuf {
        self.ws
            .library
            .clone()
            .unwrap_or_else(|| default_library(&self.clamscan))
    }

    /// Windows: Zertifikatsordner der ClamAV-Installation (wie clamscan).
    fn certsdir(&self) -> Option<PathBuf> {
        if !cfg!(windows) {
            return None;
        }
        self.library()
            .parent()
            .map(|d| d.join("certs"))
            .filter(|d| d.is_dir())
    }

    fn set_unavailable(&self, reason: String) {
        lock(&self.shared.info).health = EngineHealth::Unavailable { reason };
    }

    /// Startet einen neuen Worker und prüft ihn vollständig.
    fn launch(&self) -> Result<Active, (String, Option<Isolation>)> {
        let content = database_content(&self.db).map_err(|e| (e, None))?;
        let workdir = self
            .workdir
            .clone()
            .ok_or_else(|| ("kein Arbeitsordner".to_string(), None))?;
        let mut cmd = Command::new(&self.ws.worker_exe);
        cmd.args(&self.ws.args);
        cmd.env_clear();
        cmd.envs(self.ws.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let limits = Limits {
            timeout: self.ws.startup_timeout,
            max_output_bytes: MAX_RESPONSE_BYTES,
            max_memory_bytes: Some(self.ws.memory_bytes),
            max_processes: Some(1),
        };
        let mut s = Session::spawn(cmd, &limits, &self.ws.sandbox).map_err(|e| {
            (
                format!(
                    "ClamAV-Worker {} nicht startbar: {e}",
                    self.ws.worker_exe.display()
                ),
                None,
            )
        })?;
        let deadline = Instant::now() + self.ws.startup_timeout;
        let init = Init {
            protocol: PROTOCOL.into(),
            library: self.library().display().to_string(),
            database: self.db.display().to_string(),
            tempdir: workdir.display().to_string(),
            max_scan_bytes: self.ws.max_scan_bytes,
            max_filesize: self.ws.max_filesize,
            max_scansize: self.ws.max_scansize,
            max_recursion: self.ws.max_recursion,
            max_files: self.ws.max_files,
            max_scantime_ms: 120_000,
            certsdir: self.certsdir().map(|p| p.display().to_string()),
        };
        let frame = serde_json::to_vec(&init)
            .map_err(|e| e.to_string())
            .and_then(|j| encode_frame(T_INIT, &j).map_err(|e| e.to_string()))
            .map_err(|e| (e, None))?;
        if let Err(e) = s.write_all(frame, deadline) {
            let d = detail(&e, &s);
            s.kill();
            return Err((format!("ClamAV-Worker nahm den Start nicht an: {d}"), None));
        }
        let ready: Ready = match read_response(&mut s, deadline) {
            Ok((T_READY, p)) => match serde_json::from_slice::<Ready>(&p) {
                Ok(r) if r.protocol == PROTOCOL => r,
                Ok(r) => {
                    s.kill();
                    return Err((
                        format!("Worker spricht {} statt {PROTOCOL}", r.protocol),
                        None,
                    ));
                }
                Err(e) => {
                    s.kill();
                    return Err((format!("Ready ungültig: {e}"), None));
                }
            },
            Ok((T_ERROR, p)) => {
                s.kill();
                let m = serde_json::from_slice::<ErrorMsg>(&p)
                    .map(|m| m.message)
                    .unwrap_or_else(|_| "unlesbare Fehlermeldung".into());
                return Err((format!("ClamAV-Worker verweigert: {m}"), None));
            }
            Ok((k, _)) => {
                s.kill();
                return Err((format!("unerwartete Antwort {k:#x} statt Ready"), None));
            }
            Err(e) => {
                let d = detail(&e, &s);
                s.kill();
                return Err((format!("ClamAV-Worker antwortete nicht: {d}"), None));
            }
        };
        let stats = match &ready.database {
            Ok(st) => st.clone(),
            Err(e) => {
                s.kill();
                return Err((format!("Signaturdatenbank nicht geladen: {e}"), None));
            }
        };
        // Geladener Stand muss zu den Dateiköpfen passen (offizielle DB).
        if let Some(daily) = content.daily {
            if stats.db_version != daily {
                s.kill();
                return Err((
                    format!(
                        "Geladener Stand (daily {}) passt nicht zu den Dateien (daily {daily}) – \
                         Worker verworfen",
                        stats.db_version
                    ),
                    None,
                ));
            }
        }
        // Nur die ausdrücklich festgelegten Umgebungsvariablen.
        let allowed: Vec<String> = self
            .ws
            .env
            .iter()
            .map(|(k, _)| k.to_ascii_uppercase())
            .collect();
        let extra: Vec<&String> = ready
            .env_names
            .iter()
            .filter(|n| !allowed.contains(&n.to_ascii_uppercase()))
            .collect();
        // Isolationsprobe.
        let setup = ProbeSetup::new()
            .map_err(|e| (format!("Isolationsprobe nicht vorbereitbar: {e}"), None))?;
        let probe = setup
            .probe(&self.ws.worker_exe)
            .map_err(|e| (format!("Isolationsprobe nicht vorbereitbar: {e}"), None))?;
        let pd = Instant::now() + Duration::from_secs(20);
        let checks: Vec<ProbeCheck> = match serde_json::to_vec(&probe)
            .map_err(|e| e.to_string())
            .and_then(|j| encode_frame(T_PROBE, &j).map_err(|e| e.to_string()))
        {
            Ok(f) => {
                let r = s.write_all(f, pd).and_then(|_| read_response(&mut s, pd));
                match r {
                    Ok((T_PROBE_RESULT, p)) => serde_json::from_slice(&p).unwrap_or_default(),
                    _ => Vec::new(),
                }
            }
            Err(_) => Vec::new(),
        };
        let expected = probe.read_paths.len()
            + probe.write_paths.len()
            + probe.create_in.len()
            + probe.connect.len()
            + probe.spawn.len();
        let all_ok = checks.len() == expected && checks.iter().all(probe_ok);
        let open: Vec<String> = checks
            .iter()
            .filter(|c| !c.denied)
            .map(|c| format!("{} {}", c.action, c.target))
            .collect();
        let enforced = all_ok && ready.sandbox.filesystem && extra.is_empty();
        let mut d = format!(
            "{}; Probe: {} von {} Aktionen verweigert",
            ready.sandbox.detail,
            checks.iter().filter(|c| c.denied).count(),
            checks.len()
        );
        if !open.is_empty() {
            d.push_str(&format!("; erlaubt: {}", open.join(", ")));
            if cfg!(windows) {
                d.push_str(" (Loopback-TCP sperrt das Token nicht; ausgehende Verbindungen sperrt die Firewall-Regel)");
            }
        }
        #[cfg(windows)]
        if matches!(self.ws.sandbox, Sandbox::Restricted) {
            d.push_str("; ");
            d.push_str(axsafe_proc::mitigation_summary(false));
        }
        if !extra.is_empty() {
            d.push_str(&format!(
                "; unerwartete Umgebungsvariablen: {}",
                extra
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let iso = Isolation {
            kind: if enforced {
                IsolationKind::SandboxedWorker
            } else {
                IsolationKind::ChildProcess
            },
            enforced,
            detail: d,
        };
        if !enforced {
            s.kill();
            return Err((
                format!(
                    "Isolation des ClamAV-Workers nicht nachgewiesen – keine Daten ({})",
                    iso.detail
                ),
                Some(iso),
            ));
        }
        lock(&self.shared.info).isolation = iso;
        Ok(Active {
            session: s,
            launch_no: 0,
            content,
            stats,
            ready,
        })
    }

    /// Setzt einen geprüften Worker als aktiv (ersetzt ggf. den alten).
    fn activate(&self, inner: &mut Inner, mut a: Active, previous: Option<&str>) {
        if let Some(old) = inner.active.take() {
            old.session.shutdown(Duration::from_millis(500));
        }
        inner.stats.launches += 1;
        a.launch_no = inner.stats.launches;
        inner.stats.last_load_ms = Some(a.stats.load_ms);
        inner.stats.signatures = Some(a.stats.signatures);
        inner.update_error = None;
        let mut info = lock(&self.shared.info);
        info.engine_version = format!("ClamAV {}", a.ready.engine_version);
        info.content_version = a.content.version.clone();
        info.content_kind = a.content.kind;
        info.content_note = self.note(&a, None, previous);
        // Erstellungszeit laut geladener Engine (cl_engine DB_TIME); bei
        // eigener Testdatenbank ohne Zeit leer.
        info.content_time_utc = a
            .content
            .daily
            .and(chrono::DateTime::from_timestamp(a.stats.db_time, 0))
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        info.health = EngineHealth::Ready;
        inner.active = Some(a);
    }

    fn note(&self, a: &Active, update_error: Option<&str>, previous: Option<&str>) -> String {
        let mut n = format!(
            "{}; dauerhaft geladen im ClamAV-Worker ({} Signaturen, Laden {} ms, Worker-Start Nr. {})",
            a.content.note, a.stats.signatures, a.stats.load_ms, a.launch_no
        );
        if let Some(p) = previous {
            n.push_str(&format!("; aktualisiert von {p}"));
        }
        if a.content.daily.is_some() && a.stats.db_time > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let age = now.saturating_sub(a.stats.db_time).max(0) as u64;
            if age > self.ws.stale_after.as_secs() {
                n = format!(
                    "VERALTET: Signaturen {} Tage alt – Update prüfen. {n}",
                    age / 86_400
                );
            }
        }
        if let Some(e) = update_error {
            n = format!("SIGNATURUPDATE NICHT GELADEN: {e}; aktiv bleibt der bisherige Stand. {n}");
        }
        n
    }

    /// Neuer Datenbankstand? Dann neuen Worker prüfen und erst danach umschalten.
    fn maybe_update(&self, inner: &mut Inner) {
        if inner.last_update_check.elapsed() < self.ws.update_check {
            return;
        }
        inner.last_update_check = Instant::now();
        let Some(active) = &inner.active else {
            return;
        };
        let now = match database_content(&self.db) {
            Ok(c) => c,
            Err(e) => {
                inner.update_error = Some(format!("Datenbankstand nicht lesbar: {e}"));
                self.refresh_note(inner);
                return;
            }
        };
        if now.version == active.content.version {
            return;
        }
        let previous = active.content.version.clone();
        match self.launch() {
            Ok(a) if a.content.version == now.version => self.activate(inner, a, Some(&previous)),
            Ok(mut a) => {
                a.session.kill();
                inner.update_error = Some(format!(
                    "Datenbank änderte sich während des Ladens ({} → {})",
                    now.version, a.content.version
                ));
                self.refresh_note(inner);
            }
            Err((e, _)) => {
                inner.update_error = Some(format!("Stand {}: {e}", now.version));
                self.refresh_note(inner);
            }
        }
    }

    fn refresh_note(&self, inner: &Inner) {
        if let Some(a) = &inner.active {
            let n = self.note(a, inner.update_error.as_deref(), None);
            lock(&self.shared.info).content_note = n;
        }
    }

    fn failed(&self, inner: &mut Inner) {
        if let Some(mut a) = inner.active.take() {
            inner.stats.peak_memory_bytes = peak(&a.session).or(inner.stats.peak_memory_bytes);
            a.session.kill();
        }
        inner.restarts += 1;
        inner.stats.restarts = inner.restarts;
        if inner.restarts > self.ws.max_restarts && inner.disabled.is_none() {
            let why = format!(
                "ClamAV-Worker {} Mal ausgefallen; ClamAV bleibt abgeschaltet, bis AXSafe neu startet",
                inner.restarts
            );
            self.set_unavailable(why.clone());
            inner.disabled = Some(why);
        }
    }

    fn outcome(&self, start: Instant) -> EngineOutcome {
        let info = lock(&self.shared.info);
        EngineOutcome {
            engine: "clamav".into(),
            engine_version: info.engine_version.clone(),
            content_version: info.content_version.clone(),
            verdict: Verdict::NoDetection,
            detections: Vec::new(),
            gaps: Vec::new(),
            note: None,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn gap(&self, start: Instant, v: Verdict, r: GapReason, d: String) -> EngineOutcome {
        let mut o = self.outcome(start);
        o.verdict = v;
        o.note = Some(d.clone());
        o.gaps.push(Gap::new(v, r, "clamav", d));
        o
    }

    /// Wartet begrenzt auf die Engine (Warteschlange).
    fn acquire(&self) -> Option<MutexGuard<'_, Inner>> {
        let until = Instant::now() + self.ws.queue_wait;
        loop {
            match self.shared.inner.try_lock() {
                Ok(g) => return Some(g),
                Err(std::sync::TryLockError::Poisoned(p)) => return Some(p.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if Instant::now() >= until {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    /// Kennzahlen für Messungen.
    pub fn stats(&self) -> WorkerStats {
        let inner = lock(&self.shared.inner);
        let mut s = inner.stats.clone();
        if let Some(a) = &inner.active {
            s.peak_memory_bytes = peak(&a.session).or(s.peak_memory_bytes);
        }
        s
    }

    /// Beendet den Worker (wie nach Leerlauf); nur für Tests und Messungen.
    pub fn stop_worker(&self) {
        let mut inner = lock(&self.shared.inner);
        if let Some(a) = inner.active.take() {
            inner.stats.peak_memory_bytes = peak(&a.session).or(inner.stats.peak_memory_bytes);
            a.session.shutdown(Duration::from_millis(500));
        }
    }

    /// Ob gerade ein Worker läuft.
    pub fn worker_running(&self) -> bool {
        lock(&self.shared.inner).active.is_some()
    }

    fn spawn_idle_monitor(&self) {
        let shared = Arc::downgrade(&self.shared);
        let idle = self.ws.idle_timeout;
        let _ = std::thread::Builder::new()
            .name("axsafe-clamav-leerlauf".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_secs(1).min(idle));
                let Some(sh) = shared.upgrade() else { return };
                if sh.stop.load(Ordering::SeqCst) {
                    return;
                }
                let since = lock(&sh.last_use).elapsed();
                if since < idle {
                    continue;
                }
                if let Ok(mut inner) = sh.inner.try_lock() {
                    if let Some(a) = inner.active.take() {
                        inner.stats.peak_memory_bytes =
                            peak(&a.session).or(inner.stats.peak_memory_bytes);
                        a.session.shutdown(Duration::from_millis(500));
                    }
                };
            });
    }
}

impl Engine for ClamAvWorkerEngine {
    fn name(&self) -> &str {
        "clamav"
    }

    fn info(&self) -> EngineInfo {
        lock(&self.shared.info).clone()
    }

    fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
        let start = Instant::now();
        *lock(&self.shared.last_use) = Instant::now();
        if input.data.len() as u64 > self.ws.max_scan_bytes {
            return self.gap(
                start,
                Verdict::Unsupported,
                GapReason::SizeLimit,
                format!(
                    "Objekt größer als die Grenze des ClamAV-Workers ({} Bytes)",
                    self.ws.max_scan_bytes
                ),
            );
        }
        let Some(mut inner) = self.acquire() else {
            return self.gap(
                start,
                Verdict::Timeout,
                GapReason::EngineTimeout,
                format!(
                    "ClamAV-Engine ausgelastet: Warteschlange länger als {} s",
                    self.ws.queue_wait.as_secs()
                ),
            );
        };
        *lock(&self.shared.last_use) = Instant::now();
        if let Some(r) = &inner.disabled {
            return self.gap(
                start,
                Verdict::Error,
                GapReason::EngineUnavailable,
                r.clone(),
            );
        }
        if inner.active.is_none() {
            // Kaltstart (erster Start, nach Leerlauf oder nach Ausfall).
            match self.launch() {
                Ok(a) => self.activate(&mut inner, a, None),
                Err((e, iso)) => {
                    if let Some(i) = iso {
                        lock(&self.shared.info).isolation = i;
                    }
                    self.failed(&mut inner);
                    return self.gap(
                        start,
                        Verdict::Error,
                        GapReason::EngineUnavailable,
                        format!("ClamAV-Worker nicht einsatzbereit, keine Daten übergeben: {e}"),
                    );
                }
            }
        } else {
            self.maybe_update(&mut inner);
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
        let deadline = Instant::now() + input.timeout + self.ws.request_grace;
        let a = inner.active.as_mut().expect("aktiver Worker");
        let res = a
            .session
            .write_all(frame, deadline)
            .and_then(|_| read_response(&mut a.session, deadline));
        let mut out = self.outcome(start);
        out.content_version = a.content.version.clone();
        match res {
            Ok((T_RESULT, p)) => match serde_json::from_slice::<ScanReply>(&p) {
                Ok(r) => {
                    out.duration_ms = start.elapsed().as_millis() as u64;
                    match r.result {
                        ScanResult::Clean => out,
                        ScanResult::Virus { name } => {
                            let (verdict, severity, confidence) = classify(&name);
                            if verdict.is_detection() {
                                out.detections.push(Detection {
                                    rule_version: None,
                                    evidence: vec![format!("ClamAV-Signatur {name}")],
                                    test_signature: is_test_signature(&name),
                                    rule_id: Some(name.clone()),
                                    name,
                                    verdict,
                                    severity,
                                    confidence,
                                });
                            } else {
                                let reason = if verdict == Verdict::Encrypted {
                                    GapReason::Encrypted
                                } else {
                                    GapReason::EngineLimitExceeded
                                };
                                out.gaps.push(Gap::new(
                                    verdict,
                                    reason,
                                    "clamav",
                                    format!("ClamAV meldet {name}"),
                                ));
                            }
                            out.verdict = aggregate(vec![verdict]);
                            out
                        }
                        ScanResult::Error { code, message } if code == CL_ETIMEOUT => self.gap(
                            start,
                            Verdict::Timeout,
                            GapReason::EngineTimeout,
                            format!("libclamav: Zeitgrenze erreicht ({message})"),
                        ),
                        ScanResult::Error { code, message } => self.gap(
                            start,
                            Verdict::Error,
                            GapReason::EngineError,
                            format!("libclamav-Fehler {code}: {message}"),
                        ),
                    }
                }
                Err(e) => {
                    self.failed(&mut inner);
                    self.gap(
                        start,
                        Verdict::Error,
                        GapReason::EngineError,
                        format!("Antwort ungültig: {e}"),
                    )
                }
            },
            Ok((T_ERROR, p)) => {
                let m = serde_json::from_slice::<ErrorMsg>(&p)
                    .map(|m| m.message)
                    .unwrap_or_else(|_| "unlesbare Fehlermeldung".into());
                self.failed(&mut inner);
                self.gap(
                    start,
                    Verdict::Error,
                    GapReason::EngineError,
                    format!("ClamAV-Worker meldet Fehler: {m}"),
                )
            }
            Ok((k, _)) => {
                self.failed(&mut inner);
                self.gap(
                    start,
                    Verdict::Error,
                    GapReason::EngineError,
                    format!("Protokollverletzung: Antworttyp {k:#x}"),
                )
            }
            Err(SessionError::Timeout) => {
                self.failed(&mut inner);
                self.gap(
                    start,
                    Verdict::Timeout,
                    GapReason::EngineTimeout,
                    "ClamAV-Worker überschritt das Zeitbudget und wurde beendet".into(),
                )
            }
            Err(e) => {
                let d = detail(&e, &a.session);
                self.failed(&mut inner);
                self.gap(
                    start,
                    Verdict::Error,
                    GapReason::EngineError,
                    format!("ClamAV-Worker ausgefallen: {d}"),
                )
            }
        }
    }
}

impl Drop for ClamAvWorkerEngine {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        let mut inner = lock(&self.shared.inner);
        if let Some(a) = inner.active.take() {
            a.session.shutdown(Duration::from_millis(500));
        }
        drop(inner);
        if let Some(w) = &self.workdir {
            let _ = std::fs::remove_dir_all(w);
        }
    }
}
