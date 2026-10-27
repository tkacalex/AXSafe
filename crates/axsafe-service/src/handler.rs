//! Bearbeitung einer Client-Verbindung (unabhängig vom Transport).
//!
//! Grenzen je Verbindung: Leerlauf bis zur nächsten Nachricht, Zeit für eine
//! begonnene Nachricht (gegen langsames Senden), Schreibzeit, Anfragerate je
//! Identität, streng steigende Folgenummern, Nonce-Wiederholschutz für
//! verändernde Anfragen. Bei Protokollverletzungen wird die Verbindung
//! beendet.

use crate::identity::Identity;
use crate::ipc::*;
use crate::jobs::{JobManager, JobSpec, SubmitError};
use axsafe_core::scan::FileAccess;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ConnLimits {
    /// Höchstwartezeit auf die nächste Nachricht.
    pub idle: Duration,
    /// Höchstzeit für das Übertragen einer begonnenen Nachricht.
    pub message: Duration,
    /// Höchstzeit für das Schreiben einer Antwort.
    pub write: Duration,
    /// Anfragen je Sekunde und Identität (Mittel) und kurzzeitige Spitze.
    pub rate_per_sec: f64,
    pub burst: f64,
}

impl Default for ConnLimits {
    fn default() -> Self {
        ConnLimits {
            idle: Duration::from_secs(120),
            message: Duration::from_secs(5),
            write: Duration::from_secs(10),
            rate_per_sec: 20.0,
            burst: 40.0,
        }
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Benutzer-SID und Anmeldesitzung.
type OwnerKey = (String, u64);
/// Gesehene Nonces (Menge + Reihenfolge zum Begrenzen).
type NonceMemory = (HashSet<String>, VecDeque<String>);

/// Gemeinsamer Zustand aller Verbindungen.
pub struct ServiceCtx {
    pub jobs: Arc<JobManager>,
    /// Liefert Dienst- und Enginezustand für `status`.
    pub status: Arc<dyn Fn() -> serde_json::Value + Send + Sync>,
    pub limits: ConnLimits,
    pub shutting_down: AtomicBool,
    nonces: Mutex<HashMap<OwnerKey, NonceMemory>>,
    buckets: Mutex<HashMap<OwnerKey, Bucket>>,
}

const NONCE_MEMORY: usize = 4096;

impl ServiceCtx {
    pub fn new(
        jobs: Arc<JobManager>,
        status: Arc<dyn Fn() -> serde_json::Value + Send + Sync>,
        limits: ConnLimits,
    ) -> Self {
        ServiceCtx {
            jobs,
            status,
            limits,
            shutting_down: AtomicBool::new(false),
            nonces: Mutex::new(HashMap::new()),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn key(id: &Identity) -> (String, u64) {
        (id.user_sid.clone(), id.logon_id)
    }

    /// `false`, wenn die Nonce für diese Identität schon verwendet wurde.
    fn fresh_nonce(&self, id: &Identity, nonce: &str) -> bool {
        let mut g = self.nonces.lock().unwrap_or_else(|p| p.into_inner());
        let (set, order) = g.entry(Self::key(id)).or_default();
        if !set.insert(nonce.to_ascii_lowercase()) {
            return false;
        }
        order.push_back(nonce.to_ascii_lowercase());
        while order.len() > NONCE_MEMORY {
            if let Some(old) = order.pop_front() {
                set.remove(&old);
            }
        }
        true
    }

    fn allow_rate(&self, id: &Identity) -> bool {
        let mut g = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let b = g.entry(Self::key(id)).or_insert(Bucket {
            tokens: self.limits.burst,
            last: now,
        });
        let dt = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + dt * self.limits.rate_per_sec).min(self.limits.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Authentisierte Verbindung: Identität und Dateizugriff mit deren Rechten.
pub struct ConnAuth {
    pub identity: Identity,
    pub access: Arc<dyn FileAccess>,
    /// Prozess des Clients (PID + Startzeit) – nur Nachweis, nie Grundlage
    /// für Rechteentscheidungen.
    pub client_process: Option<axsafe_core::report::ProcessIdentity>,
}

/// Warum eine Verbindung endete (Protokoll/Tests).
#[derive(Debug, PartialEq, Eq)]
pub enum ConnEnd {
    ClientClosed,
    Idle,
    SlowOrBroken(String),
    Oversized,
    Malformed,
    Replay,
    Forbidden(String),
    ShuttingDown,
}

fn send(conn: &mut dyn Conn, ctx: &ServiceCtx, r: &Response) -> io::Result<()> {
    let mut data = serde_json::to_vec(r).map_err(io::Error::other)?;
    if data.len() > MAX_RESPONSE_BYTES {
        data = serde_json::to_vec(&Response::err(
            r.seq,
            ErrorCode::Internal,
            "Antwort überschreitet die Höchstgröße",
        ))
        .map_err(io::Error::other)?;
    }
    write_frame(conn, &data, Instant::now() + ctx.limits.write)
}

/// Bedient eine Verbindung bis zum Ende.
pub fn serve(conn: &mut dyn Conn, auth: &ConnAuth, ctx: &ServiceCtx) -> ConnEnd {
    if let Err(e) = auth.identity.check_allowed() {
        let _ = send(conn, ctx, &Response::err(0, ErrorCode::Forbidden, &e));
        return ConnEnd::Forbidden(e);
    }
    let mut last_seq = 0u64;
    loop {
        if ctx.shutting_down.load(Ordering::SeqCst) {
            let _ = send(
                conn,
                ctx,
                &Response::err(0, ErrorCode::ShuttingDown, "Dienst wird beendet"),
            );
            return ConnEnd::ShuttingDown;
        }
        let frame = match read_frame(
            conn,
            MAX_REQUEST_BYTES,
            Some(Instant::now() + ctx.limits.idle),
            ctx.limits.message,
        ) {
            Ok(Some(f)) => f,
            Ok(None) => return ConnEnd::ClientClosed,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                let _ = send(
                    conn,
                    ctx,
                    &Response::err(0, ErrorCode::Invalid, e.to_string()),
                );
                return ConnEnd::Oversized;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return if last_seq == 0 {
                    ConnEnd::Idle
                } else {
                    ConnEnd::SlowOrBroken(e.to_string())
                };
            }
            Err(e) => return ConnEnd::SlowOrBroken(e.to_string()),
        };
        let req: Request = match serde_json::from_slice(&frame) {
            Ok(r) => r,
            Err(e) => {
                let _ = send(
                    conn,
                    ctx,
                    &Response::err(0, ErrorCode::Invalid, format!("Anfrage ungültig: {e}")),
                );
                return ConnEnd::Malformed;
            }
        };
        if let Err(e) = validate(&req) {
            if send(conn, ctx, &Response::err(req.seq, ErrorCode::Invalid, e)).is_err() {
                return ConnEnd::SlowOrBroken("Antwort nicht schreibbar".into());
            }
            continue;
        }
        if req.seq <= last_seq {
            let _ = send(
                conn,
                ctx,
                &Response::err(req.seq, ErrorCode::Replay, "Folgenummer nicht steigend"),
            );
            return ConnEnd::Replay;
        }
        last_seq = req.seq;
        if !ctx.allow_rate(&auth.identity) {
            if send(
                conn,
                ctx,
                &Response::err(req.seq, ErrorCode::Overloaded, "zu viele Anfragen"),
            )
            .is_err()
            {
                return ConnEnd::SlowOrBroken("Antwort nicht schreibbar".into());
            }
            continue;
        }
        if req.body.is_mutating() && !ctx.fresh_nonce(&auth.identity, &req.nonce) {
            let _ = send(
                conn,
                ctx,
                &Response::err(
                    req.seq,
                    ErrorCode::Replay,
                    "Anfrage wiederholt (Nonce bekannt)",
                ),
            );
            return ConnEnd::Replay;
        }
        let resp = dispatch(&req, auth, ctx);
        if send(conn, ctx, &resp).is_err() {
            return ConnEnd::SlowOrBroken("Antwort nicht schreibbar".into());
        }
    }
}

fn dispatch(req: &Request, auth: &ConnAuth, ctx: &ServiceCtx) -> Response {
    let me = &auth.identity;
    match &req.body {
        Body::Status => {
            let (running, queued) = ctx.jobs.counts();
            let mut v = serde_json::json!({
                "service": "bereit",
                "version": axsafe_core::AXSAFE_VERSION,
                "client": { "display": me.display, "session_id": me.session_id },
                "file_access": auth.access.describe(),
                "jobs_running": running,
                "jobs_queued": queued,
                "own_jobs": ctx.jobs.list(me),
            });
            v["engines"] = (ctx.status)();
            Response::ok(req.seq, v)
        }
        Body::ScanStart {
            paths,
            use_clamav,
            kind,
            trigger,
        } => {
            let spec = JobSpec {
                job_id: uuid::Uuid::new_v4().to_string(),
                paths: paths.iter().map(PathBuf::from).collect(),
                use_clamav: *use_clamav,
                owner: me.clone(),
                access: Arc::clone(&auth.access),
                client_process: auth.client_process.clone(),
                kind: kind.unwrap_or_default(),
                // Ohne Angabe: über den Dienst ausgelöst.
                trigger: trigger.unwrap_or(axsafe_core::scanjob::Trigger::Service),
                progress: Default::default(),
            };
            match ctx.jobs.submit(spec) {
                Ok(id) => Response::ok(req.seq, serde_json::json!({ "job_id": id })),
                Err(SubmitError::Overloaded(m)) => Response::err(req.seq, ErrorCode::Overloaded, m),
                Err(SubmitError::ShuttingDown) => {
                    Response::err(req.seq, ErrorCode::ShuttingDown, "Dienst wird beendet")
                }
            }
        }
        Body::ScanCancel { job_id } => {
            if ctx.jobs.cancel(me, job_id) {
                Response::ok(req.seq, serde_json::json!({ "cancel_requested": true }))
            } else {
                Response::err(
                    req.seq,
                    ErrorCode::NotFound,
                    "kein abbrechbarer eigener Auftrag",
                )
            }
        }
        Body::Job { job_id } => match ctx.jobs.view(me, job_id) {
            Some(v) => Response::ok(req.seq, serde_json::to_value(v).unwrap_or_default()),
            None => Response::err(req.seq, ErrorCode::NotFound, "kein eigener Auftrag"),
        },
        Body::Report { job_id } => match ctx.jobs.report(me, job_id) {
            Some(bytes) if bytes.len() + 512 > MAX_RESPONSE_BYTES => Response::err(
                req.seq,
                ErrorCode::Internal,
                "Bericht größer als die Antwortgrenze",
            ),
            Some(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(v) => Response::ok(req.seq, serde_json::json!({ "report": v })),
                Err(e) => Response::err(
                    req.seq,
                    ErrorCode::Internal,
                    format!("Bericht unlesbar: {e}"),
                ),
            },
            None => Response::err(req.seq, ErrorCode::NotFound, "kein eigener Bericht"),
        },
    }
}
