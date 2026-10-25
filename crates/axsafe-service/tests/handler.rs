//! Integrationstests der Dienstschnittstelle über ein echtes Socket-Paar
//! (Unix). Die Identität wird hier vom Test vorgegeben; unter Windows
//! stammt sie aus dem Token (siehe Windows-Systemtest in der CI).
#![cfg(unix)]

use axsafe_core::report::ScanReport;
use axsafe_core::scan::{NoProgress, ProcessAccess, Scanner};
use axsafe_service::client::{nonce, Client};
use axsafe_service::handler::{serve, ConnAuth, ConnEnd, ConnLimits, ServiceCtx};
use axsafe_service::identity::Identity;
use axsafe_service::ipc::*;
use axsafe_service::jobs::{JobLimits, JobManager, JobRunner, JobSpec};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Echter Scan ohne Engines (schnell); hält bei Bedarf bis zum Abbruch an.
struct TestRunner {
    hold: bool,
}
impl JobRunner for TestRunner {
    fn run(&self, job: &JobSpec, cancel: &AtomicBool) -> Result<ScanReport, String> {
        let t = Instant::now();
        while self.hold && !cancel.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let s = Scanner::new(Vec::new(), Default::default()).with_file_access(job.access.clone());
        Ok(s.scan_job(job.job_id.clone(), &job.paths, cancel, &mut NoProgress))
    }
}

fn identity(sid: &str, logon: u64) -> Identity {
    Identity {
        user_sid: sid.into(),
        logon_id: logon,
        session_id: 1,
        display: sid.into(),
    }
}

fn ctx(hold: bool, limits: ConnLimits) -> (Arc<ServiceCtx>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let jobs = JobManager::start(
        JobLimits::default(),
        dir.path().join("reports"),
        Arc::new(TestRunner { hold }),
    );
    let status = Arc::new(|| serde_json::json!({"state": "geprüft", "list": []}));
    (Arc::new(ServiceCtx::new(jobs, status, limits)), dir)
}

/// Startet eine Serververbindung für `id`; liefert Client und Endegrund.
fn connect(
    ctx: &Arc<ServiceCtx>,
    id: Identity,
) -> (Client<UnixStream>, std::thread::JoinHandle<ConnEnd>) {
    let (a, mut b) = UnixStream::pair().unwrap();
    let ctx = Arc::clone(ctx);
    let h = std::thread::spawn(move || {
        let auth = ConnAuth {
            identity: id,
            access: Arc::new(ProcessAccess),
            client_process: None,
        };
        serve(&mut b, &auth, &ctx)
    });
    a.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    (Client::new(a), h)
}

fn wait_finished(c: &mut Client<UnixStream>, job: &str) -> serde_json::Value {
    let t = Instant::now();
    loop {
        let r = c.call(Body::Job { job_id: job.into() }).unwrap();
        assert!(r.ok, "{r:?}");
        if r.result["state"] == "finished" || r.result["state"] == "failed" {
            return r.result;
        }
        assert!(t.elapsed() < Duration::from_secs(10), "Auftrag endet nicht");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn owner_can_scan_and_read_report_other_user_cannot() {
    let (ctx, dir) = ctx(false, ConnLimits::default());
    let target = dir.path().join("daten");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("brief.txt"), b"harmlos").unwrap();

    let alex = identity("S-1-5-21-1-2-3-1001", 77);
    let (mut c, _) = connect(&ctx, alex.clone());
    let r = c
        .call(Body::ScanStart {
            paths: vec![target.display().to_string()],
            use_clamav: false,
        })
        .unwrap();
    assert!(r.ok, "{r:?}");
    let job = r.result["job_id"].as_str().unwrap().to_string();
    let fin = wait_finished(&mut c, &job);
    assert_eq!(fin["state"], "finished", "{fin}");
    let rep = c
        .call(Body::Report {
            job_id: job.clone(),
        })
        .unwrap();
    assert!(rep.ok);
    assert_eq!(rep.result["report"]["job_id"], job.as_str());

    for other in [
        identity("S-1-5-21-1-2-3-1002", 99),
        // gleicher Benutzer, andere Anmeldesitzung
        identity("S-1-5-21-1-2-3-1001", 78),
    ] {
        let (mut o, _) = connect(&ctx, other);
        for body in [
            Body::Report {
                job_id: job.clone(),
            },
            Body::Job {
                job_id: job.clone(),
            },
            Body::ScanCancel {
                job_id: job.clone(),
            },
        ] {
            let r = o.call(body).unwrap();
            assert!(!r.ok);
            assert_eq!(r.error.unwrap().code, ErrorCode::NotFound);
        }
        let st = o.call(Body::Status).unwrap();
        assert_eq!(st.result["own_jobs"].as_array().unwrap().len(), 0);
    }
}

#[test]
fn cancel_running_job_and_service_restart_keeps_report() {
    let (ctx, dir) = ctx(true, ConnLimits::default());
    let alex = identity("S-1-5-21-1-2-3-1001", 1);
    let (mut c, _) = connect(&ctx, alex.clone());
    let r = c
        .call(Body::ScanStart {
            paths: vec![dir.path().display().to_string()],
            use_clamav: false,
        })
        .unwrap();
    let job = r.result["job_id"].as_str().unwrap().to_string();
    std::thread::sleep(Duration::from_millis(100));
    let r = c
        .call(Body::ScanCancel {
            job_id: job.clone(),
        })
        .unwrap();
    assert!(r.ok, "{r:?}");
    let fin = wait_finished(&mut c, &job);
    // Abbruch vor dem ersten Objekt: unvollständig, nicht „nichts zu prüfen“.
    assert_eq!(fin["outcome"], "incomplete", "{fin}");
    // „Neustart“: neuer Auftragsverwalter auf demselben Datenordner.
    let jobs2 = JobManager::start(
        JobLimits::default(),
        dir.path().join("reports"),
        Arc::new(TestRunner { hold: false }),
    );
    let ctx2 = Arc::new(ServiceCtx::new(
        jobs2,
        Arc::new(|| serde_json::json!({})),
        ConnLimits::default(),
    ));
    let (mut c2, _) = connect(&ctx2, alex);
    let rep = c2
        .call(Body::Report {
            job_id: job.clone(),
        })
        .unwrap();
    assert!(rep.ok, "{rep:?}");
    assert_eq!(rep.result["report"]["cancelled"], true);
}

#[test]
fn replayed_and_non_increasing_requests_are_rejected() {
    let (ctx, dir) = ctx(false, ConnLimits::default());
    let alex = identity("S-1-5-21-1-2-3-1001", 1);
    let (mut c, h) = connect(&ctx, alex.clone());
    let body = Body::ScanStart {
        paths: vec![dir.path().display().to_string()],
        use_clamav: false,
    };
    let n = nonce();
    let req = |seq: u64| {
        serde_json::to_vec(&Request {
            protocol: IPC_PROTOCOL.into(),
            seq,
            nonce: n.clone(),
            body: body.clone(),
        })
        .unwrap()
    };
    c.send_raw(&req(1)).unwrap();
    assert!(c.read_response().unwrap().ok);
    // gleiche Nonce, neue Folgenummer → Wiederholung
    c.send_raw(&req(2)).unwrap();
    let r = c.read_response().unwrap();
    assert_eq!(r.error.unwrap().code, ErrorCode::Replay);
    assert_eq!(h.join().unwrap(), ConnEnd::Replay);

    // gleiche Nonce auf einer NEUEN Verbindung desselben Auftraggebers
    let (mut c2, _) = connect(&ctx, alex);
    c2.send_raw(&req(1)).unwrap();
    assert_eq!(
        c2.read_response().unwrap().error.unwrap().code,
        ErrorCode::Replay
    );

    // Folgenummer nicht steigend
    let (mut c3, h3) = connect(&ctx, identity("S-1-5-21-1-2-3-1009", 5));
    c3.set_seq(5);
    assert!(c3.call(Body::Status).unwrap().ok);
    c3.set_seq(3);
    let r = c3.call(Body::Status).unwrap();
    assert_eq!(r.error.unwrap().code, ErrorCode::Replay);
    assert_eq!(h3.join().unwrap(), ConnEnd::Replay);
}

#[test]
fn oversized_malformed_and_slow_messages_end_the_connection() {
    let limits = ConnLimits {
        idle: Duration::from_millis(300),
        message: Duration::from_millis(200),
        ..ConnLimits::default()
    };
    let (ctx, _dir) = ctx(false, limits);
    let id = identity("S-1-5-21-1-2-3-1001", 1);

    let (mut c, h) = connect(&ctx, id.clone());
    c.conn_mut()
        .write_all(&((MAX_REQUEST_BYTES as u32) + 1).to_le_bytes())
        .unwrap();
    assert_eq!(
        c.read_response().unwrap().error.unwrap().code,
        ErrorCode::Invalid
    );
    assert_eq!(h.join().unwrap(), ConnEnd::Oversized);

    let (mut c, h) = connect(&ctx, id.clone());
    c.send_raw(br#"{"protocol":"axsafe.ipc/1","seq":1,"nonce":"x","body":{"type":"shell"}}"#)
        .unwrap();
    assert_eq!(
        c.read_response().unwrap().error.unwrap().code,
        ErrorCode::Invalid
    );
    assert_eq!(h.join().unwrap(), ConnEnd::Malformed);

    // langsam: Kopf, dann nichts mehr
    let (mut c, h) = connect(&ctx, id.clone());
    assert!(c.call(Body::Status).unwrap().ok);
    c.conn_mut().write_all(&100u32.to_le_bytes()).unwrap();
    c.conn_mut().write_all(b"{").unwrap();
    let t = Instant::now();
    assert!(matches!(h.join().unwrap(), ConnEnd::SlowOrBroken(_)));
    assert!(t.elapsed() < Duration::from_secs(2));

    // Leerlauf
    let (_c, h) = connect(&ctx, id);
    assert_eq!(h.join().unwrap(), ConnEnd::Idle);
}

#[test]
fn rate_and_job_limits_bound_overload() {
    let limits = ConnLimits {
        rate_per_sec: 5.0,
        burst: 5.0,
        ..ConnLimits::default()
    };
    let (ctx, dir) = ctx(true, limits);
    let id = identity("S-1-5-21-1-2-3-1001", 1);
    let (mut c, _) = connect(&ctx, id.clone());
    let mut over = 0;
    for _ in 0..20 {
        let r = c.call(Body::Status).unwrap();
        if r.error.map(|e| e.code) == Some(ErrorCode::Overloaded) {
            over += 1;
        }
    }
    assert!(over >= 10, "Rate nicht begrenzt ({over} von 20 abgewiesen)");

    let (ctx, _d2) = self::ctx(true, ConnLimits::default());
    let (mut c, _) = connect(&ctx, id);
    let mut accepted = 0;
    let mut refused = 0;
    for _ in 0..10 {
        let r = c
            .call(Body::ScanStart {
                paths: vec![dir.path().display().to_string()],
                use_clamav: false,
            })
            .unwrap();
        if r.ok {
            accepted += 1;
        } else {
            assert_eq!(r.error.unwrap().code, ErrorCode::Overloaded);
            refused += 1;
        }
    }
    assert_eq!(accepted, JobLimits::default().max_per_owner);
    assert_eq!(refused, 10 - accepted);
}

#[test]
fn service_accounts_and_session_zero_are_refused() {
    let (ctx, _d) = ctx(false, ConnLimits::default());
    let mut sys = identity("S-1-5-18", 1);
    sys.session_id = 0;
    let (mut c, h) = connect(&ctx, sys);
    assert_eq!(
        c.read_response().unwrap().error.unwrap().code,
        ErrorCode::Forbidden
    );
    assert!(matches!(h.join().unwrap(), ConnEnd::Forbidden(_)));
    let mut svc0 = identity("S-1-5-21-1-2-3-1001", 1);
    svc0.session_id = 0;
    let (mut c, _) = connect(&ctx, svc0);
    assert_eq!(
        c.read_response().unwrap().error.unwrap().code,
        ErrorCode::Forbidden
    );
}
