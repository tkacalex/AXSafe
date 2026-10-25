//! Isolierter Scanworker (P02, AXS-013, T-013, T-021, T-022).
//!
//! Läuft gegen das echte `axsafe-worker` und gegen das Testdoppel
//! `axsafe-worker-testhelper` mit eingebauten Fehlern. Die Abschottung wird
//! nicht angenommen, sondern mit verbotenen Aktionen nachgewiesen.

use axsafe_core::engine::{Engine, EngineHealth, GapReason, IsolationKind, ScanInput};
use axsafe_core::filetype::FileKind;
use axsafe_core::verdict::Verdict;
use axsafe_worker::host::{WorkerConfig, WorkerEngine};
use axsafe_worker::protocol::Probe;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn worker() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_axsafe-worker"))
}

fn helper() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_axsafe-worker-testhelper"))
}

fn rules() -> Result<Vec<axsafe_engine_yarax::RuleSource>, String> {
    axsafe_engine_yarax::read_rule_sources(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules"),
    )
}

fn eicar() -> Vec<u8> {
    let a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
    let b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    format!("{a}{b}").into_bytes()
}

fn scan(e: &WorkerEngine, data: &[u8], timeout_ms: u64) -> axsafe_core::engine::EngineOutcome {
    e.scan(&ScanInput {
        data,
        kind: &FileKind::Unknown,
        sha256: "",
        timeout: Duration::from_millis(timeout_ms),
    })
}

fn helper_cfg(mode: &str, extra: Option<String>) -> WorkerConfig {
    let mut c = WorkerConfig::new(helper(), rules());
    c.args = std::iter::once(mode.to_string()).chain(extra).collect();
    c
}

#[test]
fn real_worker_is_isolated_and_scans() {
    let e = WorkerEngine::start(WorkerConfig::new(worker(), rules()));
    let info = e.info();
    assert_eq!(info.health, EngineHealth::Ready, "{info:?}");
    // Abschottung zur Laufzeit nachgewiesen (Linux: Landlock, Windows: AppContainer).
    assert!(
        info.isolation.enforced,
        "Isolation nicht nachgewiesen: {:?}",
        info.isolation
    );
    assert_eq!(info.isolation.kind, IsolationKind::SandboxedWorker);
    let checks = e.probe_checks();
    assert_eq!(checks.len(), 5, "{checks:?}");
    assert!(checks.iter().all(|c| c.denied), "{checks:?}");

    let hit = scan(&e, &eicar(), 5000);
    assert_eq!(hit.verdict, Verdict::Malicious, "{hit:?}");
    assert!(hit.detections.iter().any(|d| d.test_signature));
    let clean = scan(&e, b"Sehr geehrte Damen und Herren", 5000);
    assert_eq!(clean.verdict, Verdict::NoDetection, "{clean:?}");
    assert!(clean.gaps.is_empty());
}

/// T-013: Ein „kompromittierter“ Worker versucht, eine Systemdatei zum
/// Schreiben zu öffnen und ins Netz zu verbinden. Beides muss scheitern.
/// Es wird nichts geschrieben.
#[test]
fn compromised_worker_cannot_touch_system_files_or_network() {
    let e = WorkerEngine::start(WorkerConfig::new(worker(), rules()));
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    let system_file = if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        format!(r"{root}\System32\drivers\etc\hosts")
    } else {
        "/etc/hosts".to_string()
    };
    let home =
        std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).unwrap_or_default();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let checks = e
        .probe(&Probe {
            read_paths: vec![system_file.clone()],
            write_paths: vec![system_file],
            create_in: vec![home, std::env::temp_dir().display().to_string()],
            connect: vec![
                listener.local_addr().unwrap().to_string(),
                "1.1.1.1:443".into(),
            ],
            spawn: vec![worker().display().to_string()],
        })
        .expect("Probe");
    let allowed: Vec<_> = checks.iter().filter(|c| !c.denied).collect();
    // Lesen von Systemdateien ist unter Windows im AppContainer erlaubt
    // (ALL APPLICATION PACKAGES); verboten sind Schreiben, Anlegen, Netz, Start.
    for c in &allowed {
        assert!(
            cfg!(windows) && c.action == "lesen",
            "verbotene Aktion war erlaubt: {c:?}"
        );
    }
    assert!(
        listener.accept().is_err(),
        "Verbindung zum lokalen Lauscher kam durch"
    );
}

#[test]
fn crash_is_error_gap_and_worker_restarts() {
    let e = WorkerEngine::start(helper_cfg("crash-on-payload", None));
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    // Absturz im Worker bleibt im Worker: Fehlerlücke, Host läuft weiter.
    let first = scan(&e, axsafe_worker::CRASH_PAYLOAD, 2000);
    assert_eq!(first.verdict, Verdict::Error, "{first:?}");
    assert_eq!(first.gaps[0].reason, GapReason::EngineError);
    assert!(
        first.gaps[0].detail.contains("Worker ausgefallen"),
        "{first:?}"
    );
    assert_eq!(e.restarts(), 1);
    // Wiederanlauf: nächster Scan startet einen neuen Worker und gelingt.
    let second = scan(&e, &eicar(), 5000);
    assert_eq!(second.verdict, Verdict::Malicious, "{second:?}");
    assert_eq!(e.restarts(), 1);
}

#[test]
fn repeated_crashes_disable_engine_instead_of_looping() {
    let mut cfg = helper_cfg("crash", None);
    cfg.max_restarts = 2;
    let e = WorkerEngine::start(cfg);
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    for _ in 0..3 {
        let o = scan(&e, b"x", 2000);
        assert_eq!(o.verdict, Verdict::Error, "{o:?}");
    }
    let o = scan(&e, b"x", 2000);
    assert_eq!(o.gaps[0].reason, GapReason::EngineUnavailable, "{o:?}");
    assert!(o.gaps[0].detail.contains("abgeschaltet"), "{o:?}");
}

#[test]
fn hanging_worker_is_timeout_and_killed_within_budget() {
    let mut cfg = helper_cfg("hang", None);
    cfg.request_grace = Duration::from_millis(300);
    let e = WorkerEngine::start(cfg);
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    let t = Instant::now();
    let o = scan(&e, b"x", 200);
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    assert_eq!(o.verdict, Verdict::Timeout, "{o:?}");
    assert_eq!(o.gaps[0].reason, GapReason::EngineTimeout);
    assert_eq!(e.restarts(), 1);
}

/// T-022/B-12: Ein Worker, der zu viel Speicher anfordert, wird durch die
/// Speichergrenze gestoppt (Windows: Job Object, Linux: RLIMIT_AS); das
/// Objekt gilt als Fehler, der Host läuft weiter.
#[test]
fn memory_hungry_worker_is_stopped_by_limit() {
    let mut cfg = helper_cfg("alloc", None);
    cfg.memory_bytes = Some(512 * 1024 * 1024);
    let e = WorkerEngine::start(cfg);
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    let o = scan(&e, b"x", 5000);
    assert_eq!(o.verdict, Verdict::Error, "{o:?}");
    assert!(
        o.gaps[0].detail.contains("Worker ausgefallen"),
        "Speichergrenze griff nicht: {o:?}"
    );
}

#[test]
fn protocol_violations_are_errors() {
    for mode in ["garbage", "oversized"] {
        let mut cfg = helper_cfg(mode, None);
        cfg.request_grace = Duration::from_millis(500);
        let e = WorkerEngine::start(cfg);
        assert_eq!(
            e.info().health,
            EngineHealth::Ready,
            "{mode}: {:?}",
            e.info()
        );
        let t = Instant::now();
        let o = scan(&e, b"x", 300);
        assert!(t.elapsed() < Duration::from_secs(3), "{mode}");
        assert!(
            matches!(o.verdict, Verdict::Error | Verdict::Timeout),
            "{mode}: {o:?}"
        );
        assert!(!o.gaps.is_empty(), "{mode}: {o:?}");
    }
}

#[test]
fn missing_worker_and_bad_rules_are_unavailable() {
    let e = WorkerEngine::start(WorkerConfig::new(
        PathBuf::from("/gibt/es/nicht/axsafe-worker"),
        rules(),
    ));
    match e.info().health {
        EngineHealth::Unavailable { reason } => {
            assert!(reason.contains("nicht startbar"), "{reason}")
        }
        h => panic!("{h:?}"),
    }
    let o = scan(&e, b"x", 1000);
    assert_eq!(o.gaps[0].reason, GapReason::EngineUnavailable);

    let bad = vec![axsafe_engine_yarax::RuleSource {
        path: "kaputt.yar".into(),
        text: "rule x { condition: }".into(),
    }];
    let e = WorkerEngine::start(WorkerConfig::new(worker(), Ok(bad)));
    match e.info().health {
        EngineHealth::Unavailable { reason } => assert!(reason.contains("Regelsatz"), "{reason}"),
        h => panic!("{h:?}"),
    }
}

/// Windows: Ein Worker ohne AppContainer verweigert selbst die Arbeit, und
/// der Host verwendet ihn nicht (fail closed).
#[cfg(windows)]
#[test]
fn unsandboxed_worker_is_refused_on_windows() {
    let mut cfg = WorkerConfig::new(worker(), rules());
    cfg.sandbox = axsafe_worker::host::Sandbox::None;
    let e = WorkerEngine::start(cfg);
    match e.info().health {
        EngineHealth::Unavailable { reason } => {
            assert!(reason.contains("Isolation"), "{reason}")
        }
        h => panic!("ohne AppContainer darf der Worker nicht bereit sein: {h:?}"),
    }
}

// --- Neustartpfad: jeder neue Worker wird vollständig neu geprüft ---------

fn restart_cfg(restart: &[&str]) -> WorkerConfig {
    let mut c = helper_cfg("crash-on-payload", None);
    c.restart_args = Some(restart.iter().map(|s| s.to_string()).collect());
    c
}

#[test]
fn restart_with_rejected_rules_is_refused_and_state_updated() {
    let mut cfg = restart_cfg(&["reject-rules"]);
    cfg.max_restarts = 1;
    let e = WorkerEngine::start(cfg);
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    let crash = scan(&e, axsafe_worker::CRASH_PAYLOAD, 2000);
    assert_eq!(crash.verdict, Verdict::Error);
    // Neustart liefert abgelehnten Regelsatz → kein Scan, Lücke mit Grund.
    let o = scan(&e, &eicar(), 5000);
    assert_eq!(o.verdict, Verdict::Error, "{o:?}");
    assert!(o.gaps[0].detail.contains("Regelsatz abgelehnt"), "{o:?}");
    // Nach Überschreiten der Neustartgrenze zeigt die Engine „nicht verfügbar“.
    match e.info().health {
        EngineHealth::Unavailable { reason } => {
            assert!(reason.contains("abgeschaltet"), "{reason}")
        }
        h => panic!("Zustand nicht nachgeführt: {h:?}"),
    }
}

#[test]
fn restart_with_changed_content_version_is_refused() {
    let e = WorkerEngine::start(restart_cfg(&["wrong-content"]));
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    let first_version = e.info().content_version;
    scan(&e, axsafe_worker::CRASH_PAYLOAD, 2000);
    let o = scan(&e, &eicar(), 5000);
    assert_eq!(o.verdict, Verdict::Error, "{o:?}");
    assert!(
        o.gaps[0]
            .detail
            .contains("Inhaltsstand nach Neustart weicht ab"),
        "{o:?}"
    );
    assert_eq!(e.info().content_version, first_version);
}

/// Fehlt nach einem Neustart die Abschottung, bekommt der Worker keine
/// Scandaten: Das Testdoppel legt beim Empfang eines Scans eine Markerdatei
/// an – sie darf nicht entstehen.
#[test]
fn restart_without_isolation_receives_no_scan_data() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("scandaten-erhalten");
    let e = WorkerEngine::start(restart_cfg(&["no-sandbox", &marker.display().to_string()]));
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    assert!(e.info().isolation.enforced);
    scan(&e, axsafe_worker::CRASH_PAYLOAD, 2000);
    let o = scan(&e, &eicar(), 5000);
    assert_eq!(o.verdict, Verdict::Error, "{o:?}");
    assert!(
        o.gaps[0].detail.contains("Isolation nicht nachgewiesen"),
        "{o:?}"
    );
    assert!(
        !marker.exists(),
        "Worker ohne Isolation hat Scandaten erhalten"
    );
    // Angezeigter Isolationsstand ist nachgeführt, nicht der alte Nachweis.
    assert!(!e.info().isolation.enforced, "{:?}", e.info().isolation);
}

#[test]
fn isolation_is_reprobed_after_every_restart() {
    let e = WorkerEngine::start(helper_cfg("crash-on-payload", None));
    assert!(e.info().isolation.enforced);
    for n in 1..=2 {
        scan(&e, axsafe_worker::CRASH_PAYLOAD, 2000);
        let ok = scan(&e, b"harmlos", 5000);
        assert_eq!(ok.verdict, Verdict::NoDetection, "{ok:?}");
        let iso = e.info().isolation;
        assert!(iso.enforced, "{iso:?}");
        assert!(
            iso.detail
                .contains(&format!("erneut geprüft nach Neustart {n}")),
            "{iso:?}"
        );
        assert_eq!(e.probe_checks().len(), 5);
    }
}

/// Der Worker sieht nur die festgelegte Umgebung. Geprüft mit einem
/// künstlichen Testwert, nie mit echten Zugangsdaten.
#[test]
fn worker_gets_only_explicit_environment() {
    // SAFETY-Hinweis: setzt eine künstliche Variable im Testprozess.
    std::env::set_var("AXSAFE_TEST_KUENSTLICHES_GEHEIMNIS", "nur-ein-testwert");
    let mut cfg = WorkerConfig::new(worker(), rules());
    cfg.env.push(("AXSAFE_TEST_ERLAUBT".into(), "1".into()));
    let e = WorkerEngine::start(cfg);
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    let names = e.worker_env_names();
    assert!(
        !names
            .iter()
            .any(|n| n == "AXSAFE_TEST_KUENSTLICHES_GEHEIMNIS"),
        "{names:?}"
    );
    assert!(
        names.iter().any(|n| n == "AXSAFE_TEST_ERLAUBT"),
        "{names:?}"
    );
    let mut expected: Vec<String> = axsafe_worker::host::minimal_env()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    expected.push("AXSAFE_TEST_ERLAUBT".into());
    let mut got = names.clone();
    got.sort();
    expected.sort();
    assert_eq!(got, expected, "Worker sieht mehr als festgelegt");
}
