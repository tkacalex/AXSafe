//! B-18: dauerhaft geladene ClamAV-Engine (Worker + Host
//! `ClamAvWorkerEngine`) mit der ECHTEN libclamav und einer zur Laufzeit
//! erzeugten Testsignatur. Fehlerfälle über das Testdoppel
//! `axsafe-clamav-worker-testhelper` (Absturz, Hänger, falscher Stand).
//!
//! Vorbedingung: libclamav ist installiert (Linux-CI: Paket `clamav`,
//! Windows-CI: `scripts/windows/setup-clamav.ps1`). Fehlt sie, schlagen die
//! Tests fehl – sie bestehen nie still. Sie tragen deshalb `#[ignore]` mit
//! Grund und laufen mit `--include-ignored` (Linux-CI, windows-clamav).

#[path = "../../axsafe-engine-clamav/tests/common/archives.rs"]
mod archives;

use axsafe_core::engine::{Engine, EngineHealth, GapReason, ScanInput};
use axsafe_core::verdict::Verdict;
use axsafe_engine_clamav::persistent::{default_library, ClamAvWorkerEngine, WorkerSettings};
use axsafe_engine_clamav::ClamAvConfig;
use md5::{Digest, Md5};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// EICAR zur Laufzeit zusammengesetzt (nie am Stück im Quelltext).
fn eicar() -> Vec<u8> {
    let a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
    let b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    format!("{a}{b}").into_bytes()
}

fn hdb_line(data: &[u8], name: &str) -> String {
    format!("{}:{}:{name}\n", hex::encode(Md5::digest(data)), data.len())
}

const HARMLOS_B: &[u8] = b"AXSafe harmlose Testdatei B (zweite Signatur nach Update)";

struct Fixture {
    _dir: tempfile::TempDir,
    db: PathBuf,
    exe: PathBuf,
}

fn library() -> PathBuf {
    let clamscan = if cfg!(windows) {
        axsafe_engine_clamav::windows_default_paths().0
    } else {
        PathBuf::from("clamscan")
    };
    let lib = default_library(&clamscan);
    assert!(
        lib.exists() || !lib.is_absolute(),
        "Vorbedingung fehlt: libclamav nicht gefunden ({})",
        lib.display()
    );
    lib
}

fn fixture(bin: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    std::fs::create_dir(&db).unwrap();
    std::fs::write(
        db.join("axsafe-test.hdb"),
        hdb_line(&eicar(), "AXSafe.Test.EICAR.HDB"),
    )
    .unwrap();
    let src = match bin {
        "worker" => PathBuf::from(env!("CARGO_BIN_EXE_axsafe-clamav-worker")),
        _ => PathBuf::from(env!("CARGO_BIN_EXE_axsafe-clamav-worker-testhelper")),
    };
    let exe = dir
        .path()
        .join(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(src, &exe).unwrap();
    #[cfg(windows)]
    axsafe_proc::restricted_grant_execute(&exe).unwrap();
    wait_copy(&exe);
    Fixture { _dir: dir, db, exe }
}

/// Linux: frisch kopierte Programme können kurz ETXTBSY liefern.
fn wait_copy(p: &Path) {
    for _ in 0..200 {
        if std::fs::OpenOptions::new().write(true).open(p).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn settings(f: &Fixture, args: &[&str]) -> WorkerSettings {
    let cfg = ClamAvConfig {
        database: Some(f.db.clone()),
        ..ClamAvConfig::default()
    };
    let mut ws = WorkerSettings::new(f.exe.clone(), &cfg);
    ws.library = Some(library());
    ws.args = args.iter().map(|s| s.to_string()).collect();
    ws.startup_timeout = Duration::from_secs(120);
    ws.update_check = Duration::ZERO;
    ws
}

fn scan(e: &dyn Engine, data: &[u8], timeout: Duration) -> axsafe_core::engine::EngineOutcome {
    let kind = axsafe_core::filetype::detect(data);
    e.scan(&ScanInput {
        data,
        kind: &kind,
        sha256: "",
        timeout,
    })
}

fn ready(e: &ClamAvWorkerEngine) {
    let i = e.info();
    assert_eq!(i.health, EngineHealth::Ready, "Engine nicht bereit: {i:?}");
    assert!(
        i.isolation.enforced,
        "Isolation nicht nachgewiesen: {:?}",
        i.isolation
    );
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn loads_once_and_scans_many_objects() {
    let f = fixture("worker");
    let e = ClamAvWorkerEngine::start(settings(&f, &[]), PathBuf::from("clamscan"));
    ready(&e);
    let t = Duration::from_secs(30);
    for i in 0..20 {
        let o = scan(&e, &eicar(), t);
        assert_eq!(o.verdict, Verdict::Malicious, "Durchlauf {i}: {o:?}");
        assert!(o.detections[0].name.starts_with("AXSafe.Test.EICAR.HDB"));
        assert!(o.detections[0].test_signature);
        let o = scan(&e, format!("harmlos {i}").as_bytes(), t);
        assert_eq!(o.verdict, Verdict::NoDetection, "{o:?}");
        assert!(o.gaps.is_empty());
    }
    let s = e.stats();
    assert_eq!(
        s.launches, 1,
        "Datenbank darf nur einmal geladen werden: {s:?}"
    );
    assert_eq!(s.restarts, 0);
    assert_eq!(s.signatures, Some(1));
    let note = e.info().content_note;
    assert!(note.contains("dauerhaft geladen"), "{note}");
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn parallel_jobs_get_their_own_results() {
    let f = fixture("worker");
    let e = Arc::new(ClamAvWorkerEngine::start(
        settings(&f, &[]),
        PathBuf::from("clamscan"),
    ));
    ready(&e);
    let mut hs = Vec::new();
    for t in 0..8u32 {
        let e = e.clone();
        hs.push(std::thread::spawn(move || {
            for i in 0..15u32 {
                let bad = (t + i) % 3 == 0;
                let data = if bad {
                    eicar()
                } else {
                    format!("Auftrag {t} Objekt {i}").into_bytes()
                };
                let o = scan(&*e, &data, Duration::from_secs(60));
                if bad {
                    assert_eq!(o.verdict, Verdict::Malicious, "Auftrag {t}/{i}: {o:?}");
                } else {
                    assert_eq!(o.verdict, Verdict::NoDetection, "Auftrag {t}/{i}: {o:?}");
                }
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(e.stats().launches, 1);
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn crash_is_a_gap_and_worker_restarts() {
    let f = fixture("testhelper");
    let e = ClamAvWorkerEngine::start(settings(&f, &["crash"]), PathBuf::from("clamscan"));
    ready(&e);
    let t = Duration::from_secs(30);
    let o = scan(&e, axsafe_clamav_worker::CRASH_PAYLOAD, t);
    assert_eq!(
        o.verdict,
        Verdict::Error,
        "Absturz darf nie sauber sein: {o:?}"
    );
    assert_eq!(o.gaps[0].reason, GapReason::EngineError);
    assert!(!e.worker_running());
    let o = scan(&e, &eicar(), t);
    assert_eq!(o.verdict, Verdict::Malicious, "nach Neustart: {o:?}");
    let s = e.stats();
    assert_eq!((s.launches, s.restarts), (2, 1), "{s:?}");
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn hanging_engine_times_out_and_is_replaced() {
    let f = fixture("testhelper");
    let mut ws = settings(&f, &["hang"]);
    ws.request_grace = Duration::from_millis(200);
    let e = ClamAvWorkerEngine::start(ws, PathBuf::from("clamscan"));
    ready(&e);
    let start = Instant::now();
    let o = scan(
        &e,
        axsafe_clamav_worker::HANG_PAYLOAD,
        Duration::from_secs(1),
    );
    assert!(start.elapsed() < Duration::from_secs(10));
    assert_eq!(o.verdict, Verdict::Timeout, "{o:?}");
    assert_eq!(o.gaps[0].reason, GapReason::EngineTimeout);
    let o = scan(&e, b"harmlos", Duration::from_secs(30));
    assert_eq!(o.verdict, Verdict::NoDetection, "{o:?}");
    assert_eq!(e.stats().launches, 2);
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn full_queue_is_a_visible_gap() {
    let f = fixture("testhelper");
    let mut ws = settings(&f, &["hang"]);
    ws.queue_wait = Duration::from_millis(300);
    ws.request_grace = Duration::from_millis(100);
    let e = Arc::new(ClamAvWorkerEngine::start(ws, PathBuf::from("clamscan")));
    ready(&e);
    let e2 = e.clone();
    let h = std::thread::spawn(move || {
        scan(
            &*e2,
            axsafe_clamav_worker::HANG_PAYLOAD,
            Duration::from_secs(3),
        )
    });
    std::thread::sleep(Duration::from_millis(500));
    let o = scan(&*e, b"harmlos", Duration::from_secs(30));
    assert_eq!(o.verdict, Verdict::Timeout, "{o:?}");
    assert!(o.gaps[0].detail.contains("ausgelastet"), "{o:?}");
    assert_eq!(h.join().unwrap().verdict, Verdict::Timeout);
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn repeated_failures_disable_the_engine() {
    let f = fixture("testhelper");
    let mut ws = settings(&f, &["crash"]);
    ws.max_restarts = 2;
    let e = ClamAvWorkerEngine::start(ws, PathBuf::from("clamscan"));
    ready(&e);
    for _ in 0..3 {
        let o = scan(
            &e,
            axsafe_clamav_worker::CRASH_PAYLOAD,
            Duration::from_secs(30),
        );
        assert_eq!(o.verdict, Verdict::Error);
    }
    assert!(matches!(e.info().health, EngineHealth::Unavailable { .. }));
    let o = scan(&e, b"harmlos", Duration::from_secs(30));
    assert_eq!(
        o.verdict,
        Verdict::Error,
        "abgeschaltet heißt nie sauber: {o:?}"
    );
    assert_eq!(o.gaps[0].reason, GapReason::EngineUnavailable);
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn signature_update_becomes_active_only_after_successful_load() {
    let f = fixture("worker");
    let e = ClamAvWorkerEngine::start(settings(&f, &[]), PathBuf::from("clamscan"));
    ready(&e);
    let t = Duration::from_secs(30);
    let v1 = e.info().content_version;
    assert_eq!(scan(&e, HARMLOS_B, t).verdict, Verdict::NoDetection);

    // 1) Gültiges Update: zweite Signatur.
    let mut text = hdb_line(&eicar(), "AXSafe.Test.EICAR.HDB");
    text.push_str(&hdb_line(HARMLOS_B, "AXSafe.Test.Update.HDB"));
    std::fs::write(f.db.join("axsafe-test.hdb"), &text).unwrap();
    let o = scan(&e, HARMLOS_B, t);
    assert_eq!(
        o.verdict,
        Verdict::Malicious,
        "neuer Stand nicht aktiv: {o:?}"
    );
    let v2 = e.info().content_version;
    assert_ne!(v1, v2);
    assert!(e.info().content_note.contains("aktualisiert von"));
    assert_eq!(e.stats().launches, 2);

    // 2) Kaputtes Update: alter Stand bleibt aktiv, Fehler sichtbar.
    std::fs::write(f.db.join("kaputt.hdb"), "das ist keine Signatur\n").unwrap();
    let o = scan(&e, HARMLOS_B, t);
    assert_eq!(
        o.verdict,
        Verdict::Malicious,
        "bisheriger Stand muss aktiv bleiben: {o:?}"
    );
    let info = e.info();
    assert_eq!(
        info.content_version, v2,
        "nicht geladener Stand darf nicht als aktiv gelten"
    );
    assert!(
        info.content_note.contains("SIGNATURUPDATE NICHT GELADEN"),
        "{}",
        info.content_note
    );
    assert_eq!(info.health, EngineHealth::Ready);
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn object_size_limit_is_a_gap() {
    let f = fixture("worker");
    let mut ws = settings(&f, &[]);
    ws.max_scan_bytes = 1024;
    let e = ClamAvWorkerEngine::start(ws, PathBuf::from("clamscan"));
    ready(&e);
    let o = scan(&e, &vec![b'a'; 2048], Duration::from_secs(30));
    assert_eq!(o.verdict, Verdict::Unsupported);
    assert_eq!(o.gaps[0].reason, GapReason::SizeLimit);
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn idle_worker_is_stopped_and_restarted_on_demand() {
    let f = fixture("worker");
    let mut ws = settings(&f, &[]);
    ws.idle_timeout = Duration::from_secs(1);
    let e = ClamAvWorkerEngine::start(ws, PathBuf::from("clamscan"));
    ready(&e);
    let until = Instant::now() + Duration::from_secs(15);
    while e.worker_running() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!e.worker_running(), "Leerlauf beendet den Worker nicht");
    let o = scan(&e, &eicar(), Duration::from_secs(30));
    assert_eq!(o.verdict, Verdict::Malicious);
    assert_eq!(e.stats().launches, 2);
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn missing_library_is_unavailable_never_clean() {
    let f = fixture("worker");
    let mut ws = settings(&f, &[]);
    ws.library = Some(f.db.join("gibt-es-nicht.dll"));
    let e = ClamAvWorkerEngine::start(ws, PathBuf::from("clamscan"));
    assert!(
        matches!(e.info().health, EngineHealth::Unavailable { .. }),
        "{:?}",
        e.info()
    );
    let o = scan(&e, b"harmlos", Duration::from_secs(30));
    assert_eq!(o.verdict, Verdict::Error, "{o:?}");
}

#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn broken_database_is_unavailable_never_clean() {
    let f = fixture("worker");
    std::fs::write(f.db.join("axsafe-test.hdb"), "kaputt\n").unwrap();
    let e = ClamAvWorkerEngine::start(settings(&f, &[]), PathBuf::from("clamscan"));
    assert!(
        matches!(e.info().health, EngineHealth::Unavailable { .. }),
        "{:?}",
        e.info()
    );
    assert_eq!(
        scan(&e, &eicar(), Duration::from_secs(30)).verdict,
        Verdict::Error
    );
}

/// Offizielle Datenbank: Meldet der Worker einen anderen daily-Stand als die
/// Dateiköpfe, wird er verworfen. Nur wo die offizielle DB vorhanden ist
/// (CI-Job clamav-signatures bzw. windows-clamav).
#[test]
#[ignore = "braucht die offizielle ClamAV-Datenbank (CI: clamav-signatures, windows-clamav)"]
fn worker_with_mismatching_official_db_version_is_rejected() {
    let db = if cfg!(windows) {
        axsafe_engine_clamav::windows_default_paths().1
    } else {
        Some(PathBuf::from("/var/lib/clamav"))
    }
    .expect("offizielle Datenbank fehlt");
    let content = axsafe_engine_clamav::database_content(&db).unwrap();
    assert!(
        content.daily.is_some(),
        "keine offizielle daily-Datenbank in {}",
        db.display()
    );
    let f = fixture("testhelper");
    let mut ws = settings(&f, &["wrong-db"]);
    ws.database = Some(db);
    ws.startup_timeout = Duration::from_secs(600);
    let e = ClamAvWorkerEngine::start(ws, PathBuf::from("clamscan"));
    match e.info().health {
        EngineHealth::Unavailable { reason } => assert!(reason.contains("passt nicht"), "{reason}"),
        h => panic!("falscher Stand wurde angenommen: {h:?}"),
    }
}

/// Die dauerhafte Engine (Windows-Standard) beansprucht dieselben
/// Inhaltsformate wie clamscan – hier mit der echten libclamav belegt.
#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn content_formats_are_backed_by_real_libclamav() {
    use axsafe_core::filetype::{self, ContentFormat};
    let f = fixture("worker");
    let e = ClamAvWorkerEngine::start(settings(&f, &[]), PathBuf::from("clamscan"));
    ready(&e);
    let info = e.info();
    let claimed = info.inspects_contents_of.clone();
    assert!(claimed.starts_with(&axsafe_engine_clamav::VERIFIED_CONTENT_FORMATS));
    // RAR nur nach bestandener Laufzeitprobe; sonst muss es im Hinweis stehen
    // (gemessen: Windows-Worker lädt unrar nicht, siehe CAPABILITY-MATRIX).
    println!(
        "MESSUNG RAR im dauerhaften Worker: {}",
        if claimed.contains(&ContentFormat::Rar) {
            "geprüft"
        } else {
            "nicht prüfbar"
        }
    );
    if !claimed.contains(&ContentFormat::Rar) {
        assert!(
            info.content_note.contains("RAR-Inhalt nicht prüfbar"),
            "{}",
            info.content_note
        );
    }
    let p = eicar();
    let tmp = tempfile::tempdir().unwrap();
    let cases: Vec<(ContentFormat, Vec<u8>)> = vec![
        (
            ContentFormat::Zip,
            archives::zip_with(&[("inhalt.bin", &p)], None),
        ),
        (ContentFormat::Ooxml, archives::ooxml_with(&p)),
        (ContentFormat::Gzip, archives::gzip_with(&p)),
        (ContentFormat::OleCfb, archives::cfb_with(&p)),
        (ContentFormat::Cab, archives::cab_with(&p)),
        (
            ContentFormat::SevenZip,
            archives::sevenz_with(tmp.path(), &p),
        ),
        (ContentFormat::Pdf, archives::pdf_with(&p)),
        (ContentFormat::Iso, archives::iso_with("inhalt.bin", &p)),
        (ContentFormat::Rar, archives::rar_with("inhalt.bin", &p)),
    ];
    let cases: Vec<_> = cases
        .into_iter()
        .filter(|(f, _)| claimed.contains(f))
        .collect();
    assert_eq!(
        cases.len(),
        claimed.len(),
        "jedes beanspruchte Format braucht einen Fall"
    );
    for (fmt, data) in cases {
        let kind = filetype::detect(&data);
        assert_eq!(filetype::content_format(&kind), Some(fmt), "{kind:?}");
        let o = scan(&e, &data, Duration::from_secs(60));
        assert_eq!(
            o.verdict,
            Verdict::Malicious,
            "libclamav prüft {fmt:?} nicht: {o:?}"
        );
    }
    let enc = archives::zip_with(&[("a.txt", b"hallo")], Some("geheim"));
    let o = scan(&e, &enc, Duration::from_secs(60));
    assert!(
        o.gaps.iter().any(|g| g.reason == GapReason::Encrypted),
        "{o:?}"
    );
}

/// AXS-021: Engine-Vertrag für die dauerhaft geladene ClamAV-Engine.
#[test]
#[ignore = "braucht libclamav (Linux-CI: Paket clamav; Windows: Job windows-clamav)"]
fn conformance_persistent_worker() {
    let f = fixture("worker");
    let e = ClamAvWorkerEngine::start(settings(&f, &[]), PathBuf::from("clamscan"));
    ready(&e);
    axsafe_core::conformance::assert_conforms(&axsafe_core::conformance::check_ready(
        &e,
        &eicar(),
        b"Hallo Welt",
    ));
    let g = fixture("worker");
    std::fs::remove_file(g.db.join("axsafe-test.hdb")).unwrap();
    std::fs::write(g.db.join("kaputt.hdb"), b"kein gueltiger eintrag\n").unwrap();
    let broken = ClamAvWorkerEngine::start(settings(&g, &[]), PathBuf::from("clamscan"));
    axsafe_core::conformance::assert_conforms(&axsafe_core::conformance::check_unavailable(
        &broken,
    ));
}
