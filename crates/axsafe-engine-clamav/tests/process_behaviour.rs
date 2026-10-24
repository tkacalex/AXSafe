//! Adapterverhalten bei Fehlerfällen des Engine-Prozesses (Befund 4).
//! Plattformübergreifend mit dem harmlosen Testhelfer als „clamscan“.

mod common;

use axsafe_core::engine::{Engine, EngineHealth, GapReason, ScanInput};
use axsafe_core::filetype::FileKind;
use axsafe_core::verdict::Verdict;
use axsafe_engine_clamav::{ClamAvConfig, ClamAvEngine};
use std::time::{Duration, Instant};

fn engine(mode: &str) -> (ClamAvEngine, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let exe = common::fake_clamscan(dir.path(), mode);
    let e = ClamAvEngine::new(ClamAvConfig {
        clamscan: exe,
        ..Default::default()
    });
    assert_eq!(
        e.info().health,
        EngineHealth::Ready,
        "Funktionstest muss bestehen: {:?}",
        e.info()
    );
    (e, dir)
}

fn scan(e: &ClamAvEngine, budget_ms: u64) -> (axsafe_core::engine::EngineOutcome, Duration) {
    let t = Instant::now();
    let o = e.scan(&ScanInput {
        data: b"harmloser Inhalt",
        kind: &FileKind::Text,
        sha256: "",
        timeout: Duration::from_millis(budget_ms),
    });
    (o, t.elapsed())
}

#[test]
fn ok_is_no_detection_without_gaps() {
    let (e, _d) = engine("ok");
    let (o, _) = scan(&e, 10_000);
    assert_eq!(o.verdict, Verdict::NoDetection, "{o:?}");
    assert!(o.gaps.is_empty());
}

#[test]
fn found_line_is_detection() {
    let (e, _d) = engine("found");
    let (o, _) = scan(&e, 10_000);
    assert_eq!(o.verdict, Verdict::Malicious);
    assert_eq!(o.detections[0].name, "AXSafe.Test.Helper");
}

#[test]
fn engine_error_is_error_gap() {
    let (e, _d) = engine("error");
    let (o, _) = scan(&e, 10_000);
    assert_eq!(o.verdict, Verdict::Error);
    assert_eq!(o.gaps[0].reason, GapReason::EngineError);
}

#[test]
fn crash_is_error_gap() {
    let (e, _d) = engine("crash");
    let (o, _) = scan(&e, 10_000);
    assert_eq!(o.verdict, Verdict::Error, "{o:?}");
}

#[test]
fn hang_is_timeout_within_budget() {
    let (e, _d) = engine("hang");
    let (o, took) = scan(&e, 700);
    assert_eq!(o.verdict, Verdict::Timeout);
    assert_eq!(o.gaps[0].reason, GapReason::EngineTimeout);
    assert!(took < Duration::from_secs(3), "{took:?}");
}

#[test]
fn parent_exits_but_descendant_holds_pipes() {
    // Befund 4 auf Adapterebene: Budget 1 s, Nachkomme schläft 30 s.
    // Erwartung: kein „NoDetection“, Ergebnis innerhalb des Budgets.
    let (e, _d) = engine("orphan");
    let (o, took) = scan(&e, 1_000);
    assert_ne!(o.verdict, Verdict::NoDetection, "{o:?}");
    assert!(!o.gaps.is_empty(), "Lücke muss gemeldet werden: {o:?}");
    assert!(
        took < Duration::from_millis(1_500),
        "Aufruf dauerte {took:?}"
    );
}

#[test]
fn output_flood_is_output_limit_gap() {
    let dir = tempfile::tempdir().unwrap();
    let e = ClamAvEngine::new(ClamAvConfig {
        clamscan: common::fake_clamscan(dir.path(), "flood"),
        max_output_bytes: 128 * 1024,
        ..Default::default()
    });
    let (o, took) = scan(&e, 10_000);
    assert_eq!(o.gaps[0].reason, GapReason::OutputLimit, "{o:?}");
    assert!(took < Duration::from_secs(5));
}
