//! Integrationstests mit **echtem** ClamAV. Pflicht in der Linux-CI
//! (`--include-ignored`, ClamAV installiert); lokal ohne ClamAV als
//! „ignoriert“ gezählt, nie still bestanden.

mod common;

use axsafe_core::engine::{ContentKind, Engine, EngineHealth, GapReason, ScanInput};
use axsafe_core::filetype::{self, ContentFormat};
use axsafe_core::verdict::Verdict;
use axsafe_engine_clamav::{ClamAvConfig, ClamAvEngine, VERIFIED_CONTENT_FORMATS};
use std::path::Path;
use std::time::Duration;

fn engine(dir: &Path) -> ClamAvEngine {
    common::require_clamscan();
    let e = ClamAvEngine::new(ClamAvConfig {
        database: Some(common::test_hdb(dir)),
        ..Default::default()
    });
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    e
}

fn scan(e: &ClamAvEngine, data: &[u8]) -> axsafe_core::engine::EngineOutcome {
    let kind = filetype::detect(data);
    e.scan(&ScanInput {
        data,
        kind: &kind,
        sha256: "",
        timeout: Duration::from_secs(60),
    })
}

#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn positive_benign_and_test_only_content() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let info = e.info();
    assert!(info.engine_version.starts_with("ClamAV "));
    assert_eq!(info.content_kind, ContentKind::TestOnly, "{info:?}");
    let pos = scan(&e, &common::eicar());
    assert_eq!(pos.verdict, Verdict::Malicious, "{pos:?}");
    assert!(pos.detections[0].test_signature);
    let neg = scan(&e, b"Hallo Welt, ganz harmlos.");
    assert_eq!(neg.verdict, Verdict::NoDetection, "{neg:?}");
    assert!(neg.gaps.is_empty());
}

#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn without_database_is_unavailable() {
    common::require_clamscan();
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("leer");
    std::fs::create_dir(&empty).unwrap();
    let e = ClamAvEngine::new(ClamAvConfig {
        database: Some(empty),
        ..Default::default()
    });
    assert!(
        matches!(e.info().health, EngineHealth::Unavailable { .. }),
        "{:?}",
        e.info()
    );
}

#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn content_formats_are_backed_by_real_clamav() {
    // Befund 3: Jede beanspruchte Inhaltsfähigkeit ist hier belegt.
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let p = common::eicar();
    let cases: Vec<(ContentFormat, Vec<u8>)> = vec![
        (
            ContentFormat::Zip,
            common::zip_with(&[("inhalt.bin", &p)], None),
        ),
        (ContentFormat::Ooxml, common::ooxml_with(&p)),
        (ContentFormat::Gzip, common::gzip_with(&p)),
        (ContentFormat::OleCfb, common::cfb_with(&p)),
        (ContentFormat::Cab, common::cab_with(&p)),
        (ContentFormat::SevenZip, common::sevenz_with(dir.path(), &p)),
        (ContentFormat::Pdf, common::pdf_with(&p)),
        (ContentFormat::Iso, common::iso_with("inhalt.bin", &p)),
    ];
    assert_eq!(cases.len(), VERIFIED_CONTENT_FORMATS.len());
    for (fmt, data) in cases {
        assert!(VERIFIED_CONTENT_FORMATS.contains(&fmt));
        let kind = filetype::detect(&data);
        assert_eq!(
            filetype::content_format(&kind),
            Some(fmt),
            "Typerkennung {fmt:?}: {kind:?}"
        );
        let o = scan(&e, &data);
        assert_eq!(
            o.verdict,
            Verdict::Malicious,
            "ClamAV prüft {fmt:?}-Inhalt nicht: {o:?}"
        );
    }
}

#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn harmless_archives_normal_encrypted_nested() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let normal = common::zip_with(&[("a.txt", b"hallo")], None);
    let o = scan(&e, &normal);
    assert_eq!(o.verdict, Verdict::NoDetection, "{o:?}");
    assert!(o.gaps.is_empty());

    let enc = common::zip_with(&[("a.txt", b"hallo")], Some("geheim"));
    let o = scan(&e, &enc);
    assert_eq!(o.gaps.len(), 1, "{o:?}");
    assert_eq!(o.gaps[0].state, Verdict::Encrypted);
    assert_eq!(o.gaps[0].reason, GapReason::Encrypted);

    let inner = common::zip_with(&[("e.bin", &common::eicar())], None);
    let nested = common::zip_with(&[("innen.zip", &inner)], None);
    let o = scan(&e, &nested);
    assert_eq!(o.verdict, Verdict::Malicious, "verschachtelt: {o:?}");
}

#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn recursion_limit_is_reported_as_gap() {
    common::require_clamscan();
    let dir = tempfile::tempdir().unwrap();
    let e = ClamAvEngine::new(ClamAvConfig {
        database: Some(common::test_hdb(dir.path())),
        max_recursion: 1,
        ..Default::default()
    });
    let mut data = common::zip_with(&[("a.txt", b"x")], None);
    for i in 0..4 {
        data = common::zip_with(&[(&format!("ebene{i}.zip"), &data)], None);
    }
    let o = scan(&e, &data);
    assert!(
        o.gaps
            .iter()
            .any(|g| g.reason == GapReason::EngineLimitExceeded),
        "Rekursionsgrenze muss als Lücke erscheinen: {o:?}"
    );
}
