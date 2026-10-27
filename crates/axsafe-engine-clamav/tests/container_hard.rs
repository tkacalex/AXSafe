//! AXS-024: Container-Härtetests mit **echtem** ClamAV über den ganzen
//! Prüfweg (Scanner + Strukturprüfung + Engine). Alle Container werden zur
//! Laufzeit erzeugt; EICAR nur im Speicher zusammengesetzt.
//! Ohne ClamAV schlagen die Tests fehl (nie still bestanden); sie laufen in
//! der Linux-CI mit `--include-ignored`.

mod common;

use axsafe_core::engine::{Engine, GapReason, ScanInput};
use axsafe_core::report::{FileResult, ObjectStatus};
use axsafe_core::scan::{NoProgress, Scanner};
use axsafe_core::verdict::Verdict;
use axsafe_engine_clamav::{ClamAvConfig, ClamAvEngine};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

fn engine(dir: &Path) -> ClamAvEngine {
    common::require_clamscan();
    ClamAvEngine::new(ClamAvConfig {
        database: Some(common::test_hdb(dir)),
        ..Default::default()
    })
}

fn scan_file(dir: &Path, name: &str, data: &[u8]) -> FileResult {
    let data_dir = dir.join("daten");
    std::fs::create_dir_all(&data_dir).unwrap();
    let p = data_dir.join(name);
    std::fs::write(&p, data).unwrap();
    let s = Scanner::new(vec![Box::new(engine(dir))], Default::default());
    let rep = s.scan_paths(&[p], &AtomicBool::new(false), &mut NoProgress);
    rep.files.into_iter().next().unwrap()
}

#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn truncated_archive_is_never_complete_and_clean() {
    let dir = tempfile::tempdir().unwrap();
    let z = common::zip_with(
        &[("innen/e.bin", &common::eicar()), ("b.txt", &[b'x'; 5000])],
        None,
    );
    for cut in [z.len() - 30, z.len() / 2] {
        let f = scan_file(dir.path(), &format!("kaputt-{cut}.zip"), &z[..cut]);
        assert!(
            f.gaps
                .iter()
                .any(|g| g.reason == GapReason::ContainerDamaged),
            "Beschädigung muss sichtbar sein: {f:?}"
        );
        assert_ne!(f.status, ObjectStatus::NoDetection, "{f:?}");
    }
}

#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn archive_bomb_is_gap_not_clean() {
    // 150 MiB Nullen, komprimiert ~150 KiB. ClamAV allein meldet hier
    // (gemessen) „OK“ – die Strukturprüfung macht die Grenze sichtbar.
    let dir = tempfile::tempdir().unwrap();
    let zeros = vec![0u8; 150 * 1024 * 1024];
    let z = common::zip_with(&[("null.bin", &zeros)], None);
    drop(zeros);
    let f = scan_file(dir.path(), "bombe.zip", &z);
    assert!(
        f.gaps
            .iter()
            .any(|g| g.reason == GapReason::EngineLimitExceeded),
        "{:?}",
        f.gaps
    );
    assert_eq!(f.status, ObjectStatus::Incomplete);
}

#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn encrypted_and_nested_and_embedded_content() {
    let dir = tempfile::tempdir().unwrap();
    let enc = common::zip_with(&[("a.txt", b"hallo")], Some("geheim"));
    let f = scan_file(dir.path(), "enc.zip", &enc);
    assert!(
        f.gaps.iter().any(|g| g.state == Verdict::Encrypted),
        "{f:?}"
    );
    // ZIP im Anhang einer Programmdatei (eingebetteter Inhalt).
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
    pe[128..132].copy_from_slice(b"PE\0\0");
    pe.extend(common::zip_with(&[("e.bin", &common::eicar())], None));
    let f = scan_file(dir.path(), "programm.exe", &pe);
    assert_eq!(f.detection, Verdict::Malicious, "eingebettet: {f:?}");
}

#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn path_escape_names_write_nothing_outside() {
    let dir = tempfile::tempdir().unwrap();
    let marker = "axsafe-ausbruch-pruefung.txt";
    let z = common::zip_with(
        &[
            (&format!("../../{marker}"), b"x"),
            (&format!("../../../../../../tmp/{marker}"), b"x"),
        ],
        None,
    );
    let f = scan_file(dir.path(), "slip.zip", &z);
    assert_eq!(f.detection, Verdict::NoDetection, "{f:?}");
    let h = f
        .engines
        .iter()
        .find(|e| e.engine == axsafe_core::heuristics::HEURISTICS_ENGINE)
        .unwrap();
    assert!(h.note.as_deref().unwrap_or("").contains("Pfadausbruch"));
    for p in [
        dir.path().join(marker),
        dir.path().parent().unwrap().join(marker),
        std::env::temp_dir().join(marker),
        Path::new("/tmp").join(marker),
    ] {
        assert!(!p.exists(), "Datei außerhalb angelegt: {}", p.display());
    }
}

/// ISO 9660: ClamAV prüft den Inhalt (Messung für die Fähigkeitsmatrix).
#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn iso_content_is_inspected() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    for (payload, expect) in [
        (common::eicar(), Verdict::Malicious),
        (b"harmlos".to_vec(), Verdict::NoDetection),
    ] {
        let iso = common::iso_with("inhalt.bin", &payload);
        let kind = axsafe_core::filetype::detect(&iso);
        assert_eq!(kind, axsafe_core::filetype::FileKind::Iso, "{kind:?}");
        let o = e.scan(&ScanInput {
            data: &iso,
            kind: &kind,
            sha256: "",
            timeout: Duration::from_secs(60),
        });
        assert_eq!(o.verdict, expect, "{o:?}");
    }
}

/// RAR: nur mit libclamunrar_iface geprüft. Ohne sie wird RAR nicht
/// beansprucht und erscheint als `content_not_inspected`. Das offizielle
/// Windows-Paket enthält unrar – dort muss RAR geprüft werden.
#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn rar_content_follows_unrar_availability() {
    use axsafe_core::filetype::ContentFormat;
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let claims = e.info().inspects_contents_of.contains(&ContentFormat::Rar);
    if cfg!(windows) {
        assert!(claims, "offizielles ClamAV-Paket für Windows enthält unrar");
    }
    let rar = common::rar_with("inhalt.bin", &common::eicar());
    assert_eq!(
        axsafe_core::filetype::detect(&rar),
        axsafe_core::filetype::FileKind::Rar
    );
    let f = scan_file(dir.path(), "a.rar", &rar);
    if claims {
        assert_eq!(f.detection, Verdict::Malicious, "{f:?}");
        let harmless = scan_file(dir.path(), "b.rar", &common::rar_with("b.txt", b"harmlos"));
        assert_eq!(harmless.status, ObjectStatus::NoDetection, "{harmless:?}");
    } else {
        assert!(
            f.gaps
                .iter()
                .any(|g| g.reason == GapReason::ContentNotInspected),
            "{f:?}"
        );
        assert_ne!(f.status, ObjectStatus::NoDetection);
    }
}

/// Die RAR-Laufzeitprobe (verschlüsselt markiertes RAR) muss von einem
/// ClamAV mit unrar als „verschlüsselt“ erkannt werden – sonst wäre die Probe
/// selbst wertlos. Unter Windows hat clamscan unrar (offizielles Paket).
#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn rar_capability_probe_is_recognised_where_unrar_works() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let claims = e
        .info()
        .inspects_contents_of
        .contains(&axsafe_core::filetype::ContentFormat::Rar);
    let probe = axsafe_engine_clamav::rar_capability_probe();
    let kind = axsafe_core::filetype::detect(&probe);
    let o = e.scan(&ScanInput {
        data: &probe,
        kind: &kind,
        sha256: "",
        timeout: Duration::from_secs(60),
    });
    let encrypted = o.gaps.iter().any(|g| g.state == Verdict::Encrypted);
    if claims {
        assert!(
            encrypted,
            "Probe nicht als verschlüsseltes RAR erkannt: {o:?}"
        );
    } else {
        assert!(!o.verdict.is_detection(), "{o:?}");
    }
}
