//! Gemeinsame Testhilfen: harmlose Testdaten und Container zur Laufzeit.
#![allow(dead_code)]

mod archives;

use md5::{Digest, Md5};
use std::path::{Path, PathBuf};

/// EICAR wird zur Laufzeit zusammengesetzt (Quelltext enthält ihn nicht am Stück).
pub fn eicar() -> Vec<u8> {
    let a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
    let b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    format!("{a}{b}").into_bytes()
}

/// ClamAV-Hashsignatur (.hdb) für EICAR, nur AXSafe-Testsignatur.
pub fn test_hdb(dir: &Path) -> PathBuf {
    let e = eicar();
    let p = dir.join("axsafe-test.hdb");
    std::fs::write(
        &p,
        format!(
            "{}:{}:AXSafe.Test.EICAR.HDB\n",
            hex::encode(Md5::digest(&e)),
            e.len()
        ),
    )
    .unwrap();
    p
}

#[allow(unused_imports)]
pub use archives::*;

/// Kopiert den Testhelfer als `clamscan-<modus>` in `dir`.
pub fn fake_clamscan(dir: &Path, mode: &str) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_BIN_EXE_axsafe-clamav-testhelper"));
    let dst = dir.join(format!("clamscan-{mode}{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(src, &dst).unwrap();
    wait_executable(&dst);
    dst
}

/// Linux kann eine frisch geschriebene Datei kurz mit ETXTBSY („Text file
/// busy“) ablehnen, wenn parallel ein anderer Test einen Prozess startet und
/// dabei den Schreib-Handle erbt. Warten, bis die Kopie startbar ist.
pub fn wait_executable(p: &Path) {
    for _ in 0..200 {
        match std::process::Command::new(p).arg("--version").output() {
            Ok(o) if o.status.success() => return,
            _ => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    panic!("Testhelfer {} nicht startbar", p.display());
}

pub fn clamscan_available() -> bool {
    std::process::Command::new("clamscan")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Pflicht-Vorbedingung: ohne clamscan schlägt der Test fehl statt still zu bestehen.
pub fn require_clamscan() {
    assert!(
        clamscan_available(),
        "Vorbedingung fehlt: clamscan ist nicht installiert. Dieser Test ist als #[ignore] \
         markiert und darf nur dort mit --include-ignored laufen, wo ClamAV installiert ist."
    );
}
