//! End-to-End-Tests der echten `axsafe`-Binärdatei mit echten Engines.
//!
//! Testdaten werden zur Laufzeit in temporären Ordnern erzeugt. Es wird keine
//! Probe ausgeführt und keine Datei aus dem Internet geladen (T-009, T-028).

use md5::{Digest, Md5};
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_axsafe"))
}

fn rules() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules")
}

fn eicar() -> Vec<u8> {
    let a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
    let b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    format!("{a}{b}").into_bytes()
}

fn clamscan_available() -> bool {
    Command::new("clamscan")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn report(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn verdict_of<'a>(rep: &'a serde_json::Value, suffix: &str) -> &'a str {
    rep["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with(suffix))
        .unwrap_or_else(|| panic!("{suffix} fehlt im Bericht"))["verdict"]
        .as_str()
        .unwrap()
}

#[test]
fn yara_only_detects_eicar_and_ignores_names() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("daten");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("test.txt"), eicar()).unwrap();
    std::fs::write(
        data.join("eicar.com"),
        b"harmloser Inhalt mit verdaechtigem Namen",
    )
    .unwrap();
    std::fs::write(data.join("brief.txt"), b"Sehr geehrte Damen und Herren").unwrap();
    let json = dir.path().join("r.json");

    let out = Command::new(bin())
        .args(["scan", "--no-clamav", "--rules"])
        .arg(rules())
        .arg("--json")
        .arg(&json)
        .arg(&data)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("AXSafe.Test.EICAR (Testsignatur) via yara-x"),
        "{stdout}"
    );

    let rep = report(&json);
    assert_eq!(rep["schema"], "axsafe.scan-report/1");
    assert_eq!(rep["overall"], "Malicious");
    assert_eq!(rep["summary"]["objects"], 3);
    assert_eq!(rep["summary"]["detections"], 1);
    assert_eq!(verdict_of(&rep, "test.txt"), "Malicious");
    assert_eq!(verdict_of(&rep, "eicar.com"), "NoDetection");
    assert_eq!(verdict_of(&rep, "brief.txt"), "NoDetection");
    assert_eq!(rep["scope"]["engines"].as_array().unwrap().len(), 1);
    assert_eq!(rep["files"][0]["action"], "report_only");
}

#[test]
fn clean_scan_exit_zero_and_broken_rules_exit_two() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"nur Text").unwrap();
    let ok = Command::new(bin())
        .args(["scan", "--no-clamav", "--rules"])
        .arg(rules())
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(ok.status.code(), Some(0));

    // Defekter Regelsatz: nie „sauber“, sondern unvollständig (Exit 2).
    let bad = tempfile::tempdir().unwrap();
    std::fs::write(bad.path().join("x.yar"), "rule {").unwrap();
    let out = Command::new(bin())
        .args(["scan", "--no-clamav", "--rules"])
        .arg(bad.path())
        .arg(dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(2), "{stdout}");
    assert!(stdout.contains("NICHT VERFÜGBAR"), "{stdout}");
    assert!(stdout.contains("UNVOLLSTÄNDIG"), "{stdout}");
}

#[test]
fn missing_clamav_makes_scan_incomplete_not_clean() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"nur Text").unwrap();
    let out = Command::new(bin())
        .args(["scan", "--clamscan", "/nicht/vorhanden/clamscan", "--rules"])
        .arg(rules())
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn both_engines_detect_eicar_when_clamav_present() {
    if !clamscan_available() {
        eprintln!("clamscan nicht installiert: Test übersprungen (in CI Pflicht)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let e = eicar();
    let db = dir.path().join("axsafe-test.hdb");
    std::fs::write(
        &db,
        format!(
            "{}:{}:AXSafe.Test.EICAR.HDB\n",
            hex::encode(Md5::digest(&e)),
            e.len()
        ),
    )
    .unwrap();
    let data = dir.path().join("daten");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("probe.bin"), &e).unwrap();
    std::fs::write(data.join("ok.txt"), b"harmlos").unwrap();
    let json = dir.path().join("r.json");
    let out = Command::new(bin())
        .args(["scan", "--rules"])
        .arg(rules())
        .arg("--clamav-db")
        .arg(&db)
        .arg("--json")
        .arg(&json)
        .arg(&data)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    let rep = report(&json);
    let probe = rep["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with("probe.bin"))
        .unwrap();
    let engines: Vec<&str> = probe["engines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["verdict"] == "Malicious")
        .map(|e| e["engine"].as_str().unwrap())
        .collect();
    assert_eq!(engines, vec!["yara-x", "clamav"], "{probe}");
    assert_eq!(verdict_of(&rep, "ok.txt"), "NoDetection");
    assert_eq!(rep["complete"], true);
}

#[test]
fn filetype_uses_content_not_extension() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("rechnung.txt");
    std::fs::write(&p, b"%PDF-1.7\n").unwrap();
    let out = Command::new(bin())
        .arg("filetype")
        .arg(&p)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("pdf"));
}

#[test]
fn engines_json_reports_health() {
    let out = Command::new(bin())
        .args(["engines", "--json", "--no-clamav", "--rules"])
        .arg(rules())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["name"], "yara-x");
    assert_eq!(v[0]["health"]["state"], "ready");
}
