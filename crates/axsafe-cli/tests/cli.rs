//! End-to-End-Tests der echten `axsafe`-Binärdatei.
//!
//! Testdaten werden zur Laufzeit in temporären Ordnern erzeugt. Es wird keine
//! Probe ausgeführt und keine Datei aus dem Internet geladen (T-009, T-028).
//! Tests mit externen Vorbedingungen (echtes ClamAV, Windows-Symlinkrecht)
//! sind `#[ignore]` mit Grund und laufen in der CI mit `--include-ignored`.

use md5::{Digest, Md5};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

fn sha(p: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(p).unwrap()))
}

fn scan(args: &[&str], extra: &[&Path]) -> Output {
    let mut c = Command::new(bin());
    c.arg("scan")
        .arg("--rules")
        .arg(rules())
        .arg("--ohne-fortsetzung")
        .args(args);
    for p in extra {
        c.arg(p);
    }
    c.output().unwrap()
}

fn report(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn file_entry<'a>(rep: &'a serde_json::Value, suffix: &str) -> &'a serde_json::Value {
    rep["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with(suffix))
        .unwrap_or_else(|| panic!("{suffix} fehlt im Bericht"))
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// Befund 1: Berichtsziel überschreibt nie vorhandene Objekte
// ---------------------------------------------------------------------------

#[test]
fn report_target_equal_to_scan_object_is_refused_and_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("nutz.txt");
    std::fs::write(&f, b"Wichtige Nutzdaten\n").unwrap();
    let before = sha(&f);
    let o = scan(&["--no-clamav", "--json", f.to_str().unwrap()], &[&f]);
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    assert!(stderr(&o).contains("existiert bereits"));
    assert_eq!(sha(&f), before, "Inhalt wurde verändert");
}

#[test]
fn report_target_hardlink_to_scan_object_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("nutz.txt");
    std::fs::write(&f, b"Nutzdaten").unwrap();
    let link = dir.path().join("bericht.json");
    std::fs::hard_link(&f, &link).unwrap();
    let before = sha(&f);
    let o = scan(&["--no-clamav", "--json", link.to_str().unwrap()], &[&f]);
    assert_eq!(o.status.code(), Some(3));
    assert_eq!(sha(&f), before);
    assert_eq!(sha(&link), before);
}

#[test]
fn report_target_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("ordner");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
    let o = scan(
        &["--no-clamav", "--json", sub.to_str().unwrap()],
        &[dir.path()],
    );
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    assert!(sub.is_dir());
}

#[cfg(unix)]
#[test]
fn report_target_symlink_and_dangling_symlink_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("nutz.txt");
    std::fs::write(&f, b"Nutzdaten").unwrap();
    let before = sha(&f);
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&f, &link).unwrap();
    let o = scan(&["--no-clamav", "--json", link.to_str().unwrap()], &[&f]);
    assert_eq!(o.status.code(), Some(3));
    assert_eq!(sha(&f), before);

    let target = dir.path().join("noch-nicht-da.txt");
    let dangling = dir.path().join("dangling.json");
    std::os::unix::fs::symlink(&target, &dangling).unwrap();
    let o = scan(
        &["--no-clamav", "--json", dangling.to_str().unwrap()],
        &[&f],
    );
    assert_eq!(o.status.code(), Some(3));
    assert!(!target.exists(), "Linkziel darf nicht angelegt werden");
}

#[test]
fn new_report_inside_scan_root_is_excluded_by_identity() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"harmlos").unwrap();
    let rep_path = dir.path().join("bericht.json");
    let o = scan(
        &["--no-clamav", "--json", rep_path.to_str().unwrap()],
        &[dir.path()],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
    let rep = report(&rep_path);
    assert_eq!(
        rep["summary"]["objects_total"], 1,
        "nur a.txt, nicht der eigene Bericht"
    );
    assert_eq!(rep["scope"]["excluded"].as_array().unwrap().len(), 1);
}

#[cfg(windows)]
#[test]
fn report_via_junction_into_scan_root_is_excluded_and_junction_target_refused() {
    // Junctions brauchen kein Sonderrecht (mklink /J).
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("daten");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("a.txt"), b"harmlos").unwrap();
    let junction = dir.path().join("j");
    let st = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&data)
        .status()
        .unwrap();
    assert!(st.success(), "mklink /J fehlgeschlagen");
    // Bericht über die Junction in den gescannten Ordner: wird ausgeschlossen.
    let via = junction.join("bericht.json");
    let o = scan(&["--no-clamav", "--json", via.to_str().unwrap()], &[&data]);
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
    let rep = report(&data.join("bericht.json"));
    assert_eq!(rep["summary"]["objects_total"], 1);
    assert_eq!(rep["scope"]["excluded"].as_array().unwrap().len(), 1);
    // Die Junction selbst als Berichtsziel: abgelehnt.
    let o = scan(
        &["--no-clamav", "--json", junction.to_str().unwrap()],
        &[&data],
    );
    assert_eq!(o.status.code(), Some(3));
}

#[cfg(windows)]
#[test]
#[ignore = "benötigt Recht zum Anlegen symbolischer Links (Windows-CI: Administrator)"]
fn report_target_windows_symlink_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("nutz.txt");
    std::fs::write(&f, b"Nutzdaten").unwrap();
    let before = sha(&f);
    let link = dir.path().join("link.json");
    std::os::windows::fs::symlink_file(&f, &link)
        .expect("Vorbedingung: Symlink-Recht fehlt (Test nur mit --include-ignored als Admin)");
    let o = scan(&["--no-clamav", "--json", link.to_str().unwrap()], &[&f]);
    assert_eq!(o.status.code(), Some(3));
    assert_eq!(sha(&f), before);
}

// ---------------------------------------------------------------------------
// Befund 2, 3, 6: Fund/Abdeckung, Container, leere Aufträge; Exitcodes
// ---------------------------------------------------------------------------

#[test]
fn yara_detects_eicar_and_ignores_names() {
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
    let o = scan(&["--no-clamav", "--json", json.to_str().unwrap()], &[&data]);
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    assert!(stdout(&o).contains("Fund: AXSafe.Test.EICAR (Testsignatur) via yara-x"));
    let rep = report(&json);
    assert_eq!(rep["schema"], "axsafe.scan-report/2");
    assert_eq!(rep["outcome"], "detection");
    assert_eq!(rep["complete"], true);
    assert_eq!(file_entry(&rep, "test.txt")["status"], "detection");
    assert_eq!(file_entry(&rep, "eicar.com")["status"], "no_detection");
    assert_eq!(file_entry(&rep, "brief.txt")["status"], "no_detection");
}

#[test]
fn test_only_rules_are_flagged_loudly() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
    let o = scan(&["--no-clamav"], &[dir.path()]);
    assert!(
        stdout(&o).contains("ausschließlich Funktionstest-Regeln"),
        "{}",
        stdout(&o)
    );
    assert!(stdout(&o).contains("KEINE echte Schadsoftware"));
}

#[cfg(unix)]
fn fake_clamscan(dir: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("fake-clamscan");
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ClamAV 0.0-test'; exit 0; fi\n\
             n=$(cat | wc -c)\nif [ \"$n\" -eq 0 ]; then echo 'stdin: OK'; exit 0; fi\n{body}\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    for _ in 0..200 {
        if Command::new(&p)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return p;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("Testskript nicht startbar");
}

#[cfg(unix)]
#[test]
fn detection_plus_engine_error_is_exit_4_and_visible() {
    // Befund 2 Ende-zu-Ende.
    let dir = tempfile::tempdir().unwrap();
    let fake = fake_clamscan(dir.path(), "echo 'LibClamAV Error: Test' >&2; exit 2");
    let data = dir.path().join("d");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("e.com"), eicar()).unwrap();
    let json = dir.path().join("r.json");
    let o = scan(
        &[
            "--clamscan",
            fake.to_str().unwrap(),
            "--json",
            json.to_str().unwrap(),
        ],
        &[&data],
    );
    assert_eq!(o.status.code(), Some(4), "{}", stdout(&o));
    assert!(stdout(&o).contains("FUND + LÜCKE"));
    let rep = report(&json);
    assert_eq!(rep["outcome"], "detection_incomplete");
    assert_eq!(rep["complete"], false);
    assert_eq!(rep["summary"]["with_detection"], 1);
    assert_eq!(rep["summary"]["incomplete"], 1);
    assert_eq!(rep["summary"]["detection_and_incomplete"], 1);
    let f = file_entry(&rep, "e.com");
    assert_eq!(f["detection"], "Malicious");
    assert_eq!(f["gaps"][0]["state"], "Error");
}

#[test]
fn archives_without_container_engine_are_incomplete() {
    // Befund 3 Ende-zu-Ende ohne ClamAV: ZIP-Signatur reicht.
    let dir = tempfile::tempdir().unwrap();
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&[0u8; 80]);
    std::fs::write(dir.path().join("a.zip"), &zip).unwrap();
    let json = dir.path().join("r.json");
    let o = scan(
        &["--no-clamav", "--json", json.to_str().unwrap()],
        &[&dir.path().join("a.zip")],
    );
    assert_eq!(o.status.code(), Some(2), "{}", stdout(&o));
    let rep = report(&json);
    assert_eq!(rep["outcome"], "incomplete");
    let g = &file_entry(&rep, "a.zip")["gaps"][0];
    assert_eq!(g["reason"], "content_not_inspected");
    assert_eq!(g["state"], "Unsupported");
}

#[test]
fn empty_folder_is_nothing_scanned_exit_5() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("leer");
    std::fs::create_dir(&empty).unwrap();
    let json = dir.path().join("r.json");
    let o = scan(
        &[
            "--clamscan",
            "/nicht/vorhanden/clamscan",
            "--json",
            json.to_str().unwrap(),
        ],
        &[&empty],
    );
    assert_eq!(o.status.code(), Some(5), "{}", stdout(&o));
    assert!(stdout(&o).contains("Keine prüfbaren Objekte"));
    let rep = report(&json);
    assert_eq!(rep["outcome"], "nothing_scanned");
    assert_eq!(rep["complete"], false);
    assert_eq!(rep["job_gaps"][0]["reason"], "engine_unavailable");
}

#[test]
fn clean_scan_exit_zero_and_broken_rules_exit_two() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"nur Text").unwrap();
    let ok = scan(&["--no-clamav"], &[dir.path()]);
    assert_eq!(ok.status.code(), Some(0), "{}", stdout(&ok));

    let bad = tempfile::tempdir().unwrap();
    std::fs::write(bad.path().join("x.yar"), "rule {").unwrap();
    let o = Command::new(bin())
        .args(["scan", "--no-clamav", "--rules"])
        .arg(bad.path())
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", stdout(&o));
    assert!(stdout(&o).contains("NICHT VERFÜGBAR"));
}

#[test]
fn missing_clamav_makes_scan_incomplete_not_clean() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"nur Text").unwrap();
    let o = scan(&["--clamscan", "/nicht/vorhanden/clamscan"], &[dir.path()]);
    assert_eq!(o.status.code(), Some(2));
}

// ---------------------------------------------------------------------------
// Befund 5 (CLI-Teil): Auftragskennung
// ---------------------------------------------------------------------------

#[test]
fn job_id_is_taken_over_and_invalid_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
    let json = dir.path().join("r.json");
    let id = "0b7c3f7a-3a52-4c64-9a0e-6c2b9e1f4d11";
    let o = scan(
        &[
            "--no-clamav",
            "--job-id",
            id,
            "--json",
            json.to_str().unwrap(),
        ],
        &[dir.path()],
    );
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(report(&json)["job_id"], id);
    let json2 = dir.path().join("r2.json");
    let o = scan(
        &[
            "--no-clamav",
            "--job-id",
            "kein-uuid",
            "--json",
            json2.to_str().unwrap(),
        ],
        &[dir.path()],
    );
    assert_eq!(o.status.code(), Some(3));
    assert!(!json2.exists(), "bei ungültigem Auftrag kein Bericht");
}

// ---------------------------------------------------------------------------
// Echte Engines
// ---------------------------------------------------------------------------

#[test]
#[ignore = "benötigt clamscan (Linux-CI: Pflicht)"]
fn both_engines_detect_eicar_with_real_clamav() {
    assert!(
        Command::new("clamscan")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
        "Vorbedingung fehlt: clamscan nicht installiert"
    );
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
    let o = scan(
        &[
            "--clamav-db",
            db.to_str().unwrap(),
            "--json",
            json.to_str().unwrap(),
        ],
        &[&data],
    );
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    let rep = report(&json);
    let probe = file_entry(&rep, "probe.bin");
    let engines: Vec<&str> = probe["engines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["verdict"] == "Malicious")
        .map(|e| e["engine"].as_str().unwrap())
        .collect();
    assert_eq!(engines, vec!["yara-x", "clamav"], "{probe}");
    assert_eq!(file_entry(&rep, "ok.txt")["status"], "no_detection");
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
fn engines_json_reports_health_content_and_capabilities() {
    let out = Command::new(bin())
        .args(["engines", "--json", "--no-clamav", "--rules"])
        .arg(rules())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["name"], "yara-x");
    assert_eq!(v[0]["health"]["state"], "ready");
    assert_eq!(v[0]["content_kind"], "test_only");
    assert_eq!(v[0]["inspects_contents_of"].as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// AXS-016 / T-016: Befund nachvollziehbar vom Ereignis bis zur Aktion
// ---------------------------------------------------------------------------

/// Ein Fund trägt Auftrags-ID, UTC-Zeit samt Zeitzone, ausführenden Prozess
/// (PID UND Startzeit), Dateiidentität, Regel, Engine- und Regelversion und
/// die ausgeführte Aktion.
#[test]
fn detection_is_traceable_from_event_to_action() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("daten");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("test.txt"), eicar()).unwrap();
    let json = dir.path().join("r.json");
    let o = scan(
        &[
            "--no-clamav",
            "--job-id",
            "6f1d2a3b-0000-4000-8000-000000000016",
            "--json",
            json.to_str().unwrap(),
        ],
        &[&data],
    );
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    let rep = report(&json);
    assert_eq!(rep["job_id"], "6f1d2a3b-0000-4000-8000-000000000016");
    assert!(rep["started_utc"].as_str().unwrap().ends_with('Z'));
    let off = rep["utc_offset"].as_str().unwrap();
    assert!(off.starts_with('+') || off.starts_with('-'), "{off}");
    let by = &rep["executed_by"];
    assert_eq!(by["kind"], "cli");
    let p = &by["process"];
    assert!(p["pid"].as_u64().unwrap() > 0, "{by}");
    assert!(p["started_utc"].as_str().unwrap().ends_with('Z'), "{by}");
    let f = file_entry(&rep, "test.txt");
    assert!(f["identity"].is_object(), "Dateiidentität fehlt: {f}");
    assert!(f["sha256"].as_str().unwrap().len() == 64);
    assert!(f["scanned_utc"].as_str().unwrap().ends_with('Z'));
    let e = f["engines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| !e["detections"].as_array().unwrap().is_empty())
        .expect("Engine mit Fund");
    assert!(!e["engine_version"].as_str().unwrap().is_empty());
    assert!(e["content_version"]
        .as_str()
        .unwrap()
        .starts_with("rules-sha256:"));
    assert_eq!(e["detections"][0]["rule_id"], "AXS-TEST-0001");
    assert_eq!(e["detections"][0]["name"], "AXSafe.Test.EICAR");
    // Aktion: diese Vorversion meldet nur.
    assert!(f["action"].is_string() || f["action"].is_object(), "{f}");
}

// ---------------------------------------------------------------------------
// AXS-026: Scanarten, Fortschritt, Abbruch und Fortsetzen
// ---------------------------------------------------------------------------

/// Echter Abbruch (Prozess wird hart beendet), Änderung einer bereits
/// geprüften Datei, Fortsetzen: Unverändertes wird übernommen, Geändertes
/// neu geprüft, nichts fehlt, die Fortsetzungsdatei wird danach entfernt.
#[test]
fn killed_scan_resumes_and_rescans_changed_files() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("daten");
    std::fs::create_dir(&data).unwrap();
    for i in 0..3000 {
        std::fs::write(data.join(format!("f{i:04}.txt")), format!("inhalt {i}")).unwrap();
    }
    let cp = dir.path().join("fortsetzung.jsonl");
    let mut child = Command::new(bin())
        .arg("scan")
        .arg("--rules")
        .arg(rules())
        .arg("--no-clamav")
        .arg("--fortsetzungsdatei")
        .arg(&cp)
        .arg(&data)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let lines = std::fs::read_to_string(&cp)
            .map(|t| t.lines().count())
            .unwrap_or(0);
        if lines > 60 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Fortsetzungsdatei wächst nicht"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "Scan zu schnell fertig für den Test"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    child.kill().unwrap();
    let _ = child.wait();
    let text = std::fs::read_to_string(&cp).unwrap();
    let done: Vec<String> = text
        .lines()
        .skip(1)
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| v["path"].as_str().unwrap().to_string())
        .collect();
    assert!(done.len() >= 60);
    // Eine bereits geprüfte Datei nach dem Abbruch ändern.
    std::fs::write(&done[0], "geändert nach Abbruch").unwrap();

    let rep_path = dir.path().join("bericht.json");
    let o = Command::new(bin())
        .arg("scan")
        .arg("--rules")
        .arg(rules())
        .arg("--no-clamav")
        .arg("--fortsetzen")
        .arg(&cp)
        .arg("--fortsetzungsdatei")
        .arg(dir.path().join("neu.jsonl"))
        .arg("--json")
        .arg(&rep_path)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    let rep = report(&rep_path);
    assert_eq!(rep["summary"]["objects_total"], 3000);
    let info = &rep["scope"]["resume"];
    let reused = info["reused"].as_u64().unwrap();
    assert!(reused >= done.len() as u64 - 1, "{info}");
    assert!(reused < 3000);
    assert_eq!(info["version_mismatch"], false);
    let changed = file_entry(&rep, &done[0]);
    assert!(
        !changed["notes"].to_string().contains("Fortsetzung"),
        "geänderte Datei darf nicht übernommen werden: {changed}"
    );
    let same = file_entry(&rep, &done[1]);
    assert!(same["notes"].to_string().contains("Fortsetzung"), "{same}");
    assert!(
        !cp.exists(),
        "alte Fortsetzungsdatei nach vollständigem Lauf entfernt"
    );
    assert!(!dir.path().join("neu.jsonl").exists());
}

#[test]
fn quick_scan_covers_downloads_and_states_its_limits() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join("Downloads")).unwrap();
    std::fs::write(home.join("Downloads").join("geladen.txt"), "harmlos").unwrap();
    let tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let rep_path = dir.path().join("bericht.json");
    let o = Command::new(bin())
        .args([
            "scan",
            "--art",
            "schnell",
            "--ausloeser",
            "zeitplan",
            "--no-clamav",
            "--ohne-fortsetzung",
        ])
        .arg("--rules")
        .arg(rules())
        .arg("--json")
        .arg(&rep_path)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("TMPDIR", &tmp)
        .env("TEMP", &tmp)
        .env("TMP", &tmp)
        .env_remove("APPDATA")
        .env_remove("ProgramData")
        .env_remove("PUBLIC")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    let rep = report(&rep_path);
    assert_eq!(rep["scope"]["kind"], "quick");
    assert_eq!(rep["scope"]["trigger"], "schedule");
    assert!(rep["scope"]["kind_note"]
        .as_str()
        .unwrap()
        .contains("Nicht geprüft"));
    file_entry(&rep, "geladen.txt");
    assert!(rep["scope"]["missing_targets"]
        .to_string()
        .contains("Desktop"));
}

#[test]
fn scan_kind_errors_are_explicit() {
    let o = scan(&["--art", "irgendwas"], &[]);
    assert_eq!(o.status.code(), Some(3));
    let o = scan(&[], &[]);
    assert_eq!(o.status.code(), Some(3), "ohne Pfade kein stiller Leerlauf");
    #[cfg(not(windows))]
    {
        let o = scan(&["--art", "voll", "--no-clamav"], &[]);
        assert_eq!(o.status.code(), Some(3));
        assert!(stderr(&o).contains("nur unter Windows"));
    }
}

#[test]
fn json_progress_lines_are_machine_readable() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..1500 {
        std::fs::write(dir.path().join(format!("{i}.txt")), "x").unwrap();
    }
    let o = scan(&["--no-clamav", "--fortschritt-json"], &[dir.path()]);
    assert!(o.status.success(), "{}", stderr(&o));
    let lines: Vec<serde_json::Value> = stderr(&o)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v.get("fortschritt").is_some())
        .collect();
    // Bei sehr schnellen Läufen kann es keine Zwischenmeldung geben; wenn
    // es welche gibt, müssen sie wohlgeformt und steigend sein.
    let mut last = 0;
    for l in &lines {
        let n = l["fortschritt"]["objekte"].as_u64().unwrap();
        assert!(n > last);
        last = n;
        assert!(
            l["fortschritt"]["gesamt"].is_null()
                || l["fortschritt"]["gesamt"].as_u64().unwrap() >= 1500
        );
    }
}

#[test]
fn rules_command_lists_id_version_origin_and_test_flag() {
    let o = Command::new(bin())
        .args(["regeln", "--json", "--rules"])
        .arg(rules())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let r = &v["rules"][0];
    assert_eq!(r["id"], "AXS-TEST-0001");
    assert_eq!(r["version"], "1.0.0");
    assert_eq!(r["test"], true);
    assert_eq!(v["content_kind"], "test_only");
    assert!(!r["source"].as_str().unwrap().is_empty());
}
