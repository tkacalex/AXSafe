//! Nachweise für Befund 4 mit dem harmlosen Testhelfer.
//! Laufen auf Linux und Windows (CI); plattformspezifische Erwartungen sind
//! ausdrücklich getrennt.

use axsafe_proc::{run, Limits};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn helper() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_axsafe-proc-testhelper"))
}

fn cmd(mode: &str, pid_file: Option<&Path>) -> Command {
    let mut c = Command::new(helper());
    c.arg(mode);
    if let Some(p) = pid_file {
        c.arg(p);
    }
    c
}

fn limits(ms: u64) -> Limits {
    Limits {
        timeout: Duration::from_millis(ms),
        ..Limits::default()
    }
}

fn read_pid(p: &Path) -> u32 {
    let s = std::fs::read_to_string(p).expect("pid-Datei");
    s.split_whitespace().next().unwrap().parse().unwrap()
}

#[cfg(target_os = "linux")]
fn alive(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => !matches!(
            s.rsplit_once(')')
                .and_then(|(_, r)| r.split_whitespace().next()),
            Some("Z")
        ),
        Err(_) => false,
    }
}

#[cfg(windows)]
fn alive(pid: u32) -> bool {
    let out = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .expect("tasklist");
    String::from_utf8_lossy(&out.stdout).contains(&format!("\"{pid}\""))
}

fn wait_dead(pid: u32) -> bool {
    for _ in 0..100 {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn ok_is_clean_success() {
    let o = run(cmd("ok", None), None, &limits(10_000)).unwrap();
    assert!(o.clean_success(), "{o:?}");
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "stdin: OK");
}

#[test]
fn hanging_process_hits_shared_deadline() {
    let o = run(cmd("hang", None), None, &limits(500)).unwrap();
    assert!(o.timed_out);
    assert!(!o.clean_success());
    assert!(o.elapsed < Duration::from_secs(3), "{:?}", o.elapsed);
}

#[test]
fn orphan_holding_pipes_does_not_extend_call_and_is_flagged() {
    // Befund 4: Elternprozess endet sofort, Nachkomme hält stdout/stderr offen.
    let dir = tempfile_dir();
    let pid_file = dir.join("orphan.pid");
    let o = run(cmd("orphan", Some(&pid_file)), None, &limits(1_000)).unwrap();
    assert!(
        o.elapsed < Duration::from_millis(1_500),
        "Aufruf dauerte {:?}",
        o.elapsed
    );
    assert!(
        o.descendants_terminated,
        "verbliebener Nachkomme muss erkannt werden: {o:?}"
    );
    assert!(
        !o.clean_success(),
        "Ergebnis mit verwaistem Nachkommen ist nicht sauber"
    );
    let gpid = read_pid(&pid_file);
    assert!(wait_dead(gpid), "Nachkomme {gpid} lebt noch");
}

#[cfg(target_os = "linux")]
#[test]
fn escaped_descendant_on_linux_is_bounded_by_deadline() {
    // Grenze der Unix-Variante: Ein Nachkomme in eigener Prozessgruppe
    // entkommt killpg. Dann greift das gemeinsame Ablaufdatum.
    let dir = tempfile_dir();
    let pid_file = dir.join("escape.pid");
    let o = run(cmd("escape", Some(&pid_file)), None, &limits(800)).unwrap();
    assert!(o.timed_out, "{o:?}");
    assert!(!o.clean_success());
    assert!(o.elapsed < Duration::from_millis(2_000), "{:?}", o.elapsed);
    // Aufräumen des absichtlich entkommenen Testprozesses.
    let gpid = read_pid(&pid_file);
    let _ = Command::new("kill")
        .args(["-9", &gpid.to_string()])
        .status();
}

#[cfg(windows)]
#[test]
fn breakaway_from_job_is_denied_and_tree_is_killed() {
    let dir = tempfile_dir();
    let pid_file = dir.join("escape.pid");
    let o = run(cmd("escape", Some(&pid_file)), None, &limits(5_000)).unwrap();
    let note = std::fs::read_to_string(&pid_file).unwrap();
    assert!(
        note.contains("breakaway_requested_denied"),
        "Breakaway darf nicht gelingen: {note}"
    );
    assert!(o.descendants_terminated, "{o:?}");
    assert!(!o.timed_out);
    assert!(o.elapsed < Duration::from_secs(3), "{:?}", o.elapsed);
    assert!(
        wait_dead(read_pid(&pid_file)),
        "Nachkomme im Job muss beendet sein"
    );
}

#[test]
fn output_flood_is_cut_off() {
    let mut l = limits(10_000);
    l.max_output_bytes = 256 * 1024;
    let o = run(cmd("flood", None), None, &l).unwrap();
    assert!(o.output_truncated);
    assert!(o.stdout.len() <= 256 * 1024);
    assert!(!o.clean_success());
    assert!(o.elapsed < Duration::from_secs(5), "{:?}", o.elapsed);
}

#[test]
fn memory_limit_stops_large_allocation() {
    let mut l = limits(20_000);
    l.max_memory_bytes = Some(256 * 1024 * 1024);
    let o = run(cmd("alloc", None), None, &l).unwrap();
    assert!(
        !o.clean_success(),
        "1 GiB unter 256-MiB-Grenze darf nicht gelingen: {o:?}"
    );
    assert!(!o.timed_out);
}

#[test]
fn memory_limit_allows_normal_allocation() {
    let mut l = limits(20_000);
    l.max_memory_bytes = Some(3 * 1024 * 1024 * 1024);
    let o = run(cmd("alloc", None), None, &l).unwrap();
    assert!(o.clean_success(), "{o:?}");
}

#[test]
fn crash_is_not_success() {
    let o = run(cmd("crash", None), None, &limits(10_000)).unwrap();
    assert!(!o.clean_success());
    assert!(!o.timed_out);
}

#[test]
fn large_stdin_is_fully_delivered_within_deadline() {
    // clamscan-artige Kopie liest stdin vollständig.
    let dir = tempfile_dir();
    let exe = dir.join(format!("clamscan-ok{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(helper(), &exe).unwrap();
    // ETXTBSY-Schutz (siehe clamav/tests/common): warten, bis startbar.
    for _ in 0..200 {
        if Command::new(&exe)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let data = vec![b'x'; 8 * 1024 * 1024];
    let o = run(Command::new(&exe), Some(data), &limits(20_000)).unwrap();
    assert!(o.clean_success(), "{o:?}");
    assert!(!o.stdin_incomplete);
}

#[test]
fn child_that_ignores_stdin_cannot_block_past_deadline() {
    // Direktmodus „hang“ liest stdin nicht: große Eingabe füllt die Pipe.
    let o = run(
        cmd("hang", None),
        Some(vec![b'x'; 16 * 1024 * 1024]),
        &limits(700),
    )
    .unwrap();
    assert!(o.timed_out);
    assert!(o.stdin_incomplete);
    assert!(o.elapsed < Duration::from_secs(3), "{:?}", o.elapsed);
}

fn tempfile_dir() -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "axsafe-proc-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}
