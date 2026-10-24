//! Harmloser Helferprozess NUR für Tests. Wird nie paketiert.
//!
//! Aufruf direkt: `axsafe-proc-testhelper <modus> [pid-datei]`
//! oder als Kopie mit Dateinamen `…-<modus>[.exe]`; dann verhält er sich wie
//! ein minimales `clamscan` (`--version`, Eingabe über stdin). Leere Eingabe
//! (Funktionstest des Adapters) wird immer mit „stdin: OK“ beantwortet,
//! damit der Testfall erst beim eigentlichen Scan greift.
//!
//! Modi: ok, found, error, hang, orphan, escape, flood, alloc, crash, sleeper.
//! Alle Modi sind harmlos: Sie schlafen, schreiben auf stdout/stderr,
//! belegen Speicher oder starten eine Kopie von sich selbst.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

const MODES: [&str; 10] = [
    "ok", "found", "error", "hang", "orphan", "escape", "flood", "alloc", "crash", "sleeper",
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let exe = std::env::current_exe().expect("eigener Pfad");
    let (mode, clamscan_style, pid_file) = if args.len() > 1 && MODES.contains(&args[1].as_str()) {
        (args[1].clone(), false, args.get(2).map(PathBuf::from))
    } else {
        let stem = exe.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let mode = stem.rsplit('-').next().unwrap_or("ok").to_string();
        let pid = exe.with_file_name(format!("{mode}.pid"));
        (mode, true, Some(pid))
    };

    if clamscan_style {
        if args.iter().any(|a| a == "--version") {
            println!("ClamAV 0.0-test");
            return;
        }
        let mut input = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut input);
        if input.is_empty() {
            println!("stdin: OK");
            return;
        }
    }

    match mode.as_str() {
        "ok" => println!("stdin: OK"),
        "found" => {
            println!("stdin: AXSafe.Test.Helper FOUND");
            std::process::exit(1);
        }
        "error" => {
            eprintln!("LibClamAV Error: Testfehler des Helfers");
            std::process::exit(2);
        }
        "hang" | "sleeper" => std::thread::sleep(Duration::from_secs(30)),
        "orphan" => {
            // Nachkomme erbt stdout/stderr und hält die Pipes offen;
            // der Hauptprozess endet sofort mit einem „sauberen“ Ergebnis.
            let child = Command::new(&exe)
                .arg("sleeper")
                .stdin(Stdio::null())
                .spawn()
                .expect("Nachkomme");
            if let Some(p) = pid_file {
                std::fs::write(p, child.id().to_string()).expect("pid-Datei");
            }
            println!("stdin: OK");
            std::mem::forget(child);
        }
        "escape" => {
            let mut cmd = Command::new(&exe);
            cmd.arg("sleeper").stdin(Stdio::null());
            let attempt = escape_attempt(&mut cmd);
            let (child, note) = match cmd.spawn() {
                Ok(c) => (c, format!("{attempt}_ok")),
                // Windows: Breakaway verweigert → normal (im Job) starten.
                Err(_) => (
                    Command::new(&exe)
                        .arg("sleeper")
                        .stdin(Stdio::null())
                        .spawn()
                        .expect("Nachkomme"),
                    format!("{attempt}_denied"),
                ),
            };
            if let Some(p) = pid_file {
                std::fs::write(p, format!("{} {note}", child.id())).expect("pid-Datei");
            }
            println!("stdin: OK");
            std::mem::forget(child);
        }
        "flood" => {
            let chunk = vec![b'A'; 64 * 1024];
            let mut out = std::io::stdout().lock();
            loop {
                if out.write_all(&chunk).is_err() {
                    return;
                }
            }
        }
        "alloc" => {
            // 1 GiB anfordern und berühren; scheitert unter einer Speichergrenze.
            let mut v: Vec<u8> = Vec::new();
            if v.try_reserve_exact(1 << 30).is_err() {
                eprintln!("Speicheranforderung abgelehnt");
                std::process::exit(3);
            }
            v.resize(1 << 30, 1);
            println!("stdin: OK {}", v[v.len() - 1]);
        }
        "crash" => std::process::abort(),
        other => {
            eprintln!("unbekannter Modus {other}");
            std::process::exit(64);
        }
    }
}

#[cfg(unix)]
fn escape_attempt(cmd: &mut Command) -> &'static str {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0); // verlässt die Prozessgruppe des Elternprozesses
    "new_process_group"
}

#[cfg(windows)]
fn escape_attempt(cmd: &mut Command) -> &'static str {
    use std::os::windows::process::CommandExt;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    cmd.creation_flags(CREATE_BREAKAWAY_FROM_JOB);
    "breakaway_requested"
}
