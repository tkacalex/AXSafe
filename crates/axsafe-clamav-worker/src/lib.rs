//! # axsafe-clamav-worker (Phase P02, B-18)
//!
//! Isolierter Prozess, der **libclamav einmal lädt** und danach beliebig
//! viele Objekte prüft. Er bekommt über stdin nur Bytes, nie Pfade, und
//! öffnet keine Benutzerdateien. Der Host (`axsafe-engine-clamav`,
//! [`protocol`]) startet ihn mit Rechtebeschränkung, weist die Abschottung
//! per Probe nach, begrenzt Zeit und Speicher und ersetzt ihn bei Absturz,
//! Hänger oder neuer Signaturdatenbank.
//!
//! Lizenz: libclamav ist GPL-2.0-only und wird zur Laufzeit aus der separat
//! installierten ClamAV-Installation geladen (nicht mitgeliefert). Dieses
//! Programm enthält nur GPL-2.0-verträgliche Abhängigkeiten
//! (docs/LICENSE-REVIEW-libclamav.md, `scripts/check_gpl_component.py`).

pub mod protocol;

mod ffi;
mod sandbox;

use protocol::*;
use std::io::{self, Write};
use std::time::Instant;

fn send(out: &mut dyn Write, kind: u8, v: &impl serde::Serialize) -> io::Result<()> {
    let json = serde_json::to_vec(v).map_err(io::Error::other)?;
    write_frame(out, kind, &json)
}

fn fail(out: &mut dyn Write, msg: String) -> i32 {
    let _ = send(out, T_ERROR, &ErrorMsg { message: msg });
    2
}

/// Eingebaute Fehler – nur für das Testdoppel `axsafe-clamav-worker-testhelper`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Fault {
    #[default]
    None,
    /// Abbruch, wenn die Nutzdaten genau [`CRASH_PAYLOAD`] sind.
    CrashOnPayload,
    /// Nie antworten, wenn die Nutzdaten genau [`HANG_PAYLOAD`] sind.
    HangOnPayload,
    /// Eine andere Datenbankversion melden (Neustart mit verändertem Stand).
    WrongDbVersion,
}

pub const CRASH_PAYLOAD: &[u8] = b"AXSAFE-TESTDOPPEL-ABSTURZ";
pub const HANG_PAYLOAD: &[u8] = b"AXSAFE-TESTDOPPEL-HAENGER";

/// Einstiegspunkt des Binärprogramms `axsafe-clamav-worker`.
pub fn worker_main() -> i32 {
    worker_main_with(Fault::None)
}

/// Wie [`worker_main`], mit eingebautem Fehler (nur Testdoppel).
pub fn worker_main_with(fault: Fault) -> i32 {
    let before = sandbox::before_input();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut out = stdout.lock();

    if let Some(r) = &before {
        if sandbox::required() && !r.filesystem {
            return fail(
                &mut out,
                format!(
                    "Isolation fehlt, Worker verweigert die Arbeit: {}",
                    r.detail
                ),
            );
        }
    }

    let init: Init = match read_frame(&mut input, MAX_CONTROL_BYTES) {
        Ok(Some((T_INIT, p))) => match serde_json::from_slice(&p) {
            Ok(i) => i,
            Err(e) => return fail(&mut out, format!("Init ungültig: {e}")),
        },
        Ok(Some((k, _))) => return fail(&mut out, format!("erwartet Init, erhalten Typ {k:#x}")),
        Ok(None) => return 0,
        Err(e) => return fail(&mut out, format!("Init nicht lesbar: {e}")),
    };
    if init.protocol != PROTOCOL {
        return fail(
            &mut out,
            format!(
                "Protokoll {} nicht unterstützt (erwartet {PROTOCOL})",
                init.protocol
            ),
        );
    }

    let started = Instant::now();
    let lib = match ffi::LibClamav::open(&init.library) {
        Ok(l) => l,
        Err(e) => return fail(&mut out, e),
    };
    let settings = ffi::EngineSettings {
        tempdir: &init.tempdir,
        max_filesize: init.max_filesize,
        max_scansize: init.max_scansize,
        max_recursion: init.max_recursion,
        max_files: init.max_files,
        max_scantime_ms: init.max_scantime_ms,
        certsdir: init.certsdir.as_deref(),
    };
    let loaded = ffi::Engine::load(&lib, &init.database, &settings);
    let (engine, database) = match loaded {
        Ok((e, sigs)) => {
            let mut v = e.get_num(ffi::CL_ENGINE_DB_VERSION).max(0) as u64;
            if fault == Fault::WrongDbVersion {
                v = v.wrapping_add(1);
            }
            let stats = DbStats {
                signatures: sigs,
                db_version: v,
                db_time: e.get_num(ffi::CL_ENGINE_DB_TIME),
                load_ms: started.elapsed().as_millis() as u64,
            };
            (Some(e), Ok(stats))
        }
        Err(e) => (None, Err(e)),
    };
    // Erst jetzt (Datenbank im Speicher): Linux beschränkt sich auf den
    // Arbeitsordner. Windows: Token wurde schon vor der Eingabe geprüft.
    let sandbox = sandbox::after_load(&init.tempdir, before);
    let ready = Ready {
        protocol: PROTOCOL.into(),
        worker_version: env!("CARGO_PKG_VERSION").into(),
        engine_version: lib.version(),
        flevel: lib.flevel(),
        sandbox,
        database,
        env_names: std::env::vars_os()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect(),
    };
    if send(&mut out, T_READY, &ready).is_err() {
        return 2;
    }
    let Some(engine) = engine else {
        // Datenbank nicht geladen: nur noch Probe/Ende beantworten ist sinnlos.
        return 0;
    };
    let max_scan = usize::try_from(init.max_scan_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(4);

    loop {
        let frame = match read_frame(&mut input, max_scan.max(MAX_CONTROL_BYTES)) {
            Ok(Some(f)) => f,
            Ok(None) => return 0,
            Err(e) => return fail(&mut out, format!("Rahmen nicht lesbar: {e}")),
        };
        let res = match frame {
            (T_SCAN, p) if p.len() >= 4 && p.len() <= max_scan => {
                let data = &p[4..];
                if fault == Fault::CrashOnPayload && data == CRASH_PAYLOAD {
                    std::process::abort();
                }
                if fault == Fault::HangOnPayload && data == HANG_PAYLOAD {
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(3600));
                    }
                }
                let t = Instant::now();
                let file_kind = axsafe_core::filetype::detect(data);
                let result = match engine.scan(data) {
                    Ok(None) => ScanResult::Clean,
                    Ok(Some(name)) => ScanResult::Virus { name },
                    Err((code, message)) => ScanResult::Error { code, message },
                };
                send(
                    &mut out,
                    T_RESULT,
                    &ScanReply {
                        result,
                        file_kind,
                        scan_ms: t.elapsed().as_millis() as u64,
                    },
                )
            }
            (T_SCAN, _) => return fail(&mut out, "Scan-Rahmen mit unzulässiger Länge".into()),
            (T_PROBE, p) => match serde_json::from_slice::<Probe>(&p) {
                Ok(pr) => send(
                    &mut out,
                    T_PROBE_RESULT,
                    &axsafe_workerproto::run_probe(&pr),
                ),
                Err(e) => return fail(&mut out, format!("Probe ungültig: {e}")),
            },
            (k, _) => return fail(&mut out, format!("unbekannter Nachrichtentyp {k:#x}")),
        };
        if res.is_err() {
            return 2;
        }
    }
}
