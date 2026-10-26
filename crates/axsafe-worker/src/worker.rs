//! Der Scanworker selbst: liest Aufträge von stdin, antwortet auf stdout.
//!
//! Ablauf: Rechte beschränken → `Init` (Regeltexte) → `Ready` → beliebig
//! viele `Scan`/`Probe` → Ende bei geschlossener Eingabe. Der Worker öffnet
//! keine Dateien und kennt keine Pfade der geprüften Objekte; er bekommt nur
//! Bytes. Testverhalten (Absturz, Hänger) gibt es hier bewusst NICHT.

use crate::protocol::*;
use crate::sandbox;
use axsafe_core::engine::{Engine, ScanInput};
use axsafe_engine_yarax::{YaraXEngine, YARAX_VERSION};
use axsafe_workerproto::run_probe;
use std::io::{self, Write};
use std::time::Duration;

fn send(out: &mut dyn Write, kind: u8, v: &impl serde::Serialize) -> io::Result<()> {
    let json = serde_json::to_vec(v).map_err(io::Error::other)?;
    write_frame(out, kind, &json)
}

fn fail(out: &mut dyn Write, msg: String) -> i32 {
    let _ = send(out, T_ERROR, &ErrorMsg { message: msg });
    2
}

/// Eingebaute Fehler – nur für das Testdoppel `axsafe-worker-testhelper`.
/// Das ausgelieferte `axsafe-worker` ruft [`worker_main`] auf, das keinen
/// Fehler einschaltet; es gibt keinen Schalter, der sie von außen aktiviert.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Fault {
    #[default]
    None,
    /// Beim Scan sofort abbrechen (Absturz).
    CrashOnScan,
    /// Beim Scan nie antworten.
    HangOnScan,
    /// Beim Scan einen unbekannten Antworttyp senden.
    GarbageOnScan,
    /// Beim Scan eine übergroße Antwortlänge ankündigen.
    OversizedOnScan,
    /// Regelsatz als abgelehnt melden (Neustart mit abgelehnten Regeln).
    RejectRules,
    /// Einen anderen Inhaltsstand melden (veränderter Regelstand).
    WrongContentVersion,
    /// Keine Abschottung anwenden und das melden; bei einem Scan wird die
    /// im zweiten Argument genannte Datei angelegt (Nachweis, dass keine
    /// Daten ankommen dürfen).
    NoSandbox,
    /// Beim Scan 2 GiB anfordern und beschreiben (Speichergrenze prüfen).
    AllocOnScan,
    /// Nur abstürzen, wenn die Nutzdaten genau [`CRASH_PAYLOAD`] sind
    /// (Wiederanlauf prüfen: danach arbeitet ein neuer Worker normal).
    CrashOnPayload,
}

/// Auslöser für [`Fault::CrashOnPayload`].
pub const CRASH_PAYLOAD: &[u8] = b"AXSAFE-TESTDOPPEL-ABSTURZ";

/// Einstiegspunkt des Binärprogramms `axsafe-worker`. Rückgabe: Exitcode.
pub fn worker_main() -> i32 {
    worker_main_with(Fault::None, None)
}

/// Wie [`worker_main`], mit eingebautem Fehler (nur Testdoppel).
pub fn worker_main_with(fault: Fault, marker: Option<std::path::PathBuf>) -> i32 {
    // Rechte beschränken, bevor irgendeine Eingabe gelesen wird.
    let sandbox = if fault == Fault::NoSandbox {
        crate::protocol::SandboxReport {
            kind: "none".into(),
            filesystem: false,
            network: false,
            detail: "Testdoppel ohne Abschottung".into(),
        }
    } else {
        sandbox::apply()
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut out = stdout.lock();

    if fault != Fault::NoSandbox && sandbox::required() && !(sandbox.filesystem && sandbox.network)
    {
        return fail(
            &mut out,
            format!(
                "Isolation fehlt, Worker verweigert die Arbeit: {}",
                sandbox.detail
            ),
        );
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
    let engine = YaraXEngine::from_sources(&init.rules);
    drop(init.rules);
    let mut rules = engine.stats();
    match fault {
        Fault::RejectRules => rules = Err("Testdoppel: Regelsatz abgelehnt".into()),
        Fault::WrongContentVersion => {
            if let Ok(st) = &mut rules {
                st.content_version = "rules-sha256:veraendert".into();
            }
        }
        _ => {}
    }
    let ready = Ready {
        protocol: PROTOCOL.into(),
        worker_version: env!("CARGO_PKG_VERSION").into(),
        engine_version: YARAX_VERSION.into(),
        sandbox,
        rules,
        env_names: std::env::vars_os()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect(),
    };
    if send(&mut out, T_READY, &ready).is_err() {
        return 2;
    }
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
            (T_SCAN, ref p)
                if fault != Fault::None && inject(fault, p, marker.as_deref(), &mut out) =>
            {
                return 2;
            }
            (T_SCAN, p) if p.len() >= 4 && p.len() <= max_scan => {
                let ms = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
                let data = &p[4..];
                // Typerkennung hier im abgeschotteten Worker, nicht im Host.
                let file_kind = axsafe_core::filetype::detect(data);
                let o = engine.scan(&ScanInput {
                    data,
                    kind: &file_kind,
                    sha256: "",
                    timeout: Duration::from_millis(u64::from(ms)),
                });
                send(
                    &mut out,
                    T_RESULT,
                    &ScanReply {
                        features: Some(axsafe_core::features::analyze(data, &file_kind)),
                        outcome: o,
                        file_kind,
                    },
                )
            }
            (T_SCAN, _) => return fail(&mut out, "Scan-Rahmen mit unzulässiger Länge".into()),
            (T_PROBE, p) => match serde_json::from_slice::<Probe>(&p) {
                Ok(pr) => send(&mut out, T_PROBE_RESULT, &run_probe(&pr)),
                Err(e) => return fail(&mut out, format!("Probe ungültig: {e}")),
            },
            (k, _) => return fail(&mut out, format!("unbekannter Nachrichtentyp {k:#x}")),
        };
        if res.is_err() {
            return 2;
        }
    }
}

/// Führt den eingebauten Fehler aus; `true` = Worker endet danach.
fn inject(
    fault: Fault,
    payload: &[u8],
    marker: Option<&std::path::Path>,
    out: &mut dyn Write,
) -> bool {
    match fault {
        Fault::None => false,
        Fault::CrashOnScan => std::process::abort(),
        Fault::RejectRules | Fault::WrongContentVersion => false,
        Fault::NoSandbox => {
            if let Some(m) = marker {
                let _ = std::fs::write(m, b"Scandaten erhalten");
            }
            false
        }
        Fault::CrashOnPayload => {
            if payload.get(4..) == Some(CRASH_PAYLOAD) {
                std::process::abort()
            }
            false
        }
        Fault::AllocOnScan => {
            let mut v: Vec<u8> = Vec::new();
            if v.try_reserve_exact(2 << 30).is_err() {
                // Grenze greift schon bei der Anforderung.
                std::process::abort();
            }
            v.resize(2 << 30, 1);
            let _ = write_frame(
                out,
                T_ERROR,
                b"{\"message\":\"Speichergrenze griff nicht\"}",
            );
            std::hint::black_box(&v);
            true
        }
        Fault::HangOnScan => loop {
            std::thread::sleep(Duration::from_secs(3600));
        },
        Fault::GarbageOnScan => {
            let _ = write_frame(out, 0x42, b"unsinn");
            // weiter lesen, als wäre nichts gewesen
            false
        }
        Fault::OversizedOnScan => {
            let _ = out.write_all(&u32::MAX.to_le_bytes());
            let _ = out.flush();
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
    }
}
