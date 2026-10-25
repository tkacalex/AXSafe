//! Testdoppel des ClamAV-Workers mit eingebauten Fehlern – NUR für Tests,
//! wird nie ausgeliefert (die Inventarprüfung lehnt "testhelper" ab).
//!
//!   axsafe-clamav-worker-testhelper <crash|hang|wrong-db|normal>
//!
//! Der Fehler greift nur bei festgelegten Nutzdaten (CRASH_PAYLOAD,
//! HANG_PAYLOAD) bzw. beim Melden des Datenbankstands; sonst arbeitet das
//! Testdoppel wie der echte Worker mit der echten libclamav.

use axsafe_clamav_worker::{worker_main_with, Fault};

fn main() {
    let fault = match std::env::args().nth(1).as_deref() {
        Some("crash") => Fault::CrashOnPayload,
        Some("hang") => Fault::HangOnPayload,
        Some("wrong-db") => Fault::WrongDbVersion,
        _ => Fault::None,
    };
    std::process::exit(worker_main_with(fault));
}
