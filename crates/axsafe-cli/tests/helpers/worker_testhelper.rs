//! Testdoppel des Scanworkers mit eingebautem Fehler. NUR für Tests.
//!
//!   axsafe-worker-testhelper <crash|hang|alloc|garbage|oversized|crash-on-payload>

use axsafe_worker::{worker_main_with, Fault};

fn main() {
    let mut a = std::env::args().skip(1);
    let fault = match a.next().as_deref() {
        Some("crash") => Fault::CrashOnScan,
        Some("hang") => Fault::HangOnScan,
        Some("alloc") => Fault::AllocOnScan,
        Some("garbage") => Fault::GarbageOnScan,
        Some("oversized") => Fault::OversizedOnScan,
        Some("crash-on-payload") => Fault::CrashOnPayload,
        _ => Fault::None,
    };
    std::process::exit(worker_main_with(fault));
}
