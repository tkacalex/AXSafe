//! Testdoppel des Scanworkers mit eingebautem Fehler. NUR für Tests.
//!
//!   axsafe-worker-testhelper <crash|hang|alloc|garbage|oversized|crash-on-payload|reject-rules|wrong-content|no-sandbox> [marker]

use axsafe_worker::{worker_main_with, Fault};

fn main() {
    let mut a = std::env::args().skip(1);
    let fault = match a.next().as_deref() {
        Some("crash") => Fault::CrashOnScan,
        Some("hang") => Fault::HangOnScan,
        Some("alloc") => Fault::AllocOnScan,
        Some("reject-rules") => Fault::RejectRules,
        Some("wrong-content") => Fault::WrongContentVersion,
        Some("no-sandbox") => Fault::NoSandbox,
        Some("garbage") => Fault::GarbageOnScan,
        Some("oversized") => Fault::OversizedOnScan,
        Some("crash-on-payload") => Fault::CrashOnPayload,
        _ => Fault::None,
    };
    std::process::exit(worker_main_with(fault, a.next().map(Into::into)));
}
