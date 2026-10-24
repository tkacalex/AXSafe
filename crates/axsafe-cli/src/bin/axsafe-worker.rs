//! Isolierter Scanworker von AXSafe (Phase P02). Wird vom Host gestartet;
//! nicht für den direkten Aufruf gedacht. Siehe crate `axsafe-worker`.

fn main() {
    std::process::exit(axsafe_worker::worker_main());
}
