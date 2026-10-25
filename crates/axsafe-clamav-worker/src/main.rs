//! Isolierter ClamAV-Worker von AXSafe. Wird vom Host gestartet; nicht für
//! den direkten Aufruf gedacht. Siehe crate `axsafe-clamav-worker`.

fn main() {
    std::process::exit(axsafe_clamav_worker::worker_main());
}
