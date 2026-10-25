//! Isolierter Scanworker von AXSafe (Phase P02). Wird vom Host gestartet;
//! nicht für den direkten Aufruf gedacht. Siehe crate `axsafe-worker`.

fn main() {
    // Zugriffsprobe für die ClamAV-Abschottung (wird mit dem eingeschränkten
    // Token gestartet, siehe `axsafe clamav-abschottung`).
    if std::env::args().nth(1).as_deref() == Some("--zugriffsprobe") {
        std::process::exit(axsafe_worker::probe::access_probe_main(
            std::env::args().skip(2),
        ));
    }
    std::process::exit(axsafe_worker::worker_main());
}
