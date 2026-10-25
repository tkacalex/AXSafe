//! `axsafe-service` – Windows-Dienst `AXSafeService` (Phase P02).
//!
//!   axsafe-service run        vom Dienststeuerungs-Manager gestartet
//!   axsafe-service --version
//!
//! Installation und Entfernung: scripts/windows/install-service.ps1 bzw.
//! uninstall-service.ps1 (Administrator).

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "--version" {
        println!("axsafe-service {}", axsafe_core::AXSAFE_VERSION);
        return;
    }
    #[cfg(windows)]
    {
        if arg == "run" {
            if let Err(e) = service::dispatch() {
                eprintln!("{e}");
                std::process::exit(1);
            }
            return;
        }
        eprintln!(
            "Aufruf: axsafe-service run (nur durch den Dienststeuerungs-Manager) | --version"
        );
        std::process::exit(2);
    }
    #[cfg(not(windows))]
    {
        eprintln!("Der AXSafe-Dienst ist nur unter Windows verfügbar ({arg}).");
        std::process::exit(2);
    }
}

#[cfg(windows)]
mod service {
    use axsafe_core::report::ScanLimits;
    use axsafe_engine_clamav::ClamAvConfig;
    use axsafe_service::handler::{ConnLimits, ServiceCtx};
    use axsafe_service::jobs::{JobLimits, JobManager};
    use axsafe_service::log::Log;
    use axsafe_service::runner::ServiceRunner;
    use axsafe_service::win::{run_server, scm};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Datenordner (Berichte, Protokoll); Rechte setzt das Installationsskript.
    pub fn data_dir() -> PathBuf {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("AXSafe")
            .join("Service")
    }

    pub fn dispatch() -> std::io::Result<()> {
        scm::dispatch(Box::new(body))
    }

    fn body(stop: Arc<AtomicBool>) -> std::io::Result<()> {
        let data = data_dir();
        let log = Arc::new(Log::new(Some(data.join("logs").join("service.log"))));
        let _ = std::fs::create_dir_all(data.join("logs"));
        let exe_dir = std::env::current_exe()?
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| std::io::Error::other("Programmordner unbekannt"))?;
        let (clamscan, database) = axsafe_engine_clamav::windows_default_paths();
        let runner = ServiceRunner {
            worker_exe: exe_dir.join("axsafe-worker.exe"),
            rules_dir: exe_dir.join("rules"),
            limits: ScanLimits::default(),
            clamav: ClamAvConfig {
                clamscan,
                database,
                ..ClamAvConfig::default()
            },
            log: Some(Arc::clone(&log)),
            clamav_worker: Some(exe_dir.join("axsafe-clamav-worker.exe")).filter(|p| p.is_file()),
            shared_clamav: Arc::new(Mutex::new(None)),
            policy_path: axsafe_core::policy::default_policy_path(),
        };
        log.line(match &runner.clamav_worker {
            Some(_) => "ClamAV: dauerhaft geladene Engine (axsafe-clamav-worker)",
            None => "ClamAV: axsafe-clamav-worker fehlt – clamscan je Objekt (langsam, B-18)",
        });
        log.line(&format!(
            "Dienst startet: {} (Programm {}, Daten {})",
            axsafe_core::AXSAFE_VERSION,
            exe_dir.display(),
            data.display()
        ));

        // Enginezustand im Hintergrund prüfen und regelmäßig auffrischen;
        // bis dahin meldet der Dienst „wird geprüft“, nie „bereit“.
        let engines: Arc<Mutex<Option<(Instant, serde_json::Value)>>> = Arc::new(Mutex::new(None));
        {
            let engines = Arc::clone(&engines);
            let runner = runner.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let infos: Vec<_> = runner.engines(true).iter().map(|e| e.info()).collect();
                    if let Ok(mut g) = engines.lock() {
                        *g = Some((
                            Instant::now(),
                            serde_json::to_value(infos).unwrap_or_default(),
                        ));
                    }
                    let t = Instant::now();
                    while t.elapsed() < Duration::from_secs(600) && !stop.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            });
        }
        let status_engines = Arc::clone(&engines);
        let status_runner = runner.clone();
        let status = Arc::new(move || {
            // AXS-019: Betriebszustand bei jeder Abfrage neu ableiten. ClamAV
            // (gemeinsame Engine) live, YARA-X aus der letzten Prüfung,
            // Richtlinie frisch gelesen und geprüft.
            let stored = status_engines.lock().ok().and_then(|g| g.clone());
            let mut infos: Option<Vec<axsafe_core::engine::EngineInfo>> = stored
                .as_ref()
                .and_then(|(_, v)| serde_json::from_value(v.clone()).ok());
            if let (Some(list), Some(_)) = (&mut infos, &status_runner.clamav_worker) {
                let live = axsafe_core::engine::Engine::info(&*status_runner.clamav_engine());
                if let Some(slot) = list.iter_mut().find(|e| e.name == "clamav") {
                    *slot = live;
                }
            }
            let health = axsafe_core::health::derive(
                infos.as_deref(),
                &axsafe_core::health::ServiceObservation::Ready,
                &status_runner.policy().observation(),
                chrono::Utc::now(),
            );
            match stored {
                Some((at, _)) => serde_json::json!({
                    "state": "geprüft",
                    "age_seconds": at.elapsed().as_secs(),
                    "list": infos,
                    "health": health,
                }),
                None => {
                    serde_json::json!({ "state": "wird geprüft", "list": [], "health": health })
                }
            }
        });
        let jobs = JobManager::start(JobLimits::default(), data.join("reports"), Arc::new(runner));
        let ctx = Arc::new(ServiceCtx::new(
            Arc::clone(&jobs),
            status,
            ConnLimits::default(),
        ));

        let server_stop = Arc::clone(&stop);
        let server_ctx = Arc::clone(&ctx);
        let server_log = Arc::clone(&log);
        let server = std::thread::spawn(move || {
            run_server(server_ctx, server_stop, 8, server_log, &|| scm::running())
        });
        while !stop.load(Ordering::SeqCst) && !server.is_finished() {
            std::thread::sleep(Duration::from_millis(200));
        }
        ctx.shutting_down.store(true, Ordering::SeqCst);
        jobs.shutdown();
        stop.store(true, Ordering::SeqCst);
        let r = server
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("Server-Thread abgestürzt")));
        log.line(&format!("Dienst beendet: {r:?}"));
        r
    }
}
