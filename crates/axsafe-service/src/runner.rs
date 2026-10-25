//! Echte Auftragsausführung im Dienst.
//!
//! * Dateien werden mit den Rechten des Auftraggebers gelesen
//!   ([`JobSpec::access`], Windows-Impersonation).
//! * Typerkennung und YARA-X laufen im abgeschotteten Worker; der Dienst
//!   parst keine Dateiinhalte.
//! * ClamAV läuft – wenn beauftragt – im AppContainer (siehe
//!   axsafe-engine-clamav); scheitert die Abschottung, ist ClamAV nicht
//!   verfügbar (Lücke), nie unbeschränkt.

use crate::jobs::{JobRunner, JobSpec};
use axsafe_core::engine::Engine;
use axsafe_core::report::{ScanLimits, ScanReport};
use axsafe_core::scan::{NoProgress, Scanner};
use axsafe_engine_clamav::{ClamAvConfig, ClamAvEngine};
use axsafe_worker::host::{WorkerConfig, WorkerEngine};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

#[derive(Debug, Clone)]
pub struct ServiceRunner {
    pub worker_exe: PathBuf,
    pub rules_dir: PathBuf,
    pub limits: ScanLimits,
    pub clamav: ClamAvConfig,
}

impl ServiceRunner {
    /// Engines für einen Auftrag (frisch je Auftrag: eigener Worker).
    pub fn engines(&self, use_clamav: bool) -> Vec<Box<dyn Engine>> {
        let mut cfg = WorkerConfig::new(
            self.worker_exe.clone(),
            axsafe_engine_yarax::read_rule_sources(&self.rules_dir),
        );
        cfg.max_scan_bytes = self.limits.max_file_size;
        cfg.memory_bytes = Some(axsafe_worker::host::memory_for(self.limits.max_file_size));
        let mut v: Vec<Box<dyn Engine>> = vec![Box::new(WorkerEngine::start(cfg))];
        if use_clamav {
            v.push(Box::new(ClamAvEngine::new(self.clamav.clone())));
        }
        v
    }
}

impl JobRunner for ServiceRunner {
    fn run(&self, job: &JobSpec, cancel: &AtomicBool) -> Result<ScanReport, String> {
        let scanner = Scanner::new(self.engines(job.use_clamav), self.limits.clone())
            .with_file_access(job.access.clone())
            .classify_in_engine(true);
        Ok(scanner.scan_job(job.job_id.clone(), &job.paths, cancel, &mut NoProgress))
    }
}
