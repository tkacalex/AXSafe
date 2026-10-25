//! Echte Auftragsausführung im Dienst.
//!
//! * Dateien werden mit den Rechten des Auftraggebers gelesen
//!   ([`JobSpec::access`], Windows-Impersonation).
//! * Typerkennung und YARA-X laufen im abgeschotteten Worker; der Dienst
//!   parst keine Dateiinhalte.
//! * ClamAV läuft – wenn beauftragt – mit eingeschränktem Token (siehe
//!   axsafe-engine-clamav); scheitert die Abschottung, ist ClamAV nicht
//!   verfügbar (Lücke), nie unbeschränkt.

use crate::jobs::{JobRunner, JobSpec};
use axsafe_core::engine::Engine;
use axsafe_core::report::{ExecutedBy, ScanLimits, ScanReport};
use axsafe_core::scan::{NoProgress, Scanner};
use axsafe_engine_clamav::{ClamAvConfig, ClamAvEngine};
use axsafe_worker::host::{WorkerConfig, WorkerEngine};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

#[derive(Clone)]
pub struct ServiceRunner {
    pub worker_exe: PathBuf,
    pub rules_dir: PathBuf,
    pub limits: ScanLimits,
    pub clamav: ClamAvConfig,
    /// Dienstprotokoll: eine Zeile je Auftrag mit Engines und Lücken.
    pub log: Option<std::sync::Arc<crate::log::Log>>,
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
        let mut rep = scanner.scan_job(job.job_id.clone(), &job.paths, cancel, &mut NoProgress);
        rep.executed_by = Some(ExecutedBy {
            kind: "dienst".into(),
            name: "AXSafeService".into(),
            account: service_account(),
            process_id: std::process::id(),
            client: Some(job.owner.display.clone()),
            client_session: Some(job.owner.session_id),
        });
        if let Some(log) = &self.log {
            log.line(&job_summary(&rep));
        }
        Ok(rep)
    }
}

/// Konto des Dienstprozesses (USERNAME/USERDOMAIN der Prozessumgebung; beim
/// Dienst „LOCAL SERVICE“ in „NT AUTHORITY“).
fn service_account() -> String {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let dom = std::env::var("USERDOMAIN").unwrap_or_default();
    if dom.is_empty() {
        user
    } else {
        format!("{dom}\\{user}")
    }
}

/// Eine Protokollzeile je Auftrag: Ergebnis, Engines (Bereitschaft,
/// Inhaltsversion, Abschottung) und Lückengründe – ohne Dateiinhalte.
pub fn job_summary(rep: &ScanReport) -> String {
    use std::collections::BTreeMap;
    let engines: Vec<String> = rep
        .scope
        .engines
        .iter()
        .map(|e| {
            format!(
                "{} {} {:?} inhalt={} isoliert={}",
                e.name, e.engine_version, e.health, e.content_version, e.isolation.enforced
            )
        })
        .collect();
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for g in rep
        .files
        .iter()
        .flat_map(|f| f.gaps.iter())
        .chain(rep.job_gaps.iter())
    {
        *reasons
            .entry(format!("{}:{:?}", g.source, g.reason))
            .or_default() += 1;
    }
    let mut per_engine: BTreeMap<String, usize> = BTreeMap::new();
    for f in &rep.files {
        for o in &f.engines {
            *per_engine
                .entry(format!("{}={:?}", o.engine, o.verdict))
                .or_default() += 1;
        }
    }
    let client = rep
        .executed_by
        .as_ref()
        .and_then(|x| x.client.clone())
        .unwrap_or_default();
    format!(
        "Auftrag {} für {}: Ergebnis {:?}, vollständig={}, Objekte {}, Funde {}, Lücken {} | Engines: {} | Engine-Ergebnisse: {:?} | Lückengründe: {:?}",
        rep.job_id,
        client,
        rep.outcome,
        rep.complete,
        rep.summary.objects_total,
        rep.summary.with_detection,
        rep.summary.incomplete,
        engines.join("; "),
        per_engine,
        reasons
    )
}
