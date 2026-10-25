//! Aufträge des Dienstes: Eigentum, Grenzen, Warteschlange, Abbruch.
//!
//! * Eigentümer eines Auftrags ist die vom Dienst festgestellte Identität
//!   (Benutzer-SID **und** Anmeldesitzung). Nur der Eigentümer sieht,
//!   bricht ab und liest den Bericht; für alle anderen existiert der Auftrag
//!   nicht (keine Auskunft über fremde Aufträge).
//! * Höchstens `max_running` Aufträge laufen gleichzeitig, höchstens
//!   `max_queued` warten insgesamt, je Eigentümer höchstens `max_per_owner`.
//! * Berichte liegen im geschützten Datenordner des Dienstes, zusammen mit
//!   einer Eigentümerangabe; der Pfad wird nur aus der geprüften UUID gebildet.

use crate::identity::Identity;
use axsafe_core::report::ScanReport;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug, Clone)]
pub struct JobLimits {
    pub max_running: usize,
    pub max_queued: usize,
    pub max_per_owner: usize,
    /// Abgeschlossene Aufträge, die im Speicher gelistet bleiben.
    pub keep_finished: usize,
}

impl Default for JobLimits {
    fn default() -> Self {
        JobLimits {
            max_running: 2,
            max_queued: 8,
            max_per_owner: 4,
            keep_finished: 200,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum JobState {
    Queued,
    Running,
    /// Bericht liegt vor (auch unvollständig oder abgebrochen – siehe Bericht).
    Finished {
        outcome: String,
    },
    /// Ohne Bericht gescheitert (z. B. Bericht nicht speicherbar).
    Failed {
        message: String,
    },
}

/// Was der Auftraggeber angefordert hat.
#[derive(Clone)]
pub struct JobSpec {
    pub job_id: String,
    pub paths: Vec<PathBuf>,
    pub use_clamav: bool,
    pub owner: Identity,
    /// Dateizugriff mit den Rechten des Auftraggebers.
    pub access: Arc<dyn axsafe_core::scan::FileAccess>,
}

/// Führt einen Auftrag aus (Dienst: echte Engines mit Impersonation).
pub trait JobRunner: Send + Sync {
    fn run(&self, job: &JobSpec, cancel: &AtomicBool) -> Result<ScanReport, String>;
}

#[derive(Debug, Clone, Serialize)]
pub struct JobView {
    pub job_id: String,
    #[serde(flatten)]
    pub state: JobState,
    pub paths: Vec<String>,
    pub use_clamav: bool,
}

struct Job {
    spec: JobSpec,
    state: JobState,
    cancel: Arc<AtomicBool>,
}

struct Inner {
    jobs: HashMap<String, Job>,
    queue: VecDeque<String>,
    running: usize,
    finished_order: VecDeque<String>,
    shutting_down: bool,
}

pub struct JobManager {
    limits: JobLimits,
    reports_dir: PathBuf,
    runner: Arc<dyn JobRunner>,
    inner: Mutex<Inner>,
    cv: Condvar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    Overloaded(String),
    ShuttingDown,
}

#[derive(Serialize, Deserialize)]
struct OwnerRecord {
    user_sid: String,
    logon_id: u64,
}

impl JobManager {
    /// Startet `limits.max_running` Arbeitsthreads.
    pub fn start(limits: JobLimits, reports_dir: PathBuf, runner: Arc<dyn JobRunner>) -> Arc<Self> {
        let m = Arc::new(JobManager {
            limits,
            reports_dir,
            runner,
            inner: Mutex::new(Inner {
                jobs: HashMap::new(),
                queue: VecDeque::new(),
                running: 0,
                finished_order: VecDeque::new(),
                shutting_down: false,
            }),
            cv: Condvar::new(),
        });
        for _ in 0..m.limits.max_running.max(1) {
            let mm = Arc::clone(&m);
            std::thread::spawn(move || mm.worker_loop());
        }
        m
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Nimmt einen Auftrag an oder lehnt ihn wegen Überlast ab.
    pub fn submit(&self, spec: JobSpec) -> Result<String, SubmitError> {
        let mut g = self.lock();
        if g.shutting_down {
            return Err(SubmitError::ShuttingDown);
        }
        let active = g
            .jobs
            .values()
            .filter(|j| matches!(j.state, JobState::Queued | JobState::Running))
            .count();
        if active >= self.limits.max_queued {
            return Err(SubmitError::Overloaded(format!(
                "Dienst ausgelastet: {active} Aufträge aktiv (höchstens {})",
                self.limits.max_queued
            )));
        }
        let own = g
            .jobs
            .values()
            .filter(|j| {
                j.spec.owner.same_owner(&spec.owner)
                    && matches!(j.state, JobState::Queued | JobState::Running)
            })
            .count();
        if own >= self.limits.max_per_owner {
            return Err(SubmitError::Overloaded(format!(
                "Zu viele eigene Aufträge aktiv ({own}, höchstens {})",
                self.limits.max_per_owner
            )));
        }
        let id = spec.job_id.clone();
        g.queue.push_back(id.clone());
        g.jobs.insert(
            id.clone(),
            Job {
                spec,
                state: JobState::Queued,
                cancel: Arc::new(AtomicBool::new(false)),
            },
        );
        drop(g);
        self.cv.notify_one();
        Ok(id)
    }

    /// Zustand eines eigenen Auftrags; fremde Aufträge „existieren nicht“.
    pub fn view(&self, owner: &Identity, job_id: &str) -> Option<JobView> {
        let g = self.lock();
        g.jobs.get(job_id).and_then(|j| {
            j.spec.owner.same_owner(owner).then(|| JobView {
                job_id: job_id.to_string(),
                state: j.state.clone(),
                paths: j
                    .spec
                    .paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect(),
                use_clamav: j.spec.use_clamav,
            })
        })
    }

    /// Eigene Aufträge.
    pub fn list(&self, owner: &Identity) -> Vec<JobView> {
        let g = self.lock();
        let mut v: Vec<JobView> = g
            .jobs
            .iter()
            .filter(|(_, j)| j.spec.owner.same_owner(owner))
            .map(|(id, j)| JobView {
                job_id: id.clone(),
                state: j.state.clone(),
                paths: j
                    .spec
                    .paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect(),
                use_clamav: j.spec.use_clamav,
            })
            .collect();
        v.sort_by(|a, b| a.job_id.cmp(&b.job_id));
        v
    }

    /// Bricht einen eigenen Auftrag ab. `false`, wenn er nicht (mehr)
    /// abbrechbar ist oder nicht dem Aufrufer gehört.
    pub fn cancel(&self, owner: &Identity, job_id: &str) -> bool {
        let mut g = self.lock();
        let Some(j) = g.jobs.get_mut(job_id) else {
            return false;
        };
        if !j.spec.owner.same_owner(owner) {
            return false;
        }
        match j.state {
            JobState::Queued => {
                j.state = JobState::Failed {
                    message: "vor dem Start abgebrochen".into(),
                };
                g.queue.retain(|q| q != job_id);
                true
            }
            JobState::Running => {
                j.cancel.store(true, Ordering::SeqCst);
                true
            }
            _ => false,
        }
    }

    /// Bericht eines eigenen Auftrags (auch nach Dienstneustart).
    pub fn report(&self, owner: &Identity, job_id: &str) -> Option<Vec<u8>> {
        uuid::Uuid::parse_str(job_id).ok()?;
        let base = self.reports_dir.join(job_id);
        let rec: OwnerRecord =
            serde_json::from_slice(&std::fs::read(base.with_extension("owner.json")).ok()?).ok()?;
        if rec.user_sid != owner.user_sid || rec.logon_id != owner.logon_id {
            return None;
        }
        std::fs::read(base.with_extension("json")).ok()
    }

    /// Aktive Aufträge (laufend, wartend).
    pub fn counts(&self) -> (usize, usize) {
        let g = self.lock();
        (g.running, g.queue.len())
    }

    /// Keine neuen Aufträge; laufende werden abgebrochen.
    pub fn shutdown(&self) {
        let mut g = self.lock();
        g.shutting_down = true;
        for j in g.jobs.values() {
            j.cancel.store(true, Ordering::SeqCst);
        }
        drop(g);
        self.cv.notify_all();
    }

    fn worker_loop(self: Arc<Self>) {
        loop {
            let (spec, cancel) = {
                let mut g = self.lock();
                loop {
                    if g.shutting_down {
                        return;
                    }
                    if let Some(id) = g.queue.pop_front() {
                        if let Some(j) = g.jobs.get_mut(&id) {
                            if j.state == JobState::Queued {
                                j.state = JobState::Running;
                                let r = (j.spec.clone(), Arc::clone(&j.cancel));
                                g.running += 1;
                                break r;
                            }
                        }
                        continue;
                    }
                    g = self.cv.wait(g).unwrap_or_else(|p| p.into_inner());
                }
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.runner.run(&spec, &cancel)
            }))
            .unwrap_or_else(|_| Err("interner Fehler (Panic) im Auftrag abgefangen".into()));
            let state = match result.and_then(|rep| self.store(&spec, &rep).map(|_| rep)) {
                Ok(rep) => JobState::Finished {
                    outcome: serde_json::to_value(rep.outcome)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_default(),
                },
                Err(e) => JobState::Failed { message: e },
            };
            let mut g = self.lock();
            g.running -= 1;
            if let Some(j) = g.jobs.get_mut(&spec.job_id) {
                j.state = state;
            }
            g.finished_order.push_back(spec.job_id.clone());
            while g.finished_order.len() > self.limits.keep_finished {
                if let Some(old) = g.finished_order.pop_front() {
                    g.jobs.remove(&old);
                }
            }
        }
    }

    /// Bericht exklusiv neu anlegen (nie überschreiben).
    fn store(&self, spec: &JobSpec, rep: &ScanReport) -> Result<(), String> {
        use std::io::Write;
        std::fs::create_dir_all(&self.reports_dir).map_err(|e| e.to_string())?;
        let base = self.reports_dir.join(&spec.job_id);
        let write_new = |path: PathBuf, data: &[u8]| -> Result<(), String> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            f.write_all(data)
                .and_then(|_| f.sync_all())
                .map_err(|e| e.to_string())
        };
        let owner = serde_json::to_vec(&OwnerRecord {
            user_sid: spec.owner.user_sid.clone(),
            logon_id: spec.owner.logon_id,
        })
        .map_err(|e| e.to_string())?;
        // Erst der Bericht (exklusiv), dann die Eigentümerangabe: Ohne sie
        // gibt report() nichts heraus.
        let json = serde_json::to_vec_pretty(rep).map_err(|e| e.to_string())?;
        write_new(base.with_extension("json"), &json)?;
        write_new(base.with_extension("owner.json"), &owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    struct SlowRunner {
        started: Mutex<usize>,
    }
    impl JobRunner for SlowRunner {
        fn run(&self, job: &JobSpec, cancel: &AtomicBool) -> Result<ScanReport, String> {
            *self.started.lock().unwrap() += 1;
            let t = Instant::now();
            while !cancel.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(5));
            }
            let s = axsafe_core::scan::Scanner::new(Vec::new(), Default::default());
            Ok(s.scan_job(
                job.job_id.clone(),
                &[],
                cancel,
                &mut axsafe_core::scan::NoProgress,
            ))
        }
    }

    fn id(user: &str, logon: u64) -> Identity {
        Identity {
            user_sid: user.into(),
            logon_id: logon,
            session_id: 1,
            display: user.into(),
        }
    }

    fn spec(owner: &Identity) -> JobSpec {
        JobSpec {
            job_id: uuid::Uuid::new_v4().to_string(),
            paths: vec![PathBuf::from("/x")],
            use_clamav: false,
            owner: owner.clone(),
            access: Arc::new(axsafe_core::scan::ProcessAccess),
        }
    }

    fn wait_state(m: &JobManager, o: &Identity, j: &str, pred: impl Fn(&JobState) -> bool) {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(10) {
            if m.view(o, j).map(|v| pred(&v.state)).unwrap_or(false) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("Zustand nicht erreicht: {:?}", m.view(o, j));
    }

    #[test]
    fn other_owner_cannot_see_cancel_or_read() {
        let dir = tempfile::tempdir().unwrap();
        let m = JobManager::start(
            JobLimits::default(),
            dir.path().into(),
            Arc::new(SlowRunner {
                started: Mutex::new(0),
            }),
        );
        let alex = id("S-1-5-21-1-1001", 7);
        let mallory = id("S-1-5-21-1-1002", 9);
        // gleiche SID, andere Anmeldesitzung = anderer Eigentümer
        let alex_other_logon = id("S-1-5-21-1-1001", 8);
        let j = m.submit(spec(&alex)).unwrap();
        for other in [&mallory, &alex_other_logon] {
            assert!(m.view(other, &j).is_none());
            assert!(!m.cancel(other, &j));
            assert!(m.list(other).is_empty());
        }
        assert!(m.cancel(&alex, &j));
        wait_state(&m, &alex, &j, |s| {
            matches!(s, JobState::Finished { .. } | JobState::Failed { .. })
        });
        assert!(
            m.report(&alex, &j).is_some()
                || matches!(m.view(&alex, &j).unwrap().state, JobState::Failed { .. })
        );
        assert!(m.report(&mallory, &j).is_none());
        assert!(m.report(&alex_other_logon, &j).is_none());
    }

    #[test]
    fn limits_bound_queue_and_parallelism() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(SlowRunner {
            started: Mutex::new(0),
        });
        let m = JobManager::start(
            JobLimits {
                max_running: 2,
                max_queued: 5,
                max_per_owner: 3,
                keep_finished: 10,
            },
            dir.path().into(),
            runner.clone(),
        );
        let a = id("S-1-5-21-1-1001", 1);
        let b = id("S-1-5-21-1-1002", 2);
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(m.submit(spec(&a)).unwrap());
        }
        assert!(
            matches!(m.submit(spec(&a)), Err(SubmitError::Overloaded(_))),
            "je Eigentümer begrenzt"
        );
        ids.push(m.submit(spec(&b)).unwrap());
        ids.push(m.submit(spec(&b)).unwrap());
        assert!(
            matches!(m.submit(spec(&b)), Err(SubmitError::Overloaded(_))),
            "gesamt begrenzt"
        );
        std::thread::sleep(Duration::from_millis(200));
        let (running, _) = m.counts();
        assert!(running <= 2, "höchstens 2 parallel, waren {running}");
        m.shutdown();
        assert!(matches!(m.submit(spec(&a)), Err(SubmitError::ShuttingDown)));
    }

    #[test]
    fn reports_are_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let m = JobManager::start(
            JobLimits::default(),
            dir.path().into(),
            Arc::new(SlowRunner {
                started: Mutex::new(0),
            }),
        );
        let a = id("S-1-5-21-1-1001", 1);
        let s = spec(&a);
        std::fs::write(dir.path().join(format!("{}.json", s.job_id)), b"vorhanden").unwrap();
        let j = m.submit(s).unwrap();
        m.cancel(&a, &j);
        wait_state(&m, &a, &j, |s| matches!(s, JobState::Failed { .. }));
        assert_eq!(
            std::fs::read(dir.path().join(format!("{j}.json"))).unwrap(),
            b"vorhanden"
        );
        assert!(
            m.report(&a, &j).is_none(),
            "ohne eigene Eigentümerangabe kein Bericht"
        );
    }
}
