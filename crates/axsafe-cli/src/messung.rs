//! `axsafe clamav-messung`: Vorher/Nachher-Vergleich (B-18) auf genau
//! derselben Dateimenge – clamscan je Objekt gegen die dauerhaft geladene
//! Engine. Gemessen wird, nichts geschätzt: Start (Datenbank laden), erster
//! Scan, Folgescans, Gesamtdauer, Speicherspitze (soweit das System sie
//! misst). Zusätzlich wird geprüft, dass beide Betriebsarten je Datei
//! dasselbe Ergebnis liefern; Abweichungen machen die Messung ungültig.

use axsafe_core::engine::{Engine, EngineOutcome, ScanInput};
use axsafe_engine_clamav::persistent::{ClamAvWorkerEngine, WorkerSettings};
use axsafe_engine_clamav::{ClamAvConfig, ClamAvEngine};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Serialize)]
pub struct ModeResult {
    pub mode: String,
    pub engine_ready: bool,
    pub engine_detail: String,
    pub engine_version: String,
    pub content_version: String,
    /// Engine anlegen inkl. Laden der Datenbank (clamscan: Funktionstest).
    pub start_ms: u64,
    pub first_scan_ms: Option<f64>,
    pub followup_scans_ms: Vec<f64>,
    pub followup_mean_ms: Option<f64>,
    pub followup_median_ms: Option<f64>,
    /// Start + alle Scans.
    pub total_ms: u64,
    pub peak_memory_bytes: Option<u64>,
    pub peak_memory_source: String,
    pub results: Vec<FileResult>,
}

#[derive(Serialize, Clone, PartialEq)]
pub struct FileResult {
    pub file: String,
    pub bytes: u64,
    pub verdict: String,
    pub detections: Vec<String>,
    pub gaps: Vec<String>,
}

#[derive(Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub axsafe_version: &'static str,
    pub os: String,
    pub cpus: usize,
    pub files: usize,
    pub total_bytes: u64,
    pub per_file_timeout_s: u64,
    pub modes: Vec<ModeResult>,
    /// Beide Betriebsarten liefern je Datei dasselbe Ergebnis.
    pub results_identical: bool,
    pub differences: Vec<String>,
    pub speedup_total: Option<f64>,
    pub note: String,
}

fn result_of(file: &Path, bytes: u64, o: &EngineOutcome) -> FileResult {
    FileResult {
        file: file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        bytes,
        verdict: format!("{:?}", o.verdict),
        detections: o.detections.iter().map(|d| d.name.clone()).collect(),
        gaps: o.gaps.iter().map(|g| format!("{:?}", g.reason)).collect(),
    }
}

fn run_mode(
    mode: &str,
    engine: &dyn Engine,
    start_ms: u64,
    files: &[(PathBuf, Vec<u8>)],
    timeout: Duration,
) -> ModeResult {
    let t0 = Instant::now();
    let info = engine.info();
    let mut results = Vec::new();
    let mut times = Vec::new();
    for (p, data) in files {
        let kind = axsafe_core::filetype::detect(data);
        let t = Instant::now();
        let o = engine.scan(&ScanInput {
            data,
            kind: &kind,
            sha256: "",
            timeout,
        });
        times.push(t.elapsed().as_micros() as f64 / 1000.0);
        results.push(result_of(p, data.len() as u64, &o));
    }
    let scans_ms = t0.elapsed().as_millis() as u64;
    let first = times.first().copied();
    let follow: Vec<f64> = times.iter().skip(1).copied().collect();
    let mean = (!follow.is_empty()).then(|| follow.iter().sum::<f64>() / follow.len() as f64);
    let median = (!follow.is_empty()).then(|| {
        let mut s = follow.clone();
        s.sort_by(|a, b| a.total_cmp(b));
        s[s.len() / 2]
    });
    ModeResult {
        mode: mode.into(),
        engine_ready: info.health == axsafe_core::engine::EngineHealth::Ready,
        engine_detail: match &info.health {
            axsafe_core::engine::EngineHealth::Ready => info.content_note.clone(),
            axsafe_core::engine::EngineHealth::Unavailable { reason } => reason.clone(),
        },
        engine_version: info.engine_version,
        content_version: info.content_version,
        start_ms,
        first_scan_ms: first,
        followup_scans_ms: follow,
        followup_mean_ms: mean,
        followup_median_ms: median,
        total_ms: start_ms + scans_ms,
        peak_memory_bytes: None,
        peak_memory_source: String::new(),
        results,
    }
}

fn collect(dir: &Path, max: usize) -> std::io::Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    names.sort();
    names.truncate(max);
    names
        .into_iter()
        .map(|p| std::fs::read(&p).map(|d| (p, d)))
        .collect()
}

pub struct Args {
    pub dir: PathBuf,
    pub cfg: ClamAvConfig,
    pub worker: PathBuf,
    pub timeout: Duration,
    pub max_files: usize,
}

pub fn measure(a: Args) -> Result<Report, String> {
    let files = collect(&a.dir, a.max_files)
        .map_err(|e| format!("Dateien in {} nicht lesbar: {e}", a.dir.display()))?;
    if files.is_empty() {
        return Err(format!("keine Dateien in {}", a.dir.display()));
    }
    let mut modes = Vec::new();

    // 1) Vorher: clamscan je Objekt. Zuerst, damit unter Linux die
    //    Kindprozess-Speicherspitze nur clamscan enthält.
    {
        let t = Instant::now();
        let e = ClamAvEngine::new(a.cfg.clone());
        let start = t.elapsed().as_millis() as u64;
        let mut r = run_mode("clamscan je Objekt", &e, start, &files, a.timeout);
        #[cfg(unix)]
        {
            r.peak_memory_bytes = axsafe_proc::children_peak_rss();
            r.peak_memory_source =
                "getrusage(RUSAGE_CHILDREN).ru_maxrss: größter clamscan-Lauf".into();
        }
        #[cfg(not(unix))]
        {
            r.peak_memory_bytes = e.peak_memory_bytes();
            r.peak_memory_source = "Job Object PeakJobMemoryUsed: größter clamscan-Lauf".into();
        }
        modes.push(r);
    }

    // 2) Nachher: dauerhaft geladene Engine.
    {
        let ws = WorkerSettings::new(a.worker.clone(), &a.cfg);
        let t = Instant::now();
        let e = ClamAvWorkerEngine::start(ws, a.cfg.clamscan.clone());
        let start = t.elapsed().as_millis() as u64;
        let mut r = run_mode(
            "dauerhaft (axsafe-clamav-worker)",
            &e,
            start,
            &files,
            a.timeout,
        );
        let s = e.stats();
        r.peak_memory_bytes = s.peak_memory_bytes;
        r.peak_memory_source = if cfg!(target_os = "linux") {
            "VmHWM des Worker-Prozesses".into()
        } else {
            "Job Object PeakJobMemoryUsed des Workers".into()
        };
        r.engine_detail = format!(
            "{}; Worker-Starts {}, Neustarts {}",
            r.engine_detail, s.launches, s.restarts
        );
        modes.push(r);
    }

    let mut differences = Vec::new();
    for (x, y) in modes[0].results.iter().zip(&modes[1].results) {
        if x != y {
            differences.push(format!(
                "{}: clamscan {} {:?} {:?} / dauerhaft {} {:?} {:?}",
                x.file, x.verdict, x.detections, x.gaps, y.verdict, y.detections, y.gaps
            ));
        }
    }
    let both_ready = modes.iter().all(|m| m.engine_ready);
    let speedup = (both_ready && modes[1].total_ms > 0)
        .then(|| modes[0].total_ms as f64 / modes[1].total_ms as f64);
    Ok(Report {
        schema: "axsafe.clamav-messung/1",
        axsafe_version: axsafe_core::AXSAFE_VERSION,
        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        cpus: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        files: files.len(),
        total_bytes: files.iter().map(|(_, d)| d.len() as u64).sum(),
        per_file_timeout_s: a.timeout.as_secs(),
        results_identical: differences.is_empty() && both_ready,
        differences,
        speedup_total: speedup,
        note: "Einmalige Messung auf diesem Rechner; Werte hängen von Hardware, \
               Datenbankgröße und Dateimenge ab und sind keine Zusage."
            .into(),
        modes,
    })
}

pub fn print(r: &Report) {
    println!(
        "ClamAV-Messung: {} Dateien, {} Bytes, {} ({} CPUs)",
        r.files, r.total_bytes, r.os, r.cpus
    );
    for m in &r.modes {
        println!("\n{}:", m.mode);
        println!(
            "  Engine: {} – {}",
            if m.engine_ready {
                "bereit"
            } else {
                "NICHT BEREIT"
            },
            m.engine_detail
        );
        println!("  Stand: {} / {}", m.engine_version, m.content_version);
        println!("  Start (Datenbank laden): {} ms", m.start_ms);
        if let Some(f) = m.first_scan_ms {
            println!("  Erster Scan: {f:.1} ms");
        }
        if let (Some(mean), Some(med)) = (m.followup_mean_ms, m.followup_median_ms) {
            println!(
                "  Folgescans: {} Stück, Mittel {:.2} ms, Median {:.2} ms",
                m.followup_scans_ms.len(),
                mean,
                med
            );
        }
        println!("  Gesamt: {} ms", m.total_ms);
        match m.peak_memory_bytes {
            Some(p) => println!(
                "  Speicherspitze: {:.1} MiB ({})",
                p as f64 / 1048576.0,
                m.peak_memory_source
            ),
            None => println!("  Speicherspitze: nicht gemessen"),
        }
    }
    println!();
    if r.results_identical {
        println!("Ergebnisse je Datei: identisch");
    } else {
        println!("Ergebnisse je Datei: ABWEICHUNG oder Engine nicht bereit – Messung ungültig");
        for d in &r.differences {
            println!("  {d}");
        }
    }
    if let Some(s) = r.speedup_total {
        println!("Gesamtdauer clamscan / dauerhaft: {s:.1}");
    }
}
