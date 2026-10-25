//! `axsafe` – Kommandozeile der AXSafe Vorversion.
//!
//! Exitcodes (stabil, für Skripte; aus dem Auftragsergebnis abgeleitet):
//! * `0` – vollständig geprüft, nichts erkannt (im angegebenen Umfang)
//! * `1` – mindestens ein Fund, Auftrag vollständig
//! * `2` – kein Fund, aber unvollständig (Lücken, Engine-Ausfall, Abbruch)
//! * `3` – Bedienungs-/Konfigurationsfehler, z. B. Berichtsziel existiert bereits
//! * `4` – mindestens ein Fund **und** unvollständig geprüft
//! * `5` – keine prüfbaren Objekte im Umfang (es wurde nichts geprüft)

#![forbid(unsafe_code)]

mod report_target;

use axsafe_core::engine::{ContentKind, Engine, EngineHealth, EngineInfo, IsolationKind};
use axsafe_core::report::{FileResult, ObjectStatus, ScanLimits, ScanReport};
use axsafe_core::scan::{Progress, Scanner};
use axsafe_engine_clamav::{ClamAvConfig, ClamAvEngine};
use axsafe_engine_yarax::YaraXEngine;
use axsafe_worker::host::{WorkerConfig, WorkerEngine};
use clap::{Parser, Subcommand};
use report_target::ReportTarget;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

#[derive(Parser)]
#[command(
    name = "axsafe",
    version,
    about = "AXSafe Vorversion: Dateien prüfen und ehrlich berichten (kein Echtzeitschutz)",
    long_about = "AXSafe Vorversion.\n\nPrüft Dateien und Ordner mit YARA-X (eigene Regeln) und optional ClamAV.\n\
Der Scanner liest nur: keine Quarantäne, kein Löschen, kein Ausführen.\n\
'Nichts erkannt' gilt nur für den angegebenen Umfang und ist kein Beweis für Harmlosigkeit.\n\
Bitte lass deinen bisherigen Virenschutz (z. B. Microsoft Defender) aktiv.\n\n\
Exitcodes: 0 ohne Fund vollständig · 1 Fund · 2 unvollständig · 3 Bedienfehler · \
4 Fund und unvollständig · 5 nichts prüfbar"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(clap::Args, Clone)]
struct EngineArgs {
    /// Verzeichnis mit YARA-X-Regeln (*.yar). Standard: ./rules oder <exe>/rules
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Pfad zum isolierten Scanworker. Standard: axsafe-worker neben axsafe
    #[arg(long)]
    worker: Option<PathBuf>,
    /// YARA-X ohne isolierten Worker im eigenen Prozess ausführen (Diagnose;
    /// wird in der Isolationsangabe sichtbar ausgewiesen)
    #[arg(long)]
    yara_in_process: bool,
    /// ClamAV nicht verwenden (Umfang wird im Bericht entsprechend kleiner)
    #[arg(long)]
    no_clamav: bool,
    /// Pfad zu clamscan
    #[arg(long)]
    clamscan: Option<PathBuf>,
    /// Eigene ClamAV-Datenbank (Datei oder Ordner); Standard: ClamAV-Standard
    #[arg(long)]
    clamav_db: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Mit dem AXSafe-Dienst sprechen (Windows; axsafe.ipc/1)
    Dienst {
        #[command(subcommand)]
        cmd: DienstCmd,
    },
    /// Dateien oder Ordner prüfen
    Scan {
        /// Zu prüfende Dateien oder Ordner
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        engines: EngineArgs,
        /// JSON-Bericht in diese NEUE Datei schreiben (wird nie überschrieben)
        #[arg(long)]
        json: Option<PathBuf>,
        /// Auftragskennung (UUID), die im Bericht steht; Standard: zufällig
        #[arg(long)]
        job_id: Option<String>,
        /// Maximale Dateigröße in MB (größere Dateien: nicht geprüft)
        #[arg(long, default_value_t = 256)]
        max_file_size_mb: u64,
        /// Gemeinsames Zeitbudget je Engine-Aufruf und Datei in Sekunden
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Zeitbudget in Millisekunden (überschreibt --timeout-secs)
        #[arg(long)]
        timeout_ms: Option<u64>,
        /// Auch Dateien ohne Fund einzeln anzeigen
        #[arg(short, long)]
        verbose: bool,
    },
    /// Zustand, Regelbestand und Fähigkeiten der Engines anzeigen
    Engines {
        #[command(flatten)]
        engines: EngineArgs,
        /// Maschinenlesbar als JSON ausgeben
        #[arg(long)]
        json: bool,
    },
    /// Dateityp nach Inhalt bestimmen (ohne Engine)
    Filetype {
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum DienstCmd {
    /// Zustand des Dienstes und der Engines (JSON)
    Status,
    /// Scan durch den Dienst mit den eigenen Rechten starten
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// ClamAV zusätzlich verwenden
        #[arg(long)]
        clamav: bool,
        /// Auf das Ende warten und den Bericht ausgeben
        #[arg(long)]
        warten: bool,
    },
    /// Zustand eines eigenen Auftrags
    Auftrag { job_id: String },
    /// Bericht eines eigenen Auftrags (JSON)
    Bericht { job_id: String },
    /// Eigenen Auftrag abbrechen
    Abbrechen { job_id: String },
}

/// Ruft den Dienst auf und gibt die Antwort als JSON aus.
/// Exitcodes: 0 ok, 6 Dienst nicht erreichbar, 7 vom Dienst abgelehnt.
fn dienst(cmd: DienstCmd) -> ExitCode {
    use axsafe_service::ipc::Body;
    let mut c = match axsafe_service::client::connect() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("AXSafe-Dienst nicht erreichbar: {e}");
            return ExitCode::from(6);
        }
    };
    let print = |r: &axsafe_service::ipc::Response| {
        println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
        if r.ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(7)
        }
    };
    let call = |c: &mut axsafe_service::client::Client<std::fs::File>, b: Body| match c.call(b) {
        Ok(r) => Ok(r),
        Err(e) => {
            eprintln!("Verbindung zum Dienst gestört: {e}");
            Err(ExitCode::from(6))
        }
    };
    let body = match cmd {
        DienstCmd::Status => Body::Status,
        DienstCmd::Auftrag { job_id } => Body::Job { job_id },
        DienstCmd::Bericht { job_id } => Body::Report { job_id },
        DienstCmd::Abbrechen { job_id } => Body::ScanCancel { job_id },
        DienstCmd::Scan {
            paths,
            clamav,
            warten,
        } => {
            // Absolute Pfade; die Prüfung erfolgt im Dienst mit den Rechten
            // dieses Benutzers.
            let paths: Vec<String> = paths
                .iter()
                .map(|p| {
                    std::path::absolute(p)
                        .unwrap_or_else(|_| p.clone())
                        .display()
                        .to_string()
                })
                .collect();
            let r = match call(
                &mut c,
                Body::ScanStart {
                    paths,
                    use_clamav: clamav,
                },
            ) {
                Ok(r) => r,
                Err(code) => return code,
            };
            if !warten || !r.ok {
                return print(&r);
            }
            let job = r.result["job_id"].as_str().unwrap_or_default().to_string();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(250));
                let j = match call(
                    &mut c,
                    Body::Job {
                        job_id: job.clone(),
                    },
                ) {
                    Ok(j) => j,
                    Err(code) => return code,
                };
                if !j.ok {
                    return print(&j);
                }
                if j.result["state"] == "finished" || j.result["state"] == "failed" {
                    break;
                }
            }
            Body::Report { job_id: job }
        }
    };
    match call(&mut c, body) {
        Ok(r) => print(&r),
        Err(code) => code,
    }
}

fn default_rules_dir() -> PathBuf {
    let cwd = PathBuf::from("rules");
    if cwd.is_dir() {
        return cwd;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("rules");
            if p.is_dir() {
                return p;
            }
        }
    }
    cwd
}

fn default_worker() -> PathBuf {
    let name = format!("axsafe-worker{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(&name)))
        .unwrap_or_else(|| PathBuf::from(name))
}

fn build_engines(a: &EngineArgs, max_scan_bytes: Option<u64>) -> Vec<Box<dyn Engine>> {
    let mut v: Vec<Box<dyn Engine>> = Vec::new();
    let rules_dir = a.rules.clone().unwrap_or_else(default_rules_dir);
    if a.yara_in_process {
        v.push(Box::new(YaraXEngine::from_dir(rules_dir)));
    } else {
        // P02: YARA-X läuft im isolierten Worker (AppContainer/Landlock).
        let rules = axsafe_engine_yarax::read_rule_sources(&rules_dir);
        let mut cfg = WorkerConfig::new(a.worker.clone().unwrap_or_else(default_worker), rules);
        if let Some(m) = max_scan_bytes {
            cfg.max_scan_bytes = m;
            cfg.memory_bytes = Some(axsafe_worker::host::memory_for(m));
        }
        v.push(Box::new(WorkerEngine::start(cfg)));
    }
    if !a.no_clamav {
        let mut cfg = ClamAvConfig::default();
        if let Some(p) = &a.clamscan {
            cfg.clamscan = p.clone();
        }
        cfg.database = a.clamav_db.clone();
        v.push(Box::new(ClamAvEngine::new(cfg)));
    }
    v
}

fn content_label(k: ContentKind) -> &'static str {
    match k {
        ContentKind::TestOnly => "NUR FUNKTIONSTEST",
        ContentKind::Production => "produktiv",
        ContentKind::OfficialSignatures => "offizielle Signaturen",
        ContentKind::CustomSignatures => "eigene Signaturen",
        ContentKind::Unknown => "unbekannt",
    }
}

fn print_engines(infos: &[EngineInfo]) {
    println!("Engines:");
    for i in infos {
        match &i.health {
            EngineHealth::Ready => {
                println!("  [bereit]          {:<7} {}", i.name, i.engine_version)
            }
            EngineHealth::Unavailable { reason } => {
                println!("  [NICHT VERFÜGBAR] {:<7} {}", i.name, reason)
            }
        }
        println!(
            "                    Regelbestand: {} – {}",
            content_label(i.content_kind),
            i.content_note
        );
        let caps = if i.inspects_contents_of.is_empty() {
            "keine (nur Rohbytes)".to_string()
        } else {
            i.inspects_contents_of
                .iter()
                .map(|f| f.label())
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!("                    Containerinhalte: {caps}");
        let iso = match (i.isolation.kind, i.isolation.enforced) {
            (IsolationKind::SandboxedWorker, true) => "abgeschotteter Worker (nachgewiesen)",
            (IsolationKind::SandboxedWorker, false) => "Worker, Abschottung NICHT nachgewiesen",
            (IsolationKind::ChildProcess, _) => "eigener Prozess mit Grenzen, Rechte des Benutzers",
            (IsolationKind::InProcess, _) => "im AXSafe-Prozess, Rechte des Benutzers",
        };
        println!(
            "                    Isolation: {iso} – {}",
            i.isolation.detail
        );
    }
    let ready: Vec<&EngineInfo> = infos
        .iter()
        .filter(|i| i.health == EngineHealth::Ready)
        .collect();
    if !ready.is_empty()
        && ready
            .iter()
            .all(|i| i.content_kind == ContentKind::TestOnly)
    {
        println!();
        println!("  ACHTUNG: Es sind ausschließlich Funktionstest-Regeln geladen (z. B. EICAR).");
        println!("           Damit erkennt AXSafe KEINE echte Schadsoftware. Ein Fund belegt nur,");
        println!("           dass der Prüfpfad funktioniert.");
    }
}

fn status_tag(s: ObjectStatus) -> &'static str {
    match s {
        ObjectStatus::Detection => "FUND         ",
        ObjectStatus::DetectionIncomplete => "FUND + LÜCKE ",
        ObjectStatus::NoDetection => "OHNE FUND    ",
        ObjectStatus::Incomplete => "NICHT VOLLST.",
    }
}

struct Live {
    verbose: bool,
}

impl Progress for Live {
    fn on_result(&mut self, r: &FileResult) {
        if !self.verbose && r.status == ObjectStatus::NoDetection {
            return;
        }
        let kind = r.file_kind.as_ref().map(|k| k.label()).unwrap_or_default();
        println!("  [{}] {}  {}", status_tag(r.status), r.path, kind);
        for e in &r.engines {
            for d in &e.detections {
                let test = if d.test_signature {
                    " (Testsignatur)"
                } else {
                    ""
                };
                println!(
                    "                  - Fund: {}{} via {}",
                    d.name, test, e.engine
                );
            }
        }
        for g in &r.gaps {
            println!(
                "                  - Lücke {:?} ({}): {}",
                g.state, g.source, g.detail
            );
        }
    }
}

fn print_summary(rep: &ScanReport) {
    let s = &rep.summary;
    println!();
    println!(
        "Zusammenfassung: {} Objekte | {} gelesen | {} mit Fund | {} mit Lücke | davon {} Fund+Lücke | {} ohne Fund vollständig | {} Bytes | {} ms",
        s.objects_total,
        s.objects_read,
        s.with_detection,
        s.incomplete,
        s.detection_and_incomplete,
        s.no_detection_complete,
        s.bytes_read,
        rep.duration_ms
    );
    for g in &rep.job_gaps {
        println!(
            "Auftragslücke:   {:?} ({}): {}",
            g.state, g.source, g.detail
        );
    }
    if !rep.scope.excluded.is_empty() {
        for x in &rep.scope.excluded {
            println!("Ausgeschlossen:  {} ({})", x.path, x.reason);
        }
    }
    println!("Ergebnis:        {}", rep.outcome.label_de());
    println!("Aktion:          keine (Vorversion meldet nur; keine Quarantäne, kein Löschen)");
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Engines { engines, json } => {
            let engines = build_engines(&engines, None);
            let infos: Vec<EngineInfo> = engines.iter().map(|e| e.info()).collect();
            if json {
                match serde_json::to_string_pretty(&infos) {
                    Ok(t) => println!("{t}"),
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(3);
                    }
                }
            } else {
                print_engines(&infos);
            }
            if infos.iter().all(|i| i.health == EngineHealth::Ready) {
                ExitCode::from(0)
            } else {
                ExitCode::from(2)
            }
        }
        Cmd::Dienst { cmd } => dienst(cmd),
        Cmd::Filetype { files } => {
            let mut code = 0u8;
            for f in files {
                match std::fs::read(&f) {
                    Ok(d) => println!(
                        "{}\t{}",
                        f.display(),
                        axsafe_core::filetype::detect(&d).label()
                    ),
                    Err(e) => {
                        eprintln!("{}\tFehler: {e}", f.display());
                        code = 2;
                    }
                }
            }
            ExitCode::from(code)
        }
        Cmd::Scan {
            paths,
            engines,
            json,
            job_id,
            max_file_size_mb,
            timeout_secs,
            timeout_ms,
            verbose,
        } => {
            let yara_in_process = engines.yara_in_process;
            let job_id = match job_id {
                Some(j) => match uuid::Uuid::parse_str(&j) {
                    Ok(u) => u.hyphenated().to_string(),
                    Err(e) => {
                        eprintln!("Ungültige Auftragskennung {j:?}: {e}");
                        return ExitCode::from(3);
                    }
                },
                None => uuid::Uuid::new_v4().to_string(),
            };
            // Berichtsziel VOR dem Scan exklusiv anlegen (Befund 1).
            let target = match json.as_deref().map(ReportTarget::reserve).transpose() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(3);
                }
            };
            println!(
                "AXSafe {} – Vorversion. Kein Echtzeitschutz. Bitte bisherigen Virenschutz aktiv lassen.",
                axsafe_core::AXSAFE_VERSION
            );
            let engines =
                build_engines(&engines, Some(max_file_size_mb.saturating_mul(1024 * 1024)));
            let limits = ScanLimits {
                max_file_size: max_file_size_mb.saturating_mul(1024 * 1024),
                engine_timeout_ms: timeout_ms.unwrap_or_else(|| timeout_secs.saturating_mul(1000)),
                ..ScanLimits::default()
            };
            // P02: Mit Worker wird auch der Dateityp im abgeschotteten Worker
            // bestimmt; der CLI-Prozess parst keine Dateiinhalte.
            let mut scanner = Scanner::new(engines, limits).classify_in_engine(!yara_in_process);
            print_engines(&scanner.engine_infos());
            if let Some(t) = &target {
                scanner.exclude_identity(t.identity().clone(), "Berichtsdatei dieses Auftrags");
            }
            println!("Ergebnisse:");
            let cancel = AtomicBool::new(false);
            let rep = scanner.scan_job(job_id, &paths, &cancel, &mut Live { verbose });
            print_summary(&rep);
            if let Some(t) = target {
                let shown = t.path().display().to_string();
                let text = match serde_json::to_vec_pretty(&rep) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("Bericht nicht serialisierbar: {e}");
                        return ExitCode::from(3);
                    }
                };
                if let Err(e) = t.write(&text) {
                    eprintln!("Bericht konnte nicht geschrieben werden ({shown}): {e}");
                    return ExitCode::from(3);
                }
                println!("Bericht:         {shown}");
            }
            ExitCode::from(rep.outcome.exit_code())
        }
    }
}
