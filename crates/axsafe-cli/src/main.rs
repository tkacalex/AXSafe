//! `axsafe` – Kommandozeile der AXSafe Vorversion.
//!
//! Exitcodes (stabil, für Skripte):
//! * `0` – vollständig geprüft, nichts erkannt (im angegebenen Umfang)
//! * `1` – mindestens ein Fund (schädlich, verdächtig oder PUA)
//! * `2` – kein Fund, aber unvollständig (Fehler, Lücken, Abbruch)
//! * `3` – Bedienungs- oder Konfigurationsfehler

#![forbid(unsafe_code)]

use axsafe_core::engine::{Engine, EngineHealth};
use axsafe_core::report::{FileResult, ScanLimits, ScanReport};
use axsafe_core::scan::{Progress, Scanner};
use axsafe_core::verdict::Verdict;
use axsafe_engine_clamav::{ClamAvConfig, ClamAvEngine};
use axsafe_engine_yarax::YaraXEngine;
use clap::{Parser, Subcommand};
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
Bitte lass deinen bisherigen Virenschutz (z. B. Microsoft Defender) aktiv."
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
    /// Dateien oder Ordner prüfen
    Scan {
        /// Zu prüfende Dateien oder Ordner
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        engines: EngineArgs,
        /// JSON-Bericht in diese Datei schreiben
        #[arg(long)]
        json: Option<PathBuf>,
        /// Maximale Dateigröße in MB (größere Dateien: nicht geprüft)
        #[arg(long, default_value_t = 256)]
        max_file_size_mb: u64,
        /// Zeitbudget je Engine und Datei in Sekunden
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Auch Dateien ohne Fund einzeln anzeigen
        #[arg(short, long)]
        verbose: bool,
    },
    /// Zustand und Versionen der Engines anzeigen
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

fn build_engines(a: &EngineArgs) -> Vec<Box<dyn Engine>> {
    let mut v: Vec<Box<dyn Engine>> = Vec::new();
    v.push(Box::new(YaraXEngine::from_dir(
        a.rules.clone().unwrap_or_else(default_rules_dir),
    )));
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

fn tag(v: Verdict) -> &'static str {
    match v {
        Verdict::Malicious => "SCHÄDLICH    ",
        Verdict::Suspicious => "VERDÄCHTIG   ",
        Verdict::Pua => "PUA          ",
        Verdict::NoDetection => "OHNE FUND    ",
        Verdict::Unsupported => "NICHT GEPRÜFT",
        Verdict::Encrypted => "VERSCHLÜSSELT",
        Verdict::AccessDenied => "KEIN ZUGRIFF ",
        Verdict::Timeout => "ZEITLIMIT    ",
        Verdict::Error => "FEHLER       ",
        Verdict::ChangedDuringScan => "GEÄNDERT     ",
    }
}

fn print_engines(engines: &[Box<dyn Engine>]) {
    println!("Engines:");
    for e in engines {
        let i = e.info();
        match &i.health {
            EngineHealth::Ready => println!(
                "  [bereit]          {:<7} {}  Inhalt: {}",
                i.name, i.engine_version, i.content_version
            ),
            EngineHealth::Unavailable { reason } => {
                println!("  [NICHT VERFÜGBAR] {:<7} {}", i.name, reason)
            }
        }
    }
}

struct Live {
    verbose: bool,
}

impl Progress for Live {
    fn on_result(&mut self, r: &FileResult) {
        if !self.verbose && r.verdict == Verdict::NoDetection {
            return;
        }
        let mut detail: Vec<String> = Vec::new();
        for e in &r.engines {
            for d in &e.detections {
                let test = if d.test_signature {
                    " (Testsignatur)"
                } else {
                    ""
                };
                detail.push(format!("{}{} via {}", d.name, test, e.engine));
            }
            if let Some(n) = &e.note {
                detail.push(format!("{}: {}", e.engine, n));
            }
        }
        detail.extend(r.notes.iter().cloned());
        let kind = r.file_kind.as_ref().map(|k| k.label()).unwrap_or_default();
        println!("  [{}] {}  {}", tag(r.verdict), r.path, kind);
        for d in detail {
            println!("                  - {d}");
        }
    }
}

fn print_summary(rep: &ScanReport) {
    let s = &rep.summary;
    println!();
    println!(
        "Zusammenfassung: {} Objekte | {} mit Fund | {} unvollständig | {} ohne Fund | {} Bytes gelesen | {} ms",
        s.objects, s.detections, s.incomplete, s.no_detection, s.bytes_read, rep.duration_ms
    );
    let status = if rep.overall.is_detection() {
        format!("FUND – {}", rep.overall.label_de())
    } else if !rep.complete {
        format!("UNVOLLSTÄNDIG – {}", rep.overall.label_de())
    } else {
        "Nichts erkannt (nur im geprüften Umfang, kein Beweis für Harmlosigkeit)".into()
    };
    println!("Gesamtstatus:    {status}");
    println!("Aktion:          keine (Vorversion meldet nur; keine Quarantäne, kein Löschen)");
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Engines { engines, json } => {
            let engines = build_engines(&engines);
            if json {
                let infos: Vec<_> = engines.iter().map(|e| e.info()).collect();
                match serde_json::to_string_pretty(&infos) {
                    Ok(t) => println!("{t}"),
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(3);
                    }
                }
            } else {
                print_engines(&engines);
            }
            let ready = engines
                .iter()
                .all(|e| e.info().health == EngineHealth::Ready);
            if ready {
                ExitCode::from(0)
            } else {
                ExitCode::from(2)
            }
        }
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
            max_file_size_mb,
            timeout_secs,
            verbose,
        } => {
            println!(
                "AXSafe {} – Vorversion. Kein Echtzeitschutz. Bitte bisherigen Virenschutz aktiv lassen.",
                axsafe_core::AXSAFE_VERSION
            );
            let engines = build_engines(&engines);
            print_engines(&engines);
            let limits = ScanLimits {
                max_file_size: max_file_size_mb.saturating_mul(1024 * 1024),
                engine_timeout_ms: timeout_secs.saturating_mul(1000),
                ..ScanLimits::default()
            };
            let scanner = Scanner::new(engines, limits);
            println!("Ergebnisse:");
            let cancel = AtomicBool::new(false);
            let rep = scanner.scan_paths(&paths, &cancel, &mut Live { verbose });
            print_summary(&rep);
            if let Some(path) = json {
                let text = match serde_json::to_string_pretty(&rep) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("Bericht nicht serialisierbar: {e}");
                        return ExitCode::from(3);
                    }
                };
                if let Err(e) = std::fs::write(&path, text) {
                    eprintln!("Bericht nicht schreibbar ({}): {e}", path.display());
                    return ExitCode::from(3);
                }
                println!("Bericht:         {}", path.display());
            }
            if rep.summary.detections > 0 {
                ExitCode::from(1)
            } else if !rep.complete {
                ExitCode::from(2)
            } else {
                ExitCode::from(0)
            }
        }
    }
}
