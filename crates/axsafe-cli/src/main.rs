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

mod messung;
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
    /// ClamAV AUSDRÜCKLICH ohne Rechtebeschränkung starten (nur zur Fehlersuche;
    /// wird in der Isolationsangabe sichtbar ausgewiesen)
    #[arg(long)]
    clamav_ohne_abschottung: bool,
    /// ClamAV-Betriebsart: `dauerhaft` (libclamav einmal im isolierten
    /// axsafe-clamav-worker laden, B-18), `clamscan` (je Objekt neu, langsam)
    /// oder `auto` (dauerhaft, wenn der Worker vorhanden ist und kein
    /// --clamscan angegeben wurde)
    #[arg(long, value_enum, default_value_t = ClamAvModus::Auto)]
    clamav_modus: ClamAvModus,
    /// Pfad zum ClamAV-Worker. Standard: axsafe-clamav-worker neben axsafe
    #[arg(long)]
    clamav_worker: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ClamAvModus {
    Auto,
    Dauerhaft,
    Clamscan,
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
    /// ClamAV-Abschottung prüfen (Windows): startet eine Zugriffsprobe mit
    /// GENAU dem eingeschränkten Token, das clamscan bekommt, und prüft
    /// Datenbank, Zertifikatsordner, Arbeitsordner, Benutzerdateien und
    /// optional das Netzwerk
    ClamavAbschottung {
        /// clamscan (Standard: fester Windows-Pfad)
        #[arg(long)]
        clamscan: Option<PathBuf>,
        /// Signaturdatenbank (Standard: fester Windows-Pfad)
        #[arg(long)]
        clamav_db: Option<PathBuf>,
        /// Ausgehende TCP-Verbindung prüfen, z. B. database.clamav.net:443
        #[arg(long)]
        netz_ziel: Option<String>,
        /// Erwartung für --netz-ziel: gesperrt | erlaubt
        #[arg(long, default_value = "gesperrt")]
        netz_erwartet: String,
        /// Nur die Netzprüfung ausführen
        #[arg(long)]
        nur_netz: bool,
        /// Maschinenlesbar als JSON ausgeben
        #[arg(long)]
        json: bool,
    },
    /// Betriebszustand (AXS-019): Scanner, Sensor, Richtlinie, Definitionen,
    /// Primärschutz und Dienst getrennt; nie „geschützt“ ohne Beleg
    Zustand {
        #[command(flatten)]
        engines: EngineArgs,
        /// Maschinenlesbar als JSON ausgeben
        #[arg(long)]
        json: bool,
    },
    /// Richtlinie und Ausnahmen anzeigen bzw. eine Datei prüfen (AXS-017)
    Richtlinie {
        /// Zu prüfende Datei (Standard: die geltende Richtlinie)
        #[arg(long)]
        datei: Option<PathBuf>,
    },
    /// Vorher/Nachher-Messung (B-18): clamscan je Objekt gegen die dauerhaft
    /// geladene ClamAV-Engine auf GENAU denselben Dateien des Ordners
    ClamavMessung {
        /// Ordner mit den Messdateien (nicht rekursiv)
        #[arg(required = true)]
        ordner: PathBuf,
        #[arg(long)]
        clamscan: Option<PathBuf>,
        #[arg(long)]
        clamav_db: Option<PathBuf>,
        #[arg(long)]
        clamav_worker: Option<PathBuf>,
        /// Zeitbudget je Datei in Sekunden
        #[arg(long, default_value_t = 120)]
        zeit: u64,
        /// Höchstzahl Dateien
        #[arg(long, default_value_t = 200)]
        max_dateien: usize,
        /// Ergebnis als JSON in diese NEUE Datei schreiben
        #[arg(long)]
        json: Option<PathBuf>,
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
        if a.clamav_db.is_some() {
            cfg.database = a.clamav_db.clone();
        }
        if a.clamav_ohne_abschottung {
            cfg.sandbox = axsafe_proc::Sandbox::None;
        }
        let worker = a
            .clamav_worker
            .clone()
            .unwrap_or_else(default_clamav_worker);
        let persistent = match a.clamav_modus {
            ClamAvModus::Dauerhaft => true,
            ClamAvModus::Clamscan => false,
            ClamAvModus::Auto => a.clamscan.is_none() && worker.is_file(),
        };
        if persistent {
            let ws = axsafe_engine_clamav::persistent::WorkerSettings::new(worker, &cfg);
            v.push(Box::new(
                axsafe_engine_clamav::persistent::ClamAvWorkerEngine::start(
                    ws,
                    cfg.clamscan.clone(),
                ),
            ));
        } else {
            v.push(Box::new(ClamAvEngine::new(cfg)));
        }
    }
    v
}

/// Geltende Richtlinie (nur angewandt, wenn nur Administratoren sie ändern können).
fn current_policy() -> axsafe_core::policy::Policy {
    axsafe_core::policy::load_policy_checked(
        &axsafe_core::policy::default_policy_path(),
        chrono::Utc::now(),
        axsafe_proc::only_admins_can_modify,
    )
}

/// Was über den Dienst bekannt ist – nur eine gültige Antwort zählt als bereit.
fn service_observation() -> axsafe_core::health::ServiceObservation {
    use axsafe_core::health::ServiceObservation as S;
    if !cfg!(windows) {
        return S::NotApplicable;
    }
    match axsafe_service::client::connect() {
        Err(e) => S::NoAnswer(e.to_string()),
        Ok(mut c) => match c.call(axsafe_service::ipc::Body::Status) {
            Ok(r) if r.ok => S::Ready,
            Ok(r) => S::NoAnswer(format!("Fehlerantwort: {:?}", r.error)),
            Err(e) => S::NoAnswer(e.to_string()),
        },
    }
}

fn print_health(h: &axsafe_core::health::HealthReport) {
    println!("Betriebszustand: {}", h.summary);
    for (name, c) in [
        ("Scanner", &h.scanner),
        ("Echtzeitsensor", &h.sensor),
        ("Richtlinie", &h.policy),
        ("Definitionen", &h.definitions),
        ("Primärschutz", &h.primary_protection),
        ("Dienst", &h.service),
    ] {
        println!("  {name:<15} {:<9} {}", format!("{:?}", c.state), c.detail);
    }
}

fn default_clamav_worker() -> PathBuf {
    let name = format!("axsafe-clamav-worker{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(&name)))
        .unwrap_or_else(|| PathBuf::from(name))
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

/// `axsafe clamav-abschottung`: Zugriffsprobe mit dem eingeschränkten Token.
#[cfg(windows)]
fn clamav_isolation_check(
    clamscan: Option<PathBuf>,
    clamav_db: Option<PathBuf>,
    netz_ziel: Option<String>,
    netz_erwartet: &str,
    nur_netz: bool,
    json: bool,
) -> ExitCode {
    use axsafe_proc::{run_sandboxed, Limits, Sandbox};
    use std::net::ToSocketAddrs;
    let (def_scan, def_db) = axsafe_engine_clamav::windows_default_paths();
    let clamscan = clamscan.unwrap_or(def_scan);
    let db = clamav_db.or(def_db);
    let expect_net_open = match netz_erwartet {
        "gesperrt" => false,
        "erlaubt" => true,
        other => {
            eprintln!("--netz-erwartet: gesperrt oder erlaubt, nicht '{other}'");
            return ExitCode::from(2);
        }
    };
    // (Kennung, Probe-Argument, erwartet erlaubt?)
    let mut plan: Vec<(String, String, bool)> = Vec::new();
    let mut cleanup: Vec<PathBuf> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    if !nur_netz {
        match &db {
            Some(d) => {
                let dir = if d.is_dir() {
                    d.clone()
                } else {
                    d.parent().map(PathBuf::from).unwrap_or_default()
                };
                plan.push((
                    "datenbank_lesbar".into(),
                    format!("lesen:{}", dir.display()),
                    true,
                ));
            }
            None => notes.push("keine Signaturdatenbank im Standardpfad".into()),
        }
        let certs = clamscan
            .parent()
            .map(|p| p.join("certs"))
            .unwrap_or_default();
        plan.push((
            "zertifikate_aufloesbar".into(),
            format!("aufloesen:{}", certs.display()),
            true,
        ));
        plan.push((
            "zertifikate_lesbar".into(),
            format!("lesen:{}", certs.display()),
            true,
        ));
        match axsafe_engine_clamav::new_restricted_work_dir() {
            Ok(w) => {
                plan.push((
                    "arbeitsordner_schreibbar".into(),
                    format!("anlegen:{}", w.display()),
                    true,
                ));
                cleanup.push(w);
            }
            Err(e) => notes.push(format!("Arbeitsordner nicht anlegbar: {e}")),
        }
        // Eine Datei, die nur der Benutzer lesen darf (Benutzer-Temp im Profil).
        let tmp = std::env::temp_dir();
        let secret = tmp.join(format!("axsafe-abschottung-{}.txt", std::process::id()));
        if std::fs::write(&secret, b"nur fuer den Benutzer").is_ok() {
            plan.push((
                "benutzerdatei_unlesbar".into(),
                format!("lesen:{}", secret.display()),
                false,
            ));
            cleanup.push(secret);
        } else {
            notes.push("Testdatei im Benutzer-Temp nicht anlegbar".into());
        }
        plan.push((
            "benutzer_temp_unbeschreibbar".into(),
            format!("anlegen:{}", tmp.display()),
            false,
        ));
        if let Some(pd) = clamscan.parent() {
            plan.push((
                "programmordner_unbeschreibbar".into(),
                format!("anlegen:{}", pd.display()),
                false,
            ));
        }
    }
    if let Some(t) = &netz_ziel {
        // Namensauflösung hier (ohne Einschränkung), damit die Probe nur die
        // Verbindung prüft und nicht an DNS scheitert.
        match t
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.find(|x| x.is_ipv4()))
        {
            Some(addr) => plan.push((
                if expect_net_open {
                    "netz_erlaubt".into()
                } else {
                    "netz_gesperrt".into()
                },
                format!("tcp:{addr}"),
                expect_net_open,
            )),
            None => notes.push(format!(
                "Netzziel {t} nicht auflösbar – Netzprüfung nicht ausführbar"
            )),
        }
    }
    let worker = default_worker();
    // Liegt die Probe im Benutzerprofil (z. B. Desktop), darf das
    // eingeschränkte Token sie sonst nicht starten: nur diese eine Datei freigeben.
    if let Err(e) = axsafe_proc::restricted_grant_execute(&worker) {
        notes.push(format!("Probe {} nicht freigebbar: {e}", worker.display()));
    }
    let mut c = std::process::Command::new(&worker);
    c.arg("--zugriffsprobe");
    for (_, a, _) in &plan {
        c.arg(a);
    }
    c.env_clear();
    for (k, v) in axsafe_proc::minimal_env() {
        c.env(k, v);
    }
    let limits = Limits {
        timeout: std::time::Duration::from_secs(30),
        ..Limits::default()
    };
    let run = run_sandboxed(c, None, &limits, &Sandbox::Restricted);
    for p in &cleanup {
        let _ = if p.is_dir() {
            std::fs::remove_dir_all(p)
        } else {
            std::fs::remove_file(p)
        };
    }
    let mut checks = Vec::new();
    let mut all_ok = notes.is_empty();
    match run {
        Err(e) => {
            all_ok = false;
            notes.push(format!(
                "Probe mit eingeschränktem Token nicht startbar: {e}"
            ));
        }
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout).to_string();
            let lines: Vec<serde_json::Value> = out
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            if lines.len() != plan.len() || o.timed_out {
                all_ok = false;
                notes.push(format!(
                    "Probe unvollständig ({} von {} Ergebnissen, Zeitüberschreitung: {}): {}",
                    lines.len(),
                    plan.len(),
                    o.timed_out,
                    String::from_utf8_lossy(&o.stderr)
                ));
            }
            for ((id, arg, expected), l) in plan.iter().zip(lines.iter()) {
                let allowed = l["allowed"].as_bool().unwrap_or(!expected);
                let ok = allowed == *expected;
                all_ok &= ok;
                checks.push(serde_json::json!({
                    "id": id, "probe": arg, "expected_allowed": expected,
                    "allowed": allowed, "ok": ok, "detail": l["detail"],
                }));
            }
        }
    }
    let rep = serde_json::json!({
        "sandbox": "eingeschränktes Token (wie clamscan): keine Privilegien, Integrität Niedrig, Einschränkungs-SIDs RESTRICTED/Jeder/Benutzer/Anmelde-SID; Token vor dem Start geprüft",
        "probe": worker.display().to_string(),
        "ok": all_ok, "checks": checks, "notes": notes,
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
    } else {
        for c in rep["checks"].as_array().into_iter().flatten() {
            println!(
                "{} {}: {} ({})",
                if c["ok"].as_bool() == Some(true) {
                    "OK  "
                } else {
                    "FEHL"
                },
                c["id"].as_str().unwrap_or(""),
                if c["allowed"].as_bool() == Some(true) {
                    "erlaubt"
                } else {
                    "verweigert"
                },
                c["detail"].as_str().unwrap_or("")
            );
        }
        for n in &notes {
            println!("HINWEIS {n}");
        }
    }
    if all_ok {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    }
}

#[cfg(not(windows))]
fn clamav_isolation_check(
    _: Option<PathBuf>,
    _: Option<PathBuf>,
    _: Option<String>,
    _: &str,
    _: bool,
    _: bool,
) -> ExitCode {
    eprintln!("Die ClamAV-Abschottung mit eingeschränktem Token gibt es nur unter Windows.");
    ExitCode::from(2)
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
        Cmd::ClamavAbschottung {
            clamscan,
            clamav_db,
            netz_ziel,
            netz_erwartet,
            nur_netz,
            json,
        } => clamav_isolation_check(
            clamscan,
            clamav_db,
            netz_ziel,
            &netz_erwartet,
            nur_netz,
            json,
        ),
        Cmd::Zustand { engines, json } => {
            let built = build_engines(&engines, None);
            let infos: Vec<EngineInfo> = built.iter().map(|e| e.info()).collect();
            let h = axsafe_core::health::derive(
                Some(&infos),
                &service_observation(),
                &current_policy().observation(),
                chrono::Utc::now(),
            );
            if json {
                println!("{}", serde_json::to_string_pretty(&h).unwrap_or_default());
            } else {
                print_health(&h);
            }
            match h.overall {
                axsafe_core::health::Overall::Geschuetzt
                | axsafe_core::health::Overall::Eingeschraenkt => ExitCode::from(0),
                axsafe_core::health::Overall::NichtBetriebsbereit => ExitCode::from(2),
                axsafe_core::health::Overall::Unbekannt => ExitCode::from(3),
            }
        }
        Cmd::Richtlinie { datei } => {
            let path = datei.unwrap_or_else(axsafe_core::policy::default_policy_path);
            let p = axsafe_core::policy::load_policy_checked(
                &path,
                chrono::Utc::now(),
                axsafe_proc::only_admins_can_modify,
            );
            println!("Richtlinie: {} ({})", p.version, p.source);
            if let Some(e) = &p.invalid {
                println!("UNGÜLTIG – es gilt die Vorgabe ohne Ausnahmen: {e}");
            }
            for x in &p.exclusions {
                println!(
                    "  Ausnahme {:?} {} – {} (von {}, bis {})",
                    x.kind, x.path, x.reason, x.created_by, x.expires_utc
                );
            }
            if p.expired > 0 {
                println!(
                    "  {} abgelaufene Ausnahme(n) werden nicht angewandt",
                    p.expired
                );
            }
            if p.invalid.is_some() {
                ExitCode::from(2)
            } else {
                ExitCode::from(0)
            }
        }
        Cmd::ClamavMessung {
            ordner,
            clamscan,
            clamav_db,
            clamav_worker,
            zeit,
            max_dateien,
            json,
        } => {
            let mut cfg = ClamAvConfig::default();
            if let Some(p) = clamscan {
                cfg.clamscan = p;
            }
            if clamav_db.is_some() {
                cfg.database = clamav_db;
            }
            let r = messung::measure(messung::Args {
                dir: ordner,
                cfg,
                worker: clamav_worker.unwrap_or_else(default_clamav_worker),
                timeout: std::time::Duration::from_secs(zeit),
                max_files: max_dateien,
            });
            match r {
                Ok(r) => {
                    messung::print(&r);
                    if let Some(p) = json {
                        let t = serde_json::to_string_pretty(&r).unwrap_or_default();
                        let w = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&p)
                            .and_then(|mut f| std::io::Write::write_all(&mut f, t.as_bytes()));
                        if let Err(e) = w {
                            eprintln!("{}: {e}", p.display());
                            return ExitCode::from(3);
                        }
                    }
                    if r.results_identical {
                        ExitCode::from(0)
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(2)
                }
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
            let policy = current_policy();
            if let Some(e) = &policy.invalid {
                eprintln!(
                    "Hinweis: Richtlinie {} nicht angewandt ({e}) – Vorgabe ohne Ausnahmen",
                    policy.source
                );
            }
            let mut scanner = Scanner::new(engines, limits)
                .classify_in_engine(!yara_in_process)
                .with_policy(std::sync::Arc::new(policy));
            print_engines(&scanner.engine_infos());
            if let Some(t) = &target {
                scanner.exclude_identity(t.identity().clone(), "Berichtsdatei dieses Auftrags");
            }
            println!("Ergebnisse:");
            let cancel = AtomicBool::new(false);
            let mut rep = scanner.scan_job(job_id, &paths, &cancel, &mut Live { verbose });
            // Herkunft (AXS-016): dieser CLI-Prozess mit PID UND Startzeit.
            let me = axsafe_proc::current_process().ok();
            rep.executed_by = Some(axsafe_core::report::ExecutedBy {
                kind: "cli".into(),
                name: "axsafe".into(),
                account: std::env::var("USERNAME")
                    .or_else(|_| std::env::var("USER"))
                    .unwrap_or_default(),
                process_id: std::process::id(),
                client: None,
                client_session: None,
                process: me.map(|p| {
                    axsafe_core::report::ProcessIdentity::new(p.pid, p.start_unix_ns, p.image)
                }),
                client_process: None,
            });
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
