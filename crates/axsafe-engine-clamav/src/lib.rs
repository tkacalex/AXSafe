//! ClamAV Engineadapter (AXS-021, T-021).
//!
//! * ClamAV läuft als **getrennter Prozess** (`clamscan`). Es wird **kein**
//!   `clamd` und keine TCP-Schnittstelle geöffnet (ClamAV-Doku: TCP ohne
//!   Authentifizierung).
//! * Der Inhalt wird über **stdin** übergeben. ClamAV prüft damit exakt den
//!   Schnappschuss, den AXSafe gehasht hat, nicht einen später erneut
//!   geöffneten Pfad.
//! * Der Aufruf läuft über [`axsafe_proc`]: **ein** gemeinsames Ablaufdatum
//!   für Prozess, Eingabe und Ausgabe; Nachkommen werden kontrolliert
//!   (Windows: Job Object); Ausgabe und Speicher sind begrenzt (Befund 4).
//! * Fund und Prüflücke werden getrennt gemeldet: Eine Zeile kann ein Fund
//!   sein, eine andere eine Lücke (verschlüsselt, Grenzwert) – beides bleibt
//!   sichtbar (Befund 2).
//! * Welche Containerformate ClamAV **inhaltlich** prüft, steht verbindlich in
//!   [`VERIFIED_CONTENT_FORMATS`]; jedes Format ist durch einen Test mit
//!   echtem ClamAV belegt (Befund 3).
//! * Signaturquelle wird ausgewiesen: offizielle Signaturen, eigene Datenbank
//!   oder ausschließlich AXSafe-Testsignaturen (Befund 7).
//!
//! Lizenz: ClamAV steht unter GPL-2.0. AXSafe ruft das separat installierte
//! Programm auf und verteilt es in dieser Vorversion **nicht** mit.

#![forbid(unsafe_code)]

pub mod persistent;

use axsafe_core::engine::{
    ContentKind, Detection, Engine, EngineHealth, EngineInfo, EngineOutcome, Gap, GapReason,
    ScanInput,
};
use axsafe_core::filetype::ContentFormat;
use axsafe_core::verdict::{aggregate, Confidence, Severity, Verdict};
use axsafe_proc::{run_sandboxed, Limits, RunOutcome, Sandbox};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Containerformate, deren **Inhalt** ClamAV nachweislich prüft.
/// Nur Formate mit bestandenem Integrationstest (`tests/clamav_real.rs`,
/// `content_formats_are_backed_by_real_clamav`). RAR (abhängig von
/// unrar-Unterstützung der Installation), ISO, RTF und VHDX fehlen bewusst.
pub const VERIFIED_CONTENT_FORMATS: [ContentFormat; 8] = [
    ContentFormat::Zip,
    ContentFormat::Ooxml,
    ContentFormat::Gzip,
    ContentFormat::OleCfb,
    ContentFormat::Cab,
    ContentFormat::SevenZip,
    ContentFormat::Pdf,
    ContentFormat::Iso,
];

/// RAR-Inhalt prüft libclamav nur mit der Zusatzbibliothek
/// `libclamunrar_iface`, die ClamAV unter genau diesem Namen neben libclamav
/// sucht (Unix: mit derselben Versionsendung wie libclamav). Das offizielle
/// Windows-Paket enthält sie; unter Debian/Ubuntu fehlt sie meist. Fehlt sie,
/// wird RAR NICHT als geprüft beansprucht (Lücke `content_not_inspected`).
pub fn unrar_available(libclamav: &std::path::Path) -> bool {
    let Some(dir) = libclamav.parent() else {
        return false;
    };
    if cfg!(windows) {
        return dir.join("libclamunrar_iface.dll").is_file();
    }
    let real = std::fs::canonicalize(libclamav).unwrap_or_else(|_| libclamav.to_path_buf());
    let Some(name) = real.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(suffix) = name.strip_prefix("libclamav") else {
        return false;
    };
    real.parent()
        .unwrap_or(dir)
        .join(format!("libclamunrar_iface{suffix}"))
        .is_file()
}

/// Belegte Inhaltsformate dieser Installation (RAR nur mit unrar).
pub fn content_formats(libclamav: &std::path::Path) -> Vec<ContentFormat> {
    let mut v = VERIFIED_CONTENT_FORMATS.to_vec();
    if unrar_available(libclamav) {
        v.push(ContentFormat::Rar);
    }
    v
}

/// Konfiguration des Adapters.
#[derive(Debug, Clone)]
pub struct ClamAvConfig {
    /// Pfad zu `clamscan` (Standard: aus `PATH`).
    pub clamscan: PathBuf,
    /// Eigene Signaturdatenbank (Datei oder Verzeichnis). `None` = ClamAV-Standard.
    pub database: Option<PathBuf>,
    /// Interne ClamAV-Limits (MB), damit Archive den Host nicht überlasten.
    pub max_filesize_mb: u32,
    pub max_scansize_mb: u32,
    pub max_recursion: u32,
    /// Speichergrenze für den clamscan-Prozess (Signaturdatenbank braucht viel).
    pub max_memory_bytes: u64,
    /// Höchstmenge der Ausgabe je Kanal.
    pub max_output_bytes: usize,
    /// Rechtebeschränkung für clamscan. Windows-Standard:
    /// [`Sandbox::Restricted`] (eingeschränktes Token, Integrität Niedrig).
    /// AppContainer ist für ClamAV 1.5 nicht möglich: Im AppContainer
    /// verweigert Windows `GetFinalPathNameByHandleW` mit DOS-/GUID-Namen
    /// (gemessen in CI, Test `appcontainer_path_resolution_is_measured`),
    /// ClamAV braucht das für seinen Zertifikatsordner. `Sandbox::None` nur
    /// nach ausdrücklicher Entscheidung (`--clamav-ohne-abschottung`),
    /// sichtbar in der Isolationsangabe.
    pub sandbox: Sandbox,
}

/// AppContainer-Profil für clamscan (nur noch für Messungen; siehe
/// [`ClamAvConfig::sandbox`]).
pub const CLAMAV_APPCONTAINER: &str = "AXSafe.ClamAV.v1";

/// Feste Windows-Pfade der von `scripts/windows/setup-clamav.ps1`
/// eingerichteten Installation. AXSafe sucht ClamAV unter Windows bewusst
/// NICHT über `PATH` (unkontrollierbar, und laufende Prozesse sehen
/// PATH-Änderungen nicht), sondern nur hier oder über `--clamscan`.
pub fn windows_default_paths() -> (PathBuf, Option<PathBuf>) {
    let pf = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    let pd = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let db = pd.join("AXSafe").join("ClamAV").join("database");
    (
        pf.join("ClamAV").join("clamscan.exe"),
        db.is_dir().then_some(db),
    )
}

impl Default for ClamAvConfig {
    fn default() -> Self {
        let (clamscan, database) = if cfg!(windows) {
            windows_default_paths()
        } else {
            // Entwicklung/CI unter Linux: Paketinstallation über PATH.
            (PathBuf::from("clamscan"), None)
        };
        ClamAvConfig {
            clamscan,
            database,
            max_filesize_mb: 100,
            max_scansize_mb: 400,
            max_recursion: 17,
            max_memory_bytes: 4 * 1024 * 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            sandbox: if cfg!(windows) {
                Sandbox::Restricted
            } else {
                Sandbox::None
            },
        }
    }
}

/// ClamAV-Engine über `clamscan`.
pub struct ClamAvEngine {
    cfg: ClamAvConfig,
    engine_version: String,
    content_version: String,
    content_kind: ContentKind,
    content_note: String,
    content_time_utc: Option<String>,
    health: EngineHealth,
    /// Arbeitsordner für entpackte Archivinhalte (AppContainer: dessen
    /// eigener Ordner).
    tempdir: Option<std::path::PathBuf>,
    /// Arbeitsordner gehört dieser Instanz und wird beim Ende entfernt.
    owns_tempdir: bool,
    /// Höchster gemessener Speicherbedarf eines clamscan-Laufs (Windows: Job
    /// Object; nur für Messungen).
    peak_memory: std::sync::atomic::AtomicU64,
}

impl ClamAvEngine {
    /// Höchster Speicherbedarf eines clamscan-Laufs, soweit das System ihn
    /// misst (Windows: Job Object). `None` = nicht gemessen.
    pub fn peak_memory_bytes(&self) -> Option<u64> {
        match self.peak_memory.load(std::sync::atomic::Ordering::Relaxed) {
            0 => None,
            p => Some(p),
        }
    }
}

impl Drop for ClamAvEngine {
    fn drop(&mut self) {
        if self.owns_tempdir {
            if let Some(t) = &self.tempdir {
                let _ = std::fs::remove_dir_all(t);
            }
        }
    }
}

/// Legt einen NEUEN Arbeitsordner für clamscan mit eingeschränktem Token an
/// (je Engine-Instanz eigener Ordner – parallele Instanzen setzen sonst
/// gleichzeitig Rechte auf denselben Ordner; in CI beobachtet: „Can't write
/// to temporary directory“). Integrität Niedrig, Ändern nur für RESTRICTED.
#[cfg(windows)]
pub fn new_restricted_work_dir() -> std::io::Result<std::path::PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("AXSafe")
        .join("ClamAV-Arbeitsordner");
    std::fs::create_dir_all(&base)?;
    let dir = base.join(format!(
        "{}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0)
    ));
    std::fs::create_dir(&dir)?;
    axsafe_proc::restricted_work_dir(&dir)?;
    Ok(dir)
}

fn first_line(s: &[u8]) -> String {
    let s = String::from_utf8_lossy(s);
    let line = s
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    line.chars().take(300).collect()
}

/// Ordnet einen ClamAV-Fundnamen einer AXSafe-Bewertung zu.
pub fn classify(name: &str) -> (Verdict, Severity, Confidence) {
    if name.starts_with("Heuristics.Encrypted") {
        (Verdict::Encrypted, Severity::Info, Confidence::High)
    } else if name.starts_with("Heuristics.Limits.Exceeded") {
        (Verdict::Unsupported, Severity::Info, Confidence::High)
    } else if name.starts_with("PUA.") {
        (Verdict::Pua, Severity::Low, Confidence::Medium)
    } else if name.starts_with("Heuristics.") {
        (Verdict::Suspicious, Severity::Medium, Confidence::Low)
    } else {
        (Verdict::Malicious, Severity::High, Confidence::Medium)
    }
}

fn is_test_signature(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("eicar") || n.starts_with("axsafe.test.")
}

fn db_files(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if path.is_dir() {
        for e in std::fs::read_dir(path)? {
            let p = e?.path();
            if p.is_file() {
                files.push(p);
            }
        }
    } else {
        files.push(path.to_path_buf());
    }
    files.sort();
    Ok(files)
}

/// Kopf einer offiziellen Datenbankdatei (CVD/CLD): die ersten 512 Bytes,
/// `ClamAV-VDB:<Erstellt>:<Version>:<Signaturen>:…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvdHeader {
    pub built: String,
    pub version: u64,
    pub signatures: u64,
}

pub fn cvd_header(path: &Path) -> Option<CvdHeader> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut b = [0u8; 512];
    let mut n = 0;
    while n < b.len() {
        match f.read(&mut b[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return None,
        }
    }
    let text = std::str::from_utf8(&b[..n]).ok()?;
    let text = text.trim_end_matches(['\0', ' ']);
    let mut it = text.split(':');
    if it.next()? != "ClamAV-VDB" {
        return None;
    }
    let built = it.next()?.trim().to_string();
    let version = it.next()?.trim().parse().ok()?;
    let signatures = it.next()?.trim().parse().ok()?;
    Some(CvdHeader {
        built,
        version,
        signatures,
    })
}

/// Stand der offiziellen Datenbanken (main, daily, bytecode) eines Ordners.
fn official_versions(files: &[PathBuf]) -> Vec<(String, CvdHeader)> {
    let mut v = Vec::new();
    for name in ["main", "daily", "bytecode"] {
        // CLD (inkrementell aktualisiert) hat Vorrang vor CVD.
        for ext in ["cld", "cvd"] {
            if let Some(f) = files.iter().find(|f| {
                f.file_stem().and_then(|s| s.to_str()) == Some(name)
                    && f.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.eq_ignore_ascii_case(ext))
                        .unwrap_or(false)
            }) {
                if let Some(h) = cvd_header(f) {
                    v.push((name.to_string(), h));
                    break;
                }
            }
        }
    }
    v
}

fn database_digest(files: &[PathBuf]) -> std::io::Result<String> {
    let mut h = Sha256::new();
    for f in files {
        h.update(
            f.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        h.update([0]);
        h.update(std::fs::read(f)?);
    }
    Ok(format!("db-sha256:{}", &hex::encode(h.finalize())[..16]))
}

/// Bestimmt die Art einer eigenen Signaturdatenbank.
fn classify_database(files: &[PathBuf]) -> (ContentKind, String) {
    let official = ["main", "daily", "bytecode"];
    let mut has_official = false;
    let mut names = Vec::new();
    let mut text_sigs = 0usize;
    let mut test_sigs = 0usize;
    for f in files {
        let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let ext = f
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        names.push(
            f.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        if official.contains(&stem) && matches!(ext.as_str(), "cvd" | "cld" | "cud") {
            has_official = true;
            continue;
        }
        let field = match ext.as_str() {
            "hdb" | "hsb" | "hdu" | "hsu" | "mdb" | "msb" => Some(2usize),
            "ndb" | "ndu" | "ldb" | "ldu" => Some(0usize),
            _ => None,
        };
        if let (Some(idx), Ok(text)) = (field, std::fs::read_to_string(f)) {
            for line in text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
            {
                text_sigs += 1;
                let name = line.split([':', ';']).nth(idx).unwrap_or("");
                if name.starts_with("AXSafe.Test.") {
                    test_sigs += 1;
                }
            }
        }
    }
    if has_official {
        (
            ContentKind::OfficialSignatures,
            format!(
                "offizielle ClamAV-Datenbank in eigenem Pfad ({})",
                names.join(", ")
            ),
        )
    } else if text_sigs > 0 && text_sigs == test_sigs {
        (
            ContentKind::TestOnly,
            format!(
                "nur AXSafe-Testsignaturen ({test_sigs}) – keine Erkennung echter Schadsoftware ({})",
                names.join(", ")
            ),
        )
    } else {
        (
            ContentKind::CustomSignatures,
            format!(
                "eigene, nicht offizielle Signaturdatenbank ({})",
                names.join(", ")
            ),
        )
    }
}

/// Stand einer Signaturdatenbank, aus den Dateien bestimmt (ohne ClamAV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbContent {
    /// z. B. `main-63/daily-28164/bytecode-339` oder `db-sha256:…`.
    pub version: String,
    pub kind: ContentKind,
    pub note: String,
    /// Version der daily-Datenbank laut Dateikopf (nur offizielle Datenbank).
    pub daily: Option<u64>,
    /// Erstellungszeit der daily-Datenbank (UTC, RFC 3339) laut Dateikopf.
    pub daily_time_utc: Option<String>,
}

/// Zeit aus dem CVD-Kopf („25 Oct 2026 06-24 +0000“) als UTC-Zeitstempel.
pub fn cvd_time_utc(built: &str) -> Option<String> {
    chrono::DateTime::parse_from_str(built.trim(), "%d %b %Y %H-%M %z")
        .ok()
        .map(|t| {
            t.with_timezone(&chrono::Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        })
}

/// Liest den Stand einer Datenbank (Ordner oder Datei). Offizielle
/// Datenbanken nur über die Dateiköpfe (schnell), eigene über eine Prüfsumme.
pub fn database_content(db: &Path) -> Result<DbContent, String> {
    let files = db_files(db)
        .map_err(|e| format!("Signaturdatenbank {} nicht lesbar: {e}", db.display()))?;
    let official = official_versions(&files);
    if let Some((_, d)) = official.iter().find(|(n, _)| n == "daily") {
        let daily = d.version;
        let version = official
            .iter()
            .map(|(n, h)| format!("{n}-{}", h.version))
            .collect::<Vec<_>>()
            .join("/");
        let details = official
            .iter()
            .map(|(n, h)| {
                format!(
                    "{n} {} ({} Signaturen, {})",
                    h.version, h.signatures, h.built
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let (kind, _) = classify_database(&files);
        return Ok(DbContent {
            version,
            kind,
            note: format!(
                "offizielle ClamAV-Signaturen: {details}; Pfad {}. Aktualisierung über \
                 FreshClam (geplanter Auftrag), Stand siehe state\\last-update.json",
                db.display()
            ),
            daily: Some(daily),
            daily_time_utc: cvd_time_utc(&d.built),
        });
    }
    let d = database_digest(&files)
        .map_err(|e| format!("Signaturdatenbank {} nicht lesbar: {e}", db.display()))?;
    let (kind, note) = classify_database(&files);
    Ok(DbContent {
        version: d,
        kind,
        note,
        daily: None,
        daily_time_utc: None,
    })
}

impl ClamAvEngine {
    /// Prüft Programm und Datenbank sofort. Fehler ergeben `Unavailable`.
    pub fn new(cfg: ClamAvConfig) -> Self {
        let mut engine = ClamAvEngine {
            cfg,
            engine_version: "unbekannt".into(),
            content_version: "unbekannt".into(),
            content_kind: ContentKind::Unknown,
            content_note: "nicht geprüft".into(),
            content_time_utc: None,
            health: EngineHealth::Unavailable {
                reason: "nicht geprüft".into(),
            },
            tempdir: None,
            owns_tempdir: false,
            peak_memory: std::sync::atomic::AtomicU64::new(0),
        };
        if let Err(e) = engine.prepare_sandbox() {
            engine.unavailable(format!(
                "ClamAV-Abschottung nicht vorbereitbar: {e} – ClamAV wird nicht ohne Abschottung genutzt"
            ));
            return engine;
        }
        engine.probe();
        engine
    }

    /// AppContainer vorbereiten: eigenen Arbeitsordner ermitteln und – wenn
    /// der Aufrufer es darf – der Datenbank Lesezugriff geben. Die offizielle
    /// Datenbank unter ProgramData gibt setup-clamav.ps1 frei.
    #[cfg(windows)]
    fn prepare_sandbox(&mut self) -> std::io::Result<()> {
        if let Sandbox::Restricted = &self.cfg.sandbox {
            // Eigener Arbeitsordner (Integritätsstufe Niedrig, nur dort
            // schreibbar); Datenbank lesbar für RESTRICTED, falls der Ordner
            // uns gehört (der Standardordner ist für Benutzer bereits lesbar).
            let tmp = new_restricted_work_dir()?;
            self.tempdir = Some(tmp);
            self.owns_tempdir = true;
            if let Some(db) = &self.cfg.database {
                let dir = if db.is_dir() {
                    db.clone()
                } else {
                    db.parent().map(|p| p.to_path_buf()).unwrap_or_default()
                };
                let _ = axsafe_proc::restricted_grant_read(&dir);
            }
        }
        if let Sandbox::AppContainer { profile } = &self.cfg.sandbox {
            let tmp = axsafe_proc::appcontainer_folder(profile)?.join("Temp");
            std::fs::create_dir_all(&tmp)?;
            self.tempdir = Some(tmp);
            if let Some(db) = &self.cfg.database {
                let dir = if db.is_dir() {
                    db.clone()
                } else {
                    db.parent().map(|p| p.to_path_buf()).unwrap_or_default()
                };
                // Scheitert bei fremden Ordnern (z. B. ProgramData) – dort
                // hat die Einrichtung die Freigabe bereits gesetzt.
                let _ = axsafe_proc::appcontainer_grant(profile, &dir, false);
            }
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn prepare_sandbox(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn isolation(&self) -> axsafe_core::engine::Isolation {
        use axsafe_core::engine::{Isolation, IsolationKind};
        match (&self.cfg.sandbox, &self.health) {
            (Sandbox::AppContainer { profile }, EngineHealth::Ready) => Isolation {
                kind: IsolationKind::SandboxedWorker,
                enforced: true,
                detail: format!(
                    "AppContainer {profile} ohne Fähigkeiten (Token vor dem Start geprüft), Job \
                     Object (Zeit, Speicher, Prozessbaum); Signaturdatenbank nur lesbar \
                     freigegeben. Verhaltensprobe nicht möglich (fremdes Programm)"
                ),
            },
            (Sandbox::AppContainer { profile }, _) => Isolation {
                kind: IsolationKind::SandboxedWorker,
                enforced: false,
                detail: format!("AppContainer {profile} vorgesehen, Start nicht gelungen"),
            },
            (Sandbox::Restricted, EngineHealth::Ready) => Isolation {
                kind: IsolationKind::SandboxedWorker,
                enforced: true,
                detail: "Eingeschränktes Token (Token vor dem Start geprüft): keine Privilegien, \
                         Integritätsstufe Niedrig, kein Zugriff auf Dateien, die nur der \
                         Benutzer lesen darf; schreiben nur im eigenen Arbeitsordner; Job Object \
                         (Zeit, Speicher, Prozessbaum). Netzwerk über diese Abschottung NICHT \
                         gesperrt (ausgehende Firewall-Sperrregel durch die Einrichtung). \
                         AppContainer nicht möglich: ClamAV 1.5 kann dort seinen \
                         Zertifikatsordner nicht auflösen"
                    .into(),
            },
            (Sandbox::Restricted, _) => Isolation {
                kind: IsolationKind::SandboxedWorker,
                enforced: false,
                detail: "eingeschränktes Token vorgesehen, Start nicht gelungen".into(),
            },
            (Sandbox::None, _) if cfg!(windows) => Isolation {
                kind: IsolationKind::ChildProcess,
                enforced: false,
                detail: "AUSDRÜCKLICH ohne Abschottung gestartet (--clamav-ohne-abschottung): \
                         eigener Prozess im Job Object, aber mit den Rechten des Benutzers"
                    .into(),
            },
            (Sandbox::None, _) => Isolation {
                kind: IsolationKind::ChildProcess,
                enforced: false,
                detail: "Linux (Entwicklung): eigener Prozess in eigener Prozessgruppe (Zeit, \
                         Speicher begrenzt), keine Rechtebeschränkung für clamscan"
                    .into(),
            },
        }
    }

    fn sandboxed(&self) -> bool {
        matches!(
            self.cfg.sandbox,
            Sandbox::AppContainer { .. } | Sandbox::Restricted
        )
    }

    fn base_command(&self) -> Command {
        let mut c = Command::new(&self.cfg.clamscan);
        if self.sandboxed() {
            // Nur die minimale Umgebung; Temp zeigt in den AppContainer-Ordner.
            c.env_clear();
            c.envs(axsafe_proc::minimal_env());
            if let Some(t) = &self.tempdir {
                c.env("TEMP", t)
                    .env("TMP", t)
                    .arg(format!("--tempdir={}", t.display()));
            }
        }
        c.arg("--no-summary")
            .arg("--stdout")
            .arg("--alert-encrypted=yes")
            .arg("--alert-exceeds-max=yes")
            .arg(format!("--max-filesize={}M", self.cfg.max_filesize_mb))
            .arg(format!("--max-scansize={}M", self.cfg.max_scansize_mb))
            .arg(format!("--max-recursion={}", self.cfg.max_recursion));
        if let Some(db) = &self.cfg.database {
            c.arg(format!("--database={}", db.display()));
        }
        c
    }

    fn limits(&self, timeout: Duration) -> Limits {
        Limits {
            timeout,
            max_output_bytes: self.cfg.max_output_bytes,
            max_memory_bytes: Some(self.cfg.max_memory_bytes),
            max_processes: Some(4),
        }
    }

    fn unavailable(&mut self, reason: String) {
        self.health = EngineHealth::Unavailable { reason };
    }

    fn probe(&mut self) {
        let mut v = Command::new(&self.cfg.clamscan);
        if self.sandboxed() {
            v.env_clear();
            v.envs(axsafe_proc::minimal_env());
        }
        v.arg("--version");
        match run_sandboxed(
            v,
            None,
            &self.limits(Duration::from_secs(15)),
            &self.cfg.sandbox,
        ) {
            Ok(o) if o.clean_success() => {
                // Format: "ClamAV 1.5.4" oder "ClamAV 1.5.4/27789/Fri Oct 23 09:28:02 2026"
                let line = first_line(&o.stdout);
                let mut parts = line.splitn(3, '/');
                self.engine_version = parts.next().unwrap_or("").trim().to_string();
                if self.cfg.database.is_none() {
                    match (parts.next(), parts.next()) {
                        (Some(daily), Some(date)) => {
                            self.content_version = format!("daily-{daily}");
                            self.content_kind = ContentKind::OfficialSignatures;
                            self.content_note = format!(
                                "offizielle ClamAV-Signaturen, daily {daily} vom {date}. \
                                 Aktualisierungspfad (FreshClam) separat nachzuweisen."
                            );
                        }
                        _ => {
                            self.content_kind = ContentKind::Unknown;
                            self.content_note =
                                "keine Signaturdatenbank im Standardpfad erkannt".into();
                        }
                    }
                }
            }
            Ok(o) => {
                return self.unavailable(format!(
                    "clamscan --version fehlgeschlagen (Status {:?}{}): {}",
                    o.code(),
                    if o.timed_out {
                        ", Zeitüberschreitung"
                    } else {
                        ""
                    },
                    first_line(&o.stderr)
                ));
            }
            Err(e) => {
                return self.unavailable(format!(
                    "clamscan nicht startbar ({}): {e}",
                    self.cfg.clamscan.display()
                ));
            }
        }
        if let Some(db) = self.cfg.database.clone() {
            match database_content(&db) {
                Ok(c) => {
                    self.content_version = c.version;
                    self.content_kind = c.kind;
                    self.content_note = c.note;
                    self.content_time_utc = c.daily_time_utc;
                }
                Err(e) => return self.unavailable(e),
            }
        }
        // Echter Funktionstest: leere Eingabe muss sauber geprüft werden.
        // Schlägt fehl, wenn z. B. keine Signaturdatenbank vorhanden ist.
        let mut c = self.base_command();
        c.arg("-");
        match run_sandboxed(
            c,
            Some(Vec::new()),
            &self.limits(Duration::from_secs(120)),
            &self.cfg.sandbox,
        ) {
            Ok(o) if o.clean_success() => self.health = EngineHealth::Ready,
            Ok(o) if o.timed_out => self
                .unavailable("Funktionstest: Zeitüberschreitung beim Laden der Datenbank".into()),
            Ok(o) => {
                let mut msg = first_line(&o.stderr);
                if msg.is_empty() {
                    msg = first_line(&o.stdout);
                }
                if o.descendants_terminated {
                    msg = format!("Engine hinterließ laufende Nachkommen. {msg}");
                }
                self.unavailable(format!(
                    "Funktionstest fehlgeschlagen (Status {:?}): {msg}",
                    o.code()
                ))
            }
            Err(e) => self.unavailable(format!("Funktionstest nicht startbar: {e}")),
        }
    }

    fn outcome(&self, start: Instant) -> EngineOutcome {
        EngineOutcome {
            engine: "clamav".into(),
            engine_version: self.engine_version.clone(),
            content_version: self.content_version.clone(),
            verdict: Verdict::NoDetection,
            detections: Vec::new(),
            gaps: Vec::new(),
            note: None,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn failed(
        &self,
        start: Instant,
        state: Verdict,
        reason: GapReason,
        detail: String,
    ) -> EngineOutcome {
        let mut o = self.outcome(start);
        o.verdict = state;
        o.note = Some(detail.clone());
        o.gaps.push(Gap::new(state, reason, "clamav", detail));
        o
    }

    /// Wertet einen begrenzten Prozesslauf aus. Öffentlich für Tests.
    pub fn interpret(&self, run: &RunOutcome, start: Instant, budget: Duration) -> EngineOutcome {
        if run.timed_out {
            return self.failed(
                start,
                Verdict::Timeout,
                GapReason::EngineTimeout,
                format!(
                    "gemeinsames Zeitbudget von {} ms überschritten (Prozess, Eingabe oder Ausgabe); Prozessbaum beendet",
                    budget.as_millis()
                ),
            );
        }
        if run.output_truncated {
            return self.failed(
                start,
                Verdict::Error,
                GapReason::OutputLimit,
                format!(
                    "Ausgabe über {} Bytes; Prozess beendet, Ergebnis verworfen",
                    self.cfg.max_output_bytes
                ),
            );
        }
        if run.descendants_terminated {
            return self.failed(
                start,
                Verdict::Error,
                GapReason::EngineError,
                "Engine-Prozess hinterließ laufende Nachkommen; diese wurden beendet, Ergebnis verworfen".into(),
            );
        }
        if run.stdin_incomplete {
            return self.failed(
                start,
                Verdict::Error,
                GapReason::EngineError,
                "Inhalt konnte nicht vollständig an die Engine übergeben werden".into(),
            );
        }
        let stdout = String::from_utf8_lossy(&run.stdout);
        let mut out = self.outcome(start);
        let mut saw_ok = false;
        let mut verdicts = Vec::new();
        for line in stdout.lines() {
            let Some(rest) = line.strip_prefix("stdin: ") else {
                continue;
            };
            if rest.trim() == "OK" {
                saw_ok = true;
            } else if let Some(name) = rest.strip_suffix(" FOUND") {
                let name = name.trim().to_string();
                let (verdict, severity, confidence) = classify(&name);
                verdicts.push(verdict);
                if verdict.is_detection() {
                    out.detections.push(Detection {
                        rule_version: None,
                        evidence: vec![format!("ClamAV-Signatur {name}")],
                        test_signature: is_test_signature(&name),
                        rule_id: Some(name.clone()),
                        name,
                        verdict,
                        severity,
                        confidence,
                    });
                } else {
                    let reason = if verdict == Verdict::Encrypted {
                        GapReason::Encrypted
                    } else {
                        GapReason::EngineLimitExceeded
                    };
                    out.gaps.push(Gap::new(
                        verdict,
                        reason,
                        "clamav",
                        format!("ClamAV meldet {name}"),
                    ));
                }
            }
        }
        match run.code() {
            Some(0) if saw_ok && verdicts.is_empty() => out,
            Some(1) if !verdicts.is_empty() => {
                out.verdict = aggregate(verdicts);
                out
            }
            status => self.failed(
                start,
                Verdict::Error,
                GapReason::EngineError,
                format!(
                    "Unerwartetes Ergebnis (Status {status:?}): {}",
                    first_line(&run.stderr)
                ),
            ),
        }
    }
}

impl Engine for ClamAvEngine {
    fn name(&self) -> &str {
        "clamav"
    }

    fn info(&self) -> EngineInfo {
        EngineInfo {
            content_time_utc: self.content_time_utc.clone(),
            name: "clamav".into(),
            engine_version: self.engine_version.clone(),
            content_version: self.content_version.clone(),
            health: self.health.clone(),
            license: "GPL-2.0 (separat installiert, nicht mitgeliefert)".into(),
            content_kind: self.content_kind,
            content_note: self.content_note.clone(),
            inspects_contents_of: content_formats(&persistent::default_library(&self.cfg.clamscan)),
            isolation: self.isolation(),
        }
    }

    fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
        let start = Instant::now();
        if let EngineHealth::Unavailable { reason } = &self.health {
            return self.failed(
                start,
                Verdict::Error,
                GapReason::EngineUnavailable,
                reason.clone(),
            );
        }
        let mut c = self.base_command();
        c.arg("-");
        match run_sandboxed(
            c,
            Some(input.data.to_vec()),
            &self.limits(input.timeout),
            &self.cfg.sandbox,
        ) {
            Ok(r) => {
                if let Some(p) = r.peak_memory_bytes {
                    self.peak_memory
                        .fetch_max(p, std::sync::atomic::Ordering::Relaxed);
                }
                self.interpret(&r, start, input.timeout)
            }
            Err(e) => self.failed(
                start,
                Verdict::Error,
                GapReason::EngineError,
                format!("Start fehlgeschlagen: {e}"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_gaps_and_detections() {
        assert_eq!(classify("Heuristics.Encrypted.Zip").0, Verdict::Encrypted);
        assert_eq!(
            classify("Heuristics.Limits.Exceeded.MaxFileSize").0,
            Verdict::Unsupported
        );
        assert_eq!(classify("PUA.Win.Tool.Foo").0, Verdict::Pua);
        assert_eq!(classify("Heuristics.Phishing.Email").0, Verdict::Suspicious);
        assert_eq!(classify("Win.Trojan.Agent-123").0, Verdict::Malicious);
    }

    #[test]
    fn missing_binary_is_unavailable() {
        let e = ClamAvEngine::new(ClamAvConfig {
            clamscan: PathBuf::from("/nicht/vorhanden/clamscan"),
            ..Default::default()
        });
        assert!(matches!(e.info().health, EngineHealth::Unavailable { .. }));
    }

    #[test]
    fn database_classification() {
        let dir = std::env::temp_dir().join(format!("axsafe-dbcls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let t = dir.join("t.hdb");
        std::fs::write(
            &t,
            "44d88612fea8a8f36de82e1278abb02f:68:AXSafe.Test.EICAR.HDB\n",
        )
        .unwrap();
        assert_eq!(
            classify_database(std::slice::from_ref(&t)).0,
            ContentKind::TestOnly
        );
        let c = dir.join("c.hdb");
        std::fs::write(&c, "00000000000000000000000000000000:1:Firma.Eigene.Sig\n").unwrap();
        assert_eq!(classify_database(&[t, c]).0, ContentKind::CustomSignatures);
        let o = dir.join("daily.cvd");
        std::fs::write(&o, b"ClamAV-VDB:binary").unwrap();
        assert_eq!(classify_database(&[o]).0, ContentKind::OfficialSignatures);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cvd_header_and_official_versions() {
        let dir = std::env::temp_dir().join(format!("axsafe-cvd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut head = b"ClamAV-VDB:24 Oct 2026 06-26 +0000:28163:355788:90:x:y:svc:1".to_vec();
        head.resize(512, b' ');
        head.extend_from_slice(b"KOERPER");
        std::fs::write(dir.join("daily.cld"), &head).unwrap();
        let mut main = b"ClamAV-VDB:16 Sep 2021 08-32 -0400:62:6647427:90:x:y:sigmgr:1".to_vec();
        main.resize(512, 0);
        std::fs::write(dir.join("main.cvd"), &main).unwrap();
        std::fs::write(dir.join("kaputt.cvd"), b"kein Kopf").unwrap();
        let h = cvd_header(&dir.join("daily.cld")).unwrap();
        assert_eq!((h.version, h.signatures), (28163, 355788));
        assert_eq!(h.built, "24 Oct 2026 06-26 +0000");
        assert_eq!(
            cvd_time_utc(&h.built).as_deref(),
            Some("2026-10-24T06:26:00Z")
        );
        assert!(cvd_header(&dir.join("kaputt.cvd")).is_none());
        let files = db_files(&dir).unwrap();
        let v = official_versions(&files);
        let names: Vec<_> = v
            .iter()
            .map(|(n, h)| format!("{n}-{}", h.version))
            .collect();
        assert_eq!(names, ["main-62", "daily-28163"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_are_fixed_not_path_search() {
        let (exe, _) = windows_default_paths();
        assert!(exe.is_absolute(), "{exe:?}");
        assert!(
            exe.ends_with("ClamAV/clamscan.exe")
                || exe.to_string_lossy().ends_with(r"ClamAV\clamscan.exe")
        );
    }

    #[test]
    fn rar_is_claimed_only_with_matching_unrar_library() {
        let d = tempfile::tempdir().unwrap();
        let (lib, iface) = if cfg!(windows) {
            ("libclamav.dll", "libclamunrar_iface.dll".to_string())
        } else {
            (
                "libclamav.so.12.1.0",
                "libclamunrar_iface.so.12.1.0".to_string(),
            )
        };
        let l = d.path().join(lib);
        std::fs::write(&l, b"").unwrap();
        assert!(!unrar_available(&l));
        assert!(!content_formats(&l).contains(&ContentFormat::Rar));
        if !cfg!(windows) {
            // Falsche Version zählt nicht.
            std::fs::write(d.path().join("libclamunrar_iface.so.11"), b"").unwrap();
            assert!(!unrar_available(&l));
        }
        std::fs::write(d.path().join(iface), b"").unwrap();
        assert!(unrar_available(&l));
        assert!(content_formats(&l).contains(&ContentFormat::Rar));
        assert!(!unrar_available(&d.path().join("fehlt").join(lib)));
    }

    #[test]
    fn verified_formats_exclude_unproven_ones() {
        for f in [ContentFormat::Rar, ContentFormat::Rtf, ContentFormat::Vhdx] {
            assert!(
                !VERIFIED_CONTENT_FORMATS.contains(&f),
                "{f:?} ohne Nachweis"
            );
        }
    }
}
