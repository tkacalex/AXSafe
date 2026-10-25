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

use axsafe_core::engine::{
    ContentKind, Detection, Engine, EngineHealth, EngineInfo, EngineOutcome, Gap, GapReason,
    ScanInput,
};
use axsafe_core::filetype::ContentFormat;
use axsafe_core::verdict::{aggregate, Confidence, Severity, Verdict};
use axsafe_proc::{run, Limits, RunOutcome};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Containerformate, deren **Inhalt** ClamAV nachweislich prüft.
/// Nur Formate mit bestandenem Integrationstest (`tests/clamav_real.rs`,
/// `content_formats_are_backed_by_real_clamav`). RAR (abhängig von
/// unrar-Unterstützung der Installation), ISO, RTF und VHDX fehlen bewusst.
pub const VERIFIED_CONTENT_FORMATS: [ContentFormat; 7] = [
    ContentFormat::Zip,
    ContentFormat::Ooxml,
    ContentFormat::Gzip,
    ContentFormat::OleCfb,
    ContentFormat::Cab,
    ContentFormat::SevenZip,
    ContentFormat::Pdf,
];

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
}

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
    health: EngineHealth,
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

impl ClamAvEngine {
    /// Prüft Programm und Datenbank sofort. Fehler ergeben `Unavailable`.
    pub fn new(cfg: ClamAvConfig) -> Self {
        let mut engine = ClamAvEngine {
            cfg,
            engine_version: "unbekannt".into(),
            content_version: "unbekannt".into(),
            content_kind: ContentKind::Unknown,
            content_note: "nicht geprüft".into(),
            health: EngineHealth::Unavailable {
                reason: "nicht geprüft".into(),
            },
        };
        engine.probe();
        engine
    }

    fn base_command(&self) -> Command {
        let mut c = Command::new(&self.cfg.clamscan);
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
        v.arg("--version");
        match run(v, None, &self.limits(Duration::from_secs(15))) {
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
            let official = db_files(&db).map(|f| official_versions(&f));
            let res = match official {
                // Offizielle Datenbank: Stand aus den Köpfen (ohne alle
                // Signaturdaten bei jedem Start einzulesen).
                Ok(o) if o.iter().any(|(n, _)| n == "daily") => db_files(&db).map(|files| {
                    let version = o
                        .iter()
                        .map(|(n, h)| format!("{n}-{}", h.version))
                        .collect::<Vec<_>>()
                        .join("/");
                    let details = o
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
                    (
                        files,
                        version,
                        kind,
                        format!(
                            "offizielle ClamAV-Signaturen: {details}; Pfad {}. Aktualisierung über \
                             FreshClam (geplanter Auftrag), Stand siehe state\\last-update.json",
                            db.display()
                        ),
                    )
                }),
                _ => db_files(&db).and_then(|f| {
                    let d = database_digest(&f)?;
                    let (kind, note) = classify_database(&f);
                    Ok((f, d, kind, note))
                }),
            };
            match res {
                Ok((_files, version, kind, note)) => {
                    self.content_version = version;
                    self.content_kind = kind;
                    self.content_note = note;
                }
                Err(e) => {
                    return self.unavailable(format!(
                        "Signaturdatenbank {} nicht lesbar: {e}",
                        db.display()
                    ));
                }
            }
        }
        // Echter Funktionstest: leere Eingabe muss sauber geprüft werden.
        // Schlägt fehl, wenn z. B. keine Signaturdatenbank vorhanden ist.
        let mut c = self.base_command();
        c.arg("-");
        match run(c, Some(Vec::new()), &self.limits(Duration::from_secs(120))) {
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
            name: "clamav".into(),
            engine_version: self.engine_version.clone(),
            content_version: self.content_version.clone(),
            health: self.health.clone(),
            license: "GPL-2.0 (separat installiert, nicht mitgeliefert)".into(),
            content_kind: self.content_kind,
            content_note: self.content_note.clone(),
            inspects_contents_of: VERIFIED_CONTENT_FORMATS.to_vec(),
            isolation: axsafe_core::engine::Isolation {
                kind: axsafe_core::engine::IsolationKind::ChildProcess,
                // Grenzen (Zeit, Speicher, Prozessbaum) ja, Rechtebeschränkung nein.
                enforced: false,
                detail: if cfg!(windows) {
                    "eigener Prozess im Job Object (Zeit, Speicher, Prozessbaum begrenzt), \
                     aber mit den Rechten des Benutzers"
                } else {
                    "eigener Prozess in eigener Prozessgruppe (Zeit, Speicher begrenzt), \
                     aber mit den Rechten des Benutzers"
                }
                .into(),
            },
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
        match run(c, Some(input.data.to_vec()), &self.limits(input.timeout)) {
            Ok(r) => self.interpret(&r, start, input.timeout),
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
    fn verified_formats_exclude_unproven_ones() {
        for f in [
            ContentFormat::Rar,
            ContentFormat::Iso,
            ContentFormat::Rtf,
            ContentFormat::Vhdx,
        ] {
            assert!(
                !VERIFIED_CONTENT_FORMATS.contains(&f),
                "{f:?} ohne Nachweis"
            );
        }
    }
}
