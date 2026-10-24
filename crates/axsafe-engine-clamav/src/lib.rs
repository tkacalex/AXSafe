//! ClamAV Engineadapter (AXS-021, T-021, erster Schritt).
//!
//! * ClamAV läuft als **getrennter Prozess** (`clamscan`). Es wird **kein**
//!   `clamd` und keine TCP-Schnittstelle geöffnet (ClamAV-Doku: TCP ohne
//!   Authentifizierung).
//! * Der Inhalt wird über **stdin** übergeben. ClamAV prüft damit exakt den
//!   Schnappschuss, den AXSafe gehasht hat, nicht einen später erneut
//!   geöffneten Pfad.
//! * Absturz, fehlende Datenbank oder Zeitüberschreitung bleiben im
//!   Kindprozess und werden als `Error` beziehungsweise `Timeout` gemeldet.
//! * Verschlüsselte Inhalte und überschrittene Limits werden über
//!   `--alert-encrypted` und `--alert-exceeds-max` sichtbar gemacht und als
//!   Prüflücke (`Encrypted`, `Unsupported`) gemeldet, nie als sauber.
//!
//! Lizenz: ClamAV steht unter GPL-2.0. AXSafe ruft das separat installierte
//! Programm auf und verteilt es in dieser Vorversion **nicht** mit. Vor einer
//! Weitergabe ist die Lizenzprüfung aus ADR-0003 abzuschließen.
//!
//! Noch offen: eingeschränktes Token/Job Object für den Kindprozess (P02),
//! FreshClam-Updatepfad (P04), Test auf Windows 10 LTSC.

#![forbid(unsafe_code)]

use axsafe_core::engine::{Detection, Engine, EngineHealth, EngineInfo, EngineOutcome, ScanInput};
use axsafe_core::verdict::{aggregate, Confidence, Severity, Verdict};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

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
}

impl Default for ClamAvConfig {
    fn default() -> Self {
        ClamAvConfig {
            clamscan: PathBuf::from(if cfg!(windows) {
                "clamscan.exe"
            } else {
                "clamscan"
            }),
            database: None,
            max_filesize_mb: 100,
            max_scansize_mb: 400,
            max_recursion: 17,
        }
    }
}

/// ClamAV-Engine über `clamscan`.
pub struct ClamAvEngine {
    cfg: ClamAvConfig,
    engine_version: String,
    content_version: String,
    health: EngineHealth,
}

struct RunOutput {
    status: Option<i32>,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

fn run(cmd: &mut Command, stdin: Option<&[u8]>, timeout: Duration) -> std::io::Result<RunOutput> {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    // stdin in eigenem Thread schreiben, damit volle Pipes nicht blockieren.
    let writer = stdin.map(|data| {
        let data = data.to_vec();
        let mut pipe = child.stdin.take().expect("stdin piped");
        std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
        })
    });
    let mut out = child.stdout.take().expect("stdout piped");
    let mut err = child.stderr.take().expect("stderr piped");
    let out_t = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = out.read_to_end(&mut s);
        s
    });
    let err_t = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = err.read_to_end(&mut s);
        s
    });
    let (status, timed_out) = match child.wait_timeout(timeout)? {
        Some(st) => (st.code(), false),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            // Nicht auf die Lesethreads warten: Enkelprozesse können die
            // Pipes offen halten. Die Threads enden, sobald die Pipe schließt.
            // (Vollständiges Beenden des Prozessbaums: Job Object, Phase P02.)
            return Ok(RunOutput {
                status: None,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: true,
            });
        }
    };
    if let Some(w) = writer {
        let _ = w.join();
    }
    let stdout = String::from_utf8_lossy(&out_t.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err_t.join().unwrap_or_default()).into_owned();
    Ok(RunOutput {
        status,
        stdout,
        stderr,
        timed_out,
    })
}

fn first_line(s: &str) -> String {
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

fn database_digest(path: &PathBuf) -> std::io::Result<String> {
    let mut files = Vec::new();
    if path.is_dir() {
        for e in std::fs::read_dir(path)? {
            let p = e?.path();
            if p.is_file() {
                files.push(p);
            }
        }
    } else {
        files.push(path.clone());
    }
    files.sort();
    let mut h = Sha256::new();
    for f in files {
        h.update(
            f.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        h.update([0]);
        h.update(std::fs::read(&f)?);
    }
    Ok(format!("db-sha256:{}", &hex::encode(h.finalize())[..16]))
}

impl ClamAvEngine {
    /// Prüft Programm und Datenbank sofort. Fehler ergeben `Unavailable`.
    pub fn new(cfg: ClamAvConfig) -> Self {
        let mut engine = ClamAvEngine {
            cfg,
            engine_version: "unbekannt".into(),
            content_version: "unbekannt".into(),
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

    fn probe(&mut self) {
        let mut v = Command::new(&self.cfg.clamscan);
        v.arg("--version");
        match run(&mut v, None, Duration::from_secs(15)) {
            Ok(o) if o.status == Some(0) => {
                // Format: "ClamAV 1.5.4" oder "ClamAV 1.5.4/27789/Fri Oct 23 ..."
                let line = first_line(&o.stdout);
                let mut parts = line.splitn(3, '/');
                self.engine_version = parts.next().unwrap_or("").trim().to_string();
                if let Some(db) = parts.next() {
                    self.content_version = format!("daily-{db}");
                }
            }
            Ok(o) => {
                self.health = EngineHealth::Unavailable {
                    reason: format!(
                        "clamscan --version fehlgeschlagen: {}",
                        first_line(&o.stderr)
                    ),
                };
                return;
            }
            Err(e) => {
                self.health = EngineHealth::Unavailable {
                    reason: format!(
                        "clamscan nicht startbar ({}): {e}",
                        self.cfg.clamscan.display()
                    ),
                };
                return;
            }
        }
        if let Some(db) = &self.cfg.database {
            match database_digest(db) {
                Ok(d) => self.content_version = d,
                Err(e) => {
                    self.health = EngineHealth::Unavailable {
                        reason: format!("Signaturdatenbank {} nicht lesbar: {e}", db.display()),
                    };
                    return;
                }
            }
        }
        // Echter Funktionstest: leere Eingabe muss mit Status 0 geprüft werden.
        // Schlägt fehl, wenn z. B. keine Signaturdatenbank vorhanden ist.
        let mut c = self.base_command();
        c.arg("-");
        match run(&mut c, Some(b""), Duration::from_secs(120)) {
            Ok(o) if o.status == Some(0) => self.health = EngineHealth::Ready,
            Ok(o) if o.timed_out => {
                self.health = EngineHealth::Unavailable {
                    reason: "Funktionstest: Zeitüberschreitung beim Laden der Datenbank".into(),
                }
            }
            Ok(o) => {
                let msg = first_line(&o.stderr);
                let msg = if msg.is_empty() {
                    first_line(&o.stdout)
                } else {
                    msg
                };
                self.health = EngineHealth::Unavailable {
                    reason: format!(
                        "Funktionstest fehlgeschlagen (Status {:?}): {msg}",
                        o.status
                    ),
                }
            }
            Err(e) => {
                self.health = EngineHealth::Unavailable {
                    reason: format!("Funktionstest nicht startbar: {e}"),
                }
            }
        }
    }

    fn outcome(&self, verdict: Verdict, note: Option<String>, start: Instant) -> EngineOutcome {
        EngineOutcome {
            engine: "clamav".into(),
            engine_version: self.engine_version.clone(),
            content_version: self.content_version.clone(),
            verdict,
            detections: Vec::new(),
            note,
            duration_ms: start.elapsed().as_millis() as u64,
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
        }
    }

    fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
        let start = Instant::now();
        if let EngineHealth::Unavailable { reason } = &self.health {
            return self.outcome(Verdict::Error, Some(reason.clone()), start);
        }
        let mut c = self.base_command();
        c.arg("-");
        let o = match run(&mut c, Some(input.data), input.timeout) {
            Ok(o) => o,
            Err(e) => {
                return self.outcome(
                    Verdict::Error,
                    Some(format!("Start fehlgeschlagen: {e}")),
                    start,
                )
            }
        };
        if o.timed_out {
            return self.outcome(
                Verdict::Timeout,
                Some("Zeitbudget überschritten, Prozess beendet".into()),
                start,
            );
        }
        let mut dets = Vec::new();
        let mut saw_ok = false;
        for line in o.stdout.lines() {
            let Some(rest) = line.strip_prefix("stdin: ") else {
                continue;
            };
            if rest.trim() == "OK" {
                saw_ok = true;
            } else if let Some(name) = rest.strip_suffix(" FOUND") {
                let name = name.trim().to_string();
                let (verdict, severity, confidence) = classify(&name);
                dets.push(Detection {
                    evidence: vec![format!("ClamAV-Signatur {name}")],
                    test_signature: is_test_signature(&name),
                    rule_id: Some(name.clone()),
                    name,
                    verdict,
                    severity,
                    confidence,
                });
            }
        }
        match o.status {
            Some(0) if saw_ok && dets.is_empty() => self.outcome(Verdict::NoDetection, None, start),
            Some(1) if !dets.is_empty() => {
                let verdict = aggregate(dets.iter().map(|d| d.verdict));
                let mut out = self.outcome(verdict, None, start);
                out.detections = dets;
                out
            }
            status => {
                let msg = first_line(&o.stderr);
                self.outcome(
                    Verdict::Error,
                    Some(format!("Unerwartetes Ergebnis (Status {status:?}): {msg}")),
                    start,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axsafe_core::filetype::FileKind;
    use md5::Md5;

    fn eicar() -> Vec<u8> {
        let a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
        let b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        format!("{a}{b}").into_bytes()
    }

    fn clamscan_available() -> bool {
        Command::new("clamscan")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Erzeugt eine ClamAV-Hashsignatur (.hdb) für EICAR zur Laufzeit.
    fn test_db(dir: &std::path::Path) -> PathBuf {
        let e = eicar();
        let md5 = hex::encode(Md5::digest(&e));
        let p = dir.join("axsafe-test.hdb");
        std::fs::write(&p, format!("{md5}:{}:AXSafe.Test.EICAR.HDB\n", e.len())).unwrap();
        p
    }

    fn input(data: &[u8], timeout: Duration) -> ScanInput<'_> {
        ScanInput {
            data,
            kind: &FileKind::Unknown,
            sha256: "",
            timeout,
        }
    }

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
        assert_eq!(
            e.scan(&input(b"x", Duration::from_secs(5))).verdict,
            Verdict::Error
        );
    }

    #[test]
    fn real_clamav_positive_and_benign() {
        if !clamscan_available() {
            eprintln!("clamscan nicht installiert: Integrationstest übersprungen (in CI Pflicht)");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let e = ClamAvEngine::new(ClamAvConfig {
            database: Some(test_db(dir.path())),
            ..Default::default()
        });
        assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
        assert!(e.info().engine_version.starts_with("ClamAV "));
        assert!(e.info().content_version.starts_with("db-sha256:"));

        let pos = e.scan(&input(&eicar(), Duration::from_secs(60)));
        assert_eq!(pos.verdict, Verdict::Malicious, "{pos:?}");
        assert!(pos.detections[0].name.starts_with("AXSafe.Test.EICAR"));
        assert!(pos.detections[0].test_signature);

        let neg = e.scan(&input(
            b"Hallo Welt, ganz harmlos.",
            Duration::from_secs(60),
        ));
        assert_eq!(neg.verdict, Verdict::NoDetection, "{neg:?}");
    }

    #[test]
    fn real_clamav_without_database_is_unavailable() {
        if !clamscan_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("leer");
        std::fs::create_dir(&empty).unwrap();
        let e = ClamAvEngine::new(ClamAvConfig {
            database: Some(empty),
            ..Default::default()
        });
        assert!(
            matches!(e.info().health, EngineHealth::Unavailable { .. }),
            "{:?}",
            e.info()
        );
    }

    #[cfg(unix)]
    fn fake_clamscan(dir: &std::path::Path, body: &str) -> PathBuf {
        // Testdoppel nur für Fehlerpfade (Absturz, Hänger). Nie im Produkt.
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("fake-clamscan");
        std::fs::write(&p, format!("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ClamAV 0.0-test'; exit 0; fi\ncat >/dev/null\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Linux meldet kurz nach dem Schreiben gelegentlich ETXTBSY („Text file
        // busy“), wenn ein parallel laufender Test gerade einen Prozess startet
        // und dabei den Schreib-Handle erbt. Warten, bis das Skript startbar ist,
        // damit der Test das Zeitlimit prüft und nicht diesen Nebeneffekt.
        for _ in 0..100 {
            match Command::new(&p).arg("--version").output() {
                Ok(o) if o.status.success() => return p,
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        panic!("Testskript nicht startbar");
    }

    #[cfg(unix)]
    #[test]
    fn engine_crash_is_error_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        // Funktionstest bestehen, danach abstürzen: Zähler über Datei.
        let flag = dir.path().join("probed");
        let body = format!(
            "if [ -f {f} ]; then kill -SEGV $$; fi\ntouch {f}\necho 'stdin: OK'\nexit 0",
            f = flag.display()
        );
        let e = ClamAvEngine::new(ClamAvConfig {
            clamscan: fake_clamscan(dir.path(), &body),
            ..Default::default()
        });
        assert_eq!(e.info().health, EngineHealth::Ready);
        let o = e.scan(&input(b"x", Duration::from_secs(10)));
        assert_eq!(o.verdict, Verdict::Error, "{o:?}");
    }

    #[cfg(unix)]
    #[test]
    fn hanging_engine_is_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let flag = dir.path().join("probed");
        let body = format!(
            "if [ -f {f} ]; then sleep 30; fi\ntouch {f}\necho 'stdin: OK'\nexit 0",
            f = flag.display()
        );
        let e = ClamAvEngine::new(ClamAvConfig {
            clamscan: fake_clamscan(dir.path(), &body),
            ..Default::default()
        });
        let t = Instant::now();
        let o = e.scan(&input(b"x", Duration::from_millis(500)));
        assert_eq!(o.verdict, Verdict::Timeout);
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn status_zero_without_ok_line_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let flag = dir.path().join("probed");
        let body = format!(
            "if [ -f {f} ]; then exit 0; fi\ntouch {f}\necho 'stdin: OK'\nexit 0",
            f = flag.display()
        );
        let e = ClamAvEngine::new(ClamAvConfig {
            clamscan: fake_clamscan(dir.path(), &body),
            ..Default::default()
        });
        assert_eq!(
            e.scan(&input(b"x", Duration::from_secs(5))).verdict,
            Verdict::Error
        );
    }
}
