//! # axsafe-proc
//!
//! Startet Kindprozesse (Engines, später den Scanworker) unter harten Grenzen:
//!
//! * **Ein gemeinsames Ablaufdatum** für Prozesslauf, Eingabeschreiben und
//!   Ausgabelesen. Es gibt keinen unbegrenzten Thread-Join (Befund 4).
//! * **Prozessbaum:** Nachkommen werden kontrolliert und beendet.
//!   - Windows: Der Prozess startet *angehalten*, wird einem **Job Object**
//!     zugewiesen (Kill-on-close, Speicher- und Prozessanzahlgrenze, kein
//!     Breakaway) und erst dann fortgesetzt. Nachkommen können den Job nicht
//!     verlassen.
//!   - Unix (Entwicklung/CI): eigene Prozessgruppe, Beenden per `killpg`,
//!     Speichergrenze per `RLIMIT_AS`. Grenze: Ein Nachkomme, der eine neue
//!     Prozessgruppe/Sitzung anlegt, verlässt die Gruppe; dann greift das
//!     Ablaufdatum (Ergebnis `timed_out`).
//! * **Ausgabe** je Kanal begrenzt; Überschreitung beendet den Prozessbaum.
//!
//! Der Aufrufer bekommt ein [`RunOutcome`] und entscheidet daraus über
//! Fehler, Zeitüberschreitung oder Erfolg. Eine Zeitüberschreitung darf nie
//! als erfolgreiche Prüfung gewertet werden.

#![cfg_attr(not(any(unix, windows)), forbid(unsafe_code))]
#![cfg_attr(any(unix, windows), deny(unsafe_code))]

use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

mod sys;

/// Grenzen für einen Kindprozess.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Gemeinsames Ablaufdatum ab Start (Prozess, Eingabe, Ausgabe).
    pub timeout: Duration,
    /// Höchstmenge je Ausgabekanal (stdout, stderr) in Bytes.
    pub max_output_bytes: usize,
    /// Speichergrenze des Prozesses (Windows: Commit je Prozess; Unix: Adressraum).
    pub max_memory_bytes: Option<u64>,
    /// Höchstzahl gleichzeitiger Prozesse im Baum (nur Windows durchgesetzt).
    pub max_processes: Option<u32>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            timeout: Duration::from_secs(30),
            max_output_bytes: 1024 * 1024,
            max_memory_bytes: Some(4 * 1024 * 1024 * 1024),
            max_processes: Some(8),
        }
    }
}

/// Ergebnis eines begrenzten Prozesslaufs.
#[derive(Debug)]
pub struct RunOutcome {
    /// Exitstatus des Hauptprozesses (falls er ermittelt werden konnte).
    pub status: Option<ExitStatus>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Ablaufdatum überschritten (Prozess, Eingabe oder Ausgabe).
    pub timed_out: bool,
    /// Ausgabegrenze überschritten; Ausgabe unvollständig.
    pub output_truncated: bool,
    /// Eingabe konnte nicht vollständig übergeben werden.
    pub stdin_incomplete: bool,
    /// Nach Ende des Hauptprozesses liefen noch Nachkommen und wurden beendet.
    pub descendants_terminated: bool,
    /// Höchster beobachteter Speicherbedarf (nur Windows, aus dem Job Object).
    pub peak_memory_bytes: Option<u64>,
    pub elapsed: Duration,
}

impl RunOutcome {
    /// `true` nur, wenn der Hauptprozess innerhalb aller Grenzen mit Code 0
    /// endete, die Eingabe vollständig übergeben und die Ausgabe vollständig
    /// gelesen wurde und keine Nachkommen zurückblieben.
    pub fn clean_success(&self) -> bool {
        !self.timed_out
            && !self.output_truncated
            && !self.stdin_incomplete
            && !self.descendants_terminated
            && self.status.map(|s| s.success()).unwrap_or(false)
    }

    /// Exitcode des Hauptprozesses, falls normal beendet.
    pub fn code(&self) -> Option<i32> {
        self.status.and_then(|s| s.code())
    }
}

enum Event {
    Stdout(Vec<u8>, bool),
    Stderr(Vec<u8>, bool),
    OutputLimit,
    StdinDone(bool),
}

fn reader<R: Read + Send + 'static>(
    mut r: R,
    max: usize,
    tx: mpsc::Sender<Event>,
    wrap: fn(Vec<u8>, bool) -> Event,
) {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut truncated = false;
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > max {
                        let take = max.saturating_sub(buf.len());
                        buf.extend_from_slice(&chunk[..take]);
                        truncated = true;
                        let _ = tx.send(Event::OutputLimit);
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = tx.send(wrap(buf, truncated));
    });
}

/// Startet `cmd` unter den angegebenen Grenzen und liefert spätestens zum
/// Ablaufdatum (plus kurzer Aufräumzeit) ein Ergebnis.
pub fn run(mut cmd: Command, stdin: Option<Vec<u8>>, limits: &Limits) -> io::Result<RunOutcome> {
    let start = Instant::now();
    let deadline = start + limits.timeout;
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let mut contained = sys::Contained::spawn(&mut cmd, limits)?;
    let (tx, rx) = mpsc::channel();

    let mut stdin_done = stdin.is_none();
    let mut stdin_ok = true;
    if let Some(data) = stdin {
        let mut pipe = contained.child.stdin.take().expect("stdin piped");
        let tx = tx.clone();
        std::thread::spawn(move || {
            let ok = pipe.write_all(&data).is_ok();
            drop(pipe);
            let _ = tx.send(Event::StdinDone(ok));
        });
    }
    reader(
        contained.child.stdout.take().expect("stdout piped"),
        limits.max_output_bytes,
        tx.clone(),
        Event::Stdout,
    );
    reader(
        contained.child.stderr.take().expect("stderr piped"),
        limits.max_output_bytes,
        tx.clone(),
        Event::Stderr,
    );
    drop(tx);

    let mut stdout = None;
    let mut stderr = None;
    let mut timed_out = false;
    let mut output_truncated = false;
    let mut exited = false;
    let mut descendants_terminated = false;

    loop {
        // Ereignisse einsammeln, maximal bis zum Ablaufdatum warten.
        let now = Instant::now();
        if now >= deadline {
            timed_out = true;
            break;
        }
        let wait = (deadline - now).min(Duration::from_millis(5));
        match rx.recv_timeout(wait) {
            Ok(Event::Stdout(b, t)) => {
                output_truncated |= t;
                stdout = Some(b);
            }
            Ok(Event::Stderr(b, t)) => {
                output_truncated |= t;
                stderr = Some(b);
            }
            Ok(Event::OutputLimit) => {
                output_truncated = true;
                break;
            }
            Ok(Event::StdinDone(ok)) => {
                stdin_done = true;
                stdin_ok = ok;
            }
            Err(mpsc::RecvTimeoutError::Timeout) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
        }
        if !exited && contained.has_exited()? {
            exited = true;
            // Hauptprozess beendet: verbliebene Nachkommen sofort beenden,
            // damit sie keine Pipes offen halten (Befund 4).
            descendants_terminated = contained.terminate_descendants();
        }
        if exited && stdout.is_some() && stderr.is_some() && stdin_done {
            break;
        }
    }

    // In jedem Fall den gesamten Baum beenden (idempotent), dann einsammeln.
    contained.terminate_tree();
    let status = contained.reap();
    let peak_memory_bytes = contained.peak_memory();

    Ok(RunOutcome {
        status,
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
        timed_out,
        output_truncated,
        stdin_incomplete: !stdin_done || !stdin_ok,
        descendants_terminated,
        peak_memory_bytes,
        elapsed: start.elapsed(),
    })
}
