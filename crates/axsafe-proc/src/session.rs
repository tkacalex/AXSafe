//! Langlebiger Kindprozess mit Anfrage/Antwort über stdin/stdout (Scanworker).
//!
//! Jede Lese- und Schreiboperation hat ein Ablaufdatum. Läuft es ab, beendet
//! der Aufrufer den Prozessbaum ([`Session::kill`]) – ein blockierender
//! Kindprozess kann den Aufrufer nie unbegrenzt aufhalten. stderr wird
//! begrenzt mitgeschnitten (Diagnose).

use crate::{sys, Limits, Sandbox};
use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

/// Fehler einer Sitzungsoperation.
#[derive(Debug)]
pub enum SessionError {
    /// Ablaufdatum überschritten; der Prozess ist in unbekanntem Zustand
    /// und muss beendet werden.
    Timeout,
    /// Der Prozess hat seine Ausgabe geschlossen oder ist beendet.
    Exited(Option<ExitStatus>),
    /// Ein-/Ausgabefehler.
    Io(io::Error),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Timeout => write!(f, "Zeitüberschreitung"),
            SessionError::Exited(Some(s)) => write!(f, "Prozess beendet ({s})"),
            SessionError::Exited(None) => write!(f, "Prozess beendet"),
            SessionError::Io(e) => write!(f, "Ein-/Ausgabefehler: {e}"),
        }
    }
}

const CHUNK: usize = 64 * 1024;
const MAX_STDERR: usize = 64 * 1024;

/// Ein laufender, begrenzter (und ggf. abgeschotteter) Kindprozess.
pub struct Session {
    contained: sys::Contained,
    to_writer: Option<mpsc::SyncSender<Vec<u8>>>,
    writer_ack: mpsc::Receiver<bool>,
    from_reader: mpsc::Receiver<Option<Vec<u8>>>,
    buf: Vec<u8>,
    eof: bool,
    stderr: Arc<Mutex<Vec<u8>>>,
    killed: bool,
}

impl Session {
    /// Startet `cmd` mit Grenzen aus `limits` (`timeout` wird hier nicht
    /// verwendet; jede Operation hat ihr eigenes Ablaufdatum) und der
    /// angegebenen Rechtebeschränkung.
    pub fn spawn(mut cmd: Command, limits: &Limits, sandbox: &Sandbox) -> io::Result<Session> {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut contained = sys::Contained::spawn_sandboxed(&mut cmd, limits, sandbox)?;
        let (stdin, stdout, stderr) = contained.take_stdio();
        let (mut stdin, mut stdout, mut stderr) = match (stdin, stdout, stderr) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => {
                contained.terminate_tree();
                contained.reap();
                return Err(io::Error::other("Pipes des Kindprozesses fehlen"));
            }
        };

        let (to_writer, writer_rx) = mpsc::sync_channel::<Vec<u8>>(1);
        let (ack_tx, writer_ack) = mpsc::channel();
        std::thread::spawn(move || {
            for data in writer_rx {
                let ok = stdin.write_all(&data).and_then(|_| stdin.flush()).is_ok();
                if ack_tx.send(ok).is_err() || !ok {
                    break;
                }
            }
        });

        // Gegendruck: höchstens 16 Blöcke à 64 KiB stehen aus.
        let (out_tx, from_reader) = mpsc::sync_channel::<Option<Vec<u8>>>(16);
        std::thread::spawn(move || {
            let mut chunk = vec![0u8; CHUNK];
            loop {
                match stdout.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if out_tx.send(Some(chunk[..n].to_vec())).is_err() {
                            return;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            let _ = out_tx.send(None);
        });

        let err_buf = Arc::new(Mutex::new(Vec::new()));
        let eb = Arc::clone(&err_buf);
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if let Ok(mut b) = eb.lock() {
                    let room = MAX_STDERR.saturating_sub(b.len());
                    b.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
        });

        Ok(Session {
            contained,
            to_writer: Some(to_writer),
            writer_ack,
            from_reader,
            buf: Vec::new(),
            eof: false,
            stderr: err_buf,
            killed: false,
        })
    }

    /// Prozess-ID (Diagnose).
    pub fn pid(&self) -> u32 {
        self.contained.pid()
    }

    fn remaining(deadline: Instant) -> Result<std::time::Duration, SessionError> {
        let now = Instant::now();
        if now >= deadline {
            Err(SessionError::Timeout)
        } else {
            Ok(deadline - now)
        }
    }

    fn exited(&mut self) -> SessionError {
        // Kurz auf den Exitstatus warten (Ausgabe ist bereits geschlossen).
        let until = Instant::now() + std::time::Duration::from_millis(200);
        while Instant::now() < until {
            if let Ok(true) = self.contained.has_exited() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        self.kill();
        SessionError::Exited(self.contained.reap())
    }

    /// Schreibt alle Bytes bis zum Ablaufdatum.
    pub fn write_all(&mut self, data: Vec<u8>, deadline: Instant) -> Result<(), SessionError> {
        let tx = self.to_writer.as_ref().ok_or(SessionError::Exited(None))?;
        tx.send(data).map_err(|_| SessionError::Exited(None))?;
        match self.writer_ack.recv_timeout(Self::remaining(deadline)?) {
            Ok(true) => Ok(()),
            Ok(false) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.to_writer = None;
                Err(self.exited())
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(SessionError::Timeout),
        }
    }

    /// Liest genau `n` Bytes bis zum Ablaufdatum.
    pub fn read_exact(&mut self, n: usize, deadline: Instant) -> Result<Vec<u8>, SessionError> {
        while self.buf.len() < n {
            if self.eof {
                return Err(self.exited());
            }
            match self.from_reader.recv_timeout(Self::remaining(deadline)?) {
                Ok(Some(chunk)) => self.buf.extend_from_slice(&chunk),
                Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => self.eof = true,
                Err(mpsc::RecvTimeoutError::Timeout) => return Err(SessionError::Timeout),
            }
        }
        let rest = self.buf.split_off(n);
        Ok(std::mem::replace(&mut self.buf, rest))
    }

    /// Bisher mitgeschnittene Fehlerausgabe (höchstens 64 KiB).
    pub fn stderr_text(&self) -> String {
        self.stderr
            .lock()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    }

    /// Höchster Speicherbedarf (nur Windows, aus dem Job Object).
    pub fn peak_memory(&self) -> Option<u64> {
        self.contained.peak_memory()
    }

    /// Ob der Prozess noch läuft.
    pub fn is_running(&mut self) -> bool {
        !self.killed && !matches!(self.contained.has_exited(), Ok(true))
    }

    /// Beendet den gesamten Prozessbaum (idempotent).
    pub fn kill(&mut self) {
        if !self.killed {
            self.killed = true;
            self.to_writer = None;
            self.contained.terminate_tree();
        }
    }

    /// Beendet geordnet: Eingabe schließen, kurz auf das Ende warten, dann
    /// den Baum beenden. Liefert den Exitstatus, falls bekannt.
    pub fn shutdown(mut self, grace: std::time::Duration) -> Option<ExitStatus> {
        self.to_writer = None;
        let until = Instant::now() + grace;
        while Instant::now() < until {
            if let Ok(true) = self.contained.has_exited() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        self.kill();
        self.contained.reap()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.kill();
        let _ = self.contained.reap();
    }
}
