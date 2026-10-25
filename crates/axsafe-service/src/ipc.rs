//! Protokoll `axsafe.ipc/1` zwischen Oberfläche/CLI und dem AXSafe-Dienst.
//!
//! Rahmen: `u32` Länge (Little Endian) + JSON. Anfragen höchstens 64 KiB,
//! Antworten höchstens 16 MiB. Jede Anfrage trägt eine pro Verbindung
//! streng steigende Folgenummer und eine zufällige Nonce; verändernde
//! Anfragen (Scan starten, abbrechen) mit bereits gesehener Nonce werden als
//! Wiederholung abgewiesen.
//!
//! **Vertrauen:** Wer der Auftraggeber ist, bestimmt allein der Dienst aus
//! dem Windows-Token der Verbindung. Das Protokoll hat bewusst KEIN Feld für
//! Benutzer, SID, Prozess- oder Sitzungskennung.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

pub const IPC_PROTOCOL: &str = "axsafe.ipc/1";
pub const PIPE_NAME: &str = r"\\.\pipe\AXSafe.v1";
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Höchstzahl Pfade je Scanauftrag.
pub const MAX_PATHS: usize = 64;
/// Höchstlänge eines Pfads in UTF-16-Einheiten (Windows-Langpfad).
pub const MAX_PATH_CHARS: usize = 32_767;

/// Anfrage des Clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: String,
    /// Pro Verbindung streng steigend, beginnend bei 1.
    pub seq: u64,
    /// 32 Hexzeichen, zufällig je Anfrage.
    pub nonce: String,
    pub body: Body,
}

/// Erlaubte Befehle – ausschließlich diese.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Body {
    /// Dienstzustand, Engines, eigene Aufträge.
    Status,
    /// Scan mit den Rechten des Auftraggebers starten.
    ScanStart {
        paths: Vec<String>,
        #[serde(default)]
        use_clamav: bool,
    },
    /// Eigenen Auftrag abbrechen.
    ScanCancel { job_id: String },
    /// Zustand eines eigenen Auftrags.
    Job { job_id: String },
    /// Bericht eines eigenen, abgeschlossenen Auftrags.
    Report { job_id: String },
}

impl Body {
    /// Verändert die Anfrage Zustand im Dienst (Wiederholschutz nötig)?
    pub fn is_mutating(&self) -> bool {
        matches!(self, Body::ScanStart { .. } | Body::ScanCancel { .. })
    }
}

/// Antwort des Dienstes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub protocol: String,
    /// Folgenummer der beantworteten Anfrage (0 = Anfrage nicht lesbar).
    pub seq: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
    #[serde(default)]
    pub result: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcError {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Schema, Typ, Länge oder Werte ungültig.
    Invalid,
    /// Folgenummer nicht steigend oder Nonce wiederholt.
    Replay,
    /// Zu viele Anfragen oder Aufträge.
    Overloaded,
    /// Auftrag gehört einem anderen Auftraggeber oder existiert nicht.
    NotFound,
    /// Identität nicht feststellbar oder unzulässig.
    Forbidden,
    /// Interner Fehler des Dienstes.
    Internal,
    /// Dienst fährt herunter.
    ShuttingDown,
}

impl Response {
    pub fn ok(seq: u64, result: serde_json::Value) -> Self {
        Response {
            protocol: IPC_PROTOCOL.into(),
            seq,
            ok: true,
            error: None,
            result,
        }
    }
    pub fn err(seq: u64, code: ErrorCode, message: impl Into<String>) -> Self {
        Response {
            protocol: IPC_PROTOCOL.into(),
            seq,
            ok: false,
            error: Some(IpcError {
                code,
                message: message.into(),
            }),
            result: serde_json::Value::Null,
        }
    }
}

/// Prüft Werte einer Anfrage, die serde nicht prüfen kann.
pub fn validate(req: &Request) -> Result<(), String> {
    if req.protocol != IPC_PROTOCOL {
        return Err(format!(
            "Protokoll {:?} nicht unterstützt (erwartet {IPC_PROTOCOL})",
            req.protocol
        ));
    }
    if req.seq == 0 {
        return Err("Folgenummer 0 ist unzulässig".into());
    }
    if req.nonce.len() != 32 || !req.nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Nonce muss aus 32 Hexadezimalzeichen bestehen".into());
    }
    match &req.body {
        Body::ScanStart { paths, .. } => {
            if paths.is_empty() || paths.len() > MAX_PATHS {
                return Err(format!("1 bis {MAX_PATHS} Pfade erlaubt"));
            }
            for p in paths {
                validate_path(p)?;
            }
        }
        Body::ScanCancel { job_id } | Body::Job { job_id } | Body::Report { job_id } => {
            uuid::Uuid::parse_str(job_id).map_err(|_| "Auftragskennung ist keine UUID")?;
        }
        Body::Status => {}
    }
    Ok(())
}

/// Nur lokale, absolute Pfade mit Laufwerksbuchstaben (Windows) bzw.
/// absolute Pfade (Unix, Entwicklung). Keine UNC-, Geräte- oder
/// `\\?\`-Pfade, keine NUL-Zeichen.
pub fn validate_path(p: &str) -> Result<(), String> {
    if p.is_empty() || p.encode_utf16().count() > MAX_PATH_CHARS {
        return Err("Pfad leer oder zu lang".into());
    }
    if p.contains('\0') {
        return Err("Pfad enthält NUL".into());
    }
    let b = p.as_bytes();
    let drive = b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/');
    let unix_abs = cfg!(unix) && b[0] == b'/';
    if p.starts_with(r"\\") || p.starts_with("//") {
        return Err("UNC-, Geräte- und \\\\?\\-Pfade sind nicht erlaubt".into());
    }
    if !(drive || unix_abs) {
        return Err(format!("Pfad muss absolut und lokal sein: {p}"));
    }
    Ok(())
}

/// Liest einen Rahmen. `first_byte_deadline` begrenzt die Wartezeit auf den
/// Beginn, `message_time` die Übertragung einer begonnenen Nachricht
/// (Schutz gegen sehr langsames Senden).
pub fn read_frame(
    conn: &mut dyn Conn,
    max: usize,
    first_byte_deadline: Option<Instant>,
    message_time: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0usize;
    let mut msg_deadline: Option<Instant> = None;
    while got < 4 {
        let deadline = msg_deadline.or(first_byte_deadline);
        conn.set_read_deadline(deadline)?;
        let n = conn.read(&mut len[got..])?;
        if n == 0 {
            return if got == 0 {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        if got == 0 {
            msg_deadline = Some(Instant::now() + message_time);
        }
        got += n;
    }
    let len = u32::from_le_bytes(len) as usize;
    if len == 0 || len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Nachrichtenlänge {len} unzulässig (höchstens {max})"),
        ));
    }
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        conn.set_read_deadline(msg_deadline)?;
        let n = conn.read(&mut buf[got..])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        got += n;
    }
    Ok(Some(buf))
}

pub fn write_frame(conn: &mut dyn Conn, data: &[u8], deadline: Instant) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Nachricht zu groß"))?;
    conn.set_write_deadline(Some(deadline))?;
    let mut v = Vec::with_capacity(data.len() + 4);
    v.extend_from_slice(&len.to_le_bytes());
    v.extend_from_slice(data);
    conn.write_all(&v)?;
    conn.flush()
}

/// Verbindung mit Ablaufdaten für Lesen und Schreiben.
pub trait Conn: Read + Write {
    fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()>;
    fn set_write_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()>;
}

#[cfg(unix)]
impl Conn for std::os::unix::net::UnixStream {
    fn set_read_deadline(&mut self, d: Option<Instant>) -> io::Result<()> {
        self.set_read_timeout(remaining(d)?)
    }
    fn set_write_deadline(&mut self, d: Option<Instant>) -> io::Result<()> {
        self.set_write_timeout(remaining(d)?)
    }
}

/// Restzeit bis zum Ablaufdatum; abgelaufen = Zeitüberschreitung.
pub fn remaining(d: Option<Instant>) -> io::Result<Option<Duration>> {
    match d {
        None => Ok(None),
        Some(d) => {
            let now = Instant::now();
            if now >= d {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(Some((d - now).max(Duration::from_millis(1))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(body: Body) -> Request {
        Request {
            protocol: IPC_PROTOCOL.into(),
            seq: 1,
            nonce: "0123456789abcdef0123456789abcdef".into(),
            body,
        }
    }

    #[test]
    fn only_listed_commands_and_fields_are_accepted() {
        let ok = r#"{"protocol":"axsafe.ipc/1","seq":1,"nonce":"0123456789abcdef0123456789abcdef","body":{"type":"status"}}"#;
        assert!(serde_json::from_str::<Request>(ok).is_ok());
        for bad in [
            // unbekannter Befehl
            r#"{"protocol":"axsafe.ipc/1","seq":1,"nonce":"0123456789abcdef0123456789abcdef","body":{"type":"shell","cmd":"del"}}"#,
            // vom Client mitgelieferte Identität wird nicht angenommen
            r#"{"protocol":"axsafe.ipc/1","seq":1,"nonce":"0123456789abcdef0123456789abcdef","body":{"type":"status"},"user_sid":"S-1-5-18"}"#,
            r#"{"protocol":"axsafe.ipc/1","seq":1,"nonce":"0123456789abcdef0123456789abcdef","body":{"type":"scan_start","paths":["C:\\x"],"session_id":0}}"#,
            r#"{"protocol":"axsafe.ipc/1","seq":1,"nonce":"0123456789abcdef0123456789abcdef","body":{"type":"delete","path":"C:\\x"}}"#,
        ] {
            assert!(serde_json::from_str::<Request>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn values_are_validated() {
        assert!(validate(&req(Body::Status)).is_ok());
        let mut r = req(Body::Status);
        r.protocol = "axsafe.ipc/2".into();
        assert!(validate(&r).is_err());
        let mut r = req(Body::Status);
        r.nonce = "kurz".into();
        assert!(validate(&r).is_err());
        let mut r = req(Body::Status);
        r.seq = 0;
        assert!(validate(&r).is_err());
        assert!(validate(&req(Body::ScanStart {
            paths: vec![],
            use_clamav: false
        }))
        .is_err());
        assert!(validate(&req(Body::ScanStart {
            paths: vec!["x".into(); MAX_PATHS + 1],
            use_clamav: false
        }))
        .is_err());
        assert!(validate(&req(Body::Report {
            job_id: "../../etc".into()
        }))
        .is_err());
        for p in [
            r"\\server\share\x",
            r"\\?\C:\x",
            r"\\.\PhysicalDrive0",
            "relativ\\pfad",
            "C:",
            "a\0b",
        ] {
            assert!(validate_path(p).is_err(), "{p}");
        }
        assert!(validate_path(r"C:\Users\x\Downloads").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn oversized_and_slow_frames_are_rejected() {
        use std::os::unix::net::UnixStream;
        // übergroß: Länge wird vor dem Allokieren geprüft
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&(MAX_REQUEST_BYTES as u32 + 1).to_le_bytes())
            .unwrap();
        let e = read_frame(&mut b, MAX_REQUEST_BYTES, None, Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // langsam: Kopf kommt, Rest nicht innerhalb der Nachrichtenzeit
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&10u32.to_le_bytes()).unwrap();
        a.write_all(b"abc").unwrap();
        let t = Instant::now();
        let e =
            read_frame(&mut b, MAX_REQUEST_BYTES, None, Duration::from_millis(200)).unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{e:?}"
        );
        assert!(t.elapsed() < Duration::from_secs(2));
        // Leerlauf: kein erstes Byte bis zum Ablaufdatum
        let (_a, mut b) = UnixStream::pair().unwrap();
        let e = read_frame(
            &mut b,
            MAX_REQUEST_BYTES,
            Some(Instant::now() + Duration::from_millis(100)),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{e:?}"
        );
    }
}
