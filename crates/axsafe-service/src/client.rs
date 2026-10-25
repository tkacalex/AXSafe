//! Client für `axsafe.ipc/1` (CLI `axsafe dienst …`, Tests).

use crate::ipc::*;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// Eine Verbindung zum Dienst; Folgenummern und Nonces werden verwaltet.
pub struct Client<C: Read + Write> {
    conn: C,
    seq: u64,
    pub timeout: Duration,
}

/// Zufällige Nonce (32 Hexzeichen) aus einer frischen UUID v4.
pub fn nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

impl<C: Read + Write> Client<C> {
    pub fn new(conn: C) -> Self {
        Client {
            conn,
            seq: 0,
            timeout: Duration::from_secs(30),
        }
    }

    /// Sendet eine Anfrage und liest die Antwort (Antwortgröße begrenzt).
    pub fn call(&mut self, body: Body) -> io::Result<Response> {
        self.seq += 1;
        let req = Request {
            protocol: IPC_PROTOCOL.into(),
            seq: self.seq,
            nonce: nonce(),
            body,
        };
        self.send_raw(&serde_json::to_vec(&req).map_err(io::Error::other)?)?;
        self.read_response()
    }

    /// Rohdaten als Rahmen senden (Tests: verfälschte Anfragen).
    pub fn send_raw(&mut self, data: &[u8]) -> io::Result<()> {
        let len = u32::try_from(data.len()).map_err(io::Error::other)?;
        let mut v = len.to_le_bytes().to_vec();
        v.extend_from_slice(data);
        self.conn.write_all(&v)?;
        self.conn.flush()
    }

    pub fn read_response(&mut self) -> io::Result<Response> {
        let t = Instant::now();
        let mut len = [0u8; 4];
        self.conn.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        if len == 0 || len > MAX_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Antwortlänge {len} unzulässig"),
            ));
        }
        let mut buf = vec![0u8; len];
        self.conn.read_exact(&mut buf)?;
        if t.elapsed() > self.timeout {
            return Err(io::ErrorKind::TimedOut.into());
        }
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Nächste Folgenummer manuell setzen (Tests: Wiederholungen).
    pub fn set_seq(&mut self, s: u64) {
        self.seq = s;
    }

    pub fn conn_mut(&mut self) -> &mut C {
        &mut self.conn
    }
}

/// Verbindet zur Pipe des lokalen Dienstes.
#[cfg(windows)]
pub fn connect() -> io::Result<Client<std::fs::File>> {
    Ok(Client::new(crate::win::connect_client(
        Duration::from_secs(5),
    )?))
}

#[cfg(not(windows))]
pub fn connect() -> io::Result<Client<std::fs::File>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Der AXSafe-Dienst existiert nur unter Windows",
    ))
}
