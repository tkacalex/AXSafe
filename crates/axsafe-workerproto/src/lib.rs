//! Gemeinsame Bausteine der isolierten AXSafe-Worker (YARA-X-Worker und
//! ClamAV-Worker): Rahmenformat, Abschottungsbericht, Fehlermeldung und die
//! Isolationsprobe (Worker-Seite).
//!
//! Bewusst OHNE Engine-Abhängigkeiten: Der ClamAV-Worker lädt libclamav
//! (GPL-2.0-only) und darf keine Apache-2.0-only-Komponenten enthalten
//! (siehe docs/LICENSE-REVIEW-libclamav.md).
//!
//! Rahmen: `u32` Länge (Little Endian, zählt Typbyte + Nutzdaten), `u8` Typ,
//! Nutzdaten. Beide Seiten prüfen Höchstgrößen, bevor sie Speicher anfordern.

#![forbid(unsafe_code)]

pub mod clamav;

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::time::Duration;

/// Rechtebeschränkung, wie sie der Worker selbst festgestellt hat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxReport {
    /// `appcontainer`, `landlock` oder `none`.
    pub kind: String,
    /// Dateizugriff beschränkt.
    pub filesystem: bool,
    /// Netzwerk beschränkt.
    pub network: bool,
    pub detail: String,
}

/// Prüfauftrag „verhalte dich wie ein kompromittierter Worker“: Jede Aktion
/// muss scheitern. Es wird nichts geschrieben oder gesendet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Probe {
    /// Vorhandene Dateien: Öffnen zum Lesen versuchen.
    pub read_paths: Vec<String>,
    /// Vorhandene Dateien: Öffnen zum Schreiben versuchen (ohne Kürzen,
    /// ohne Schreiben).
    pub write_paths: Vec<String>,
    /// Ordner: Anlegen einer neuen Datei versuchen.
    pub create_in: Vec<String>,
    /// TCP-Ziele `host:port`: Verbindungsaufbau versuchen.
    pub connect: Vec<String>,
    /// Programme: Start eines Kindprozesses versuchen.
    pub spawn: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCheck {
    pub action: String,
    pub target: String,
    /// `true`, wenn die Aktion verweigert wurde.
    pub denied: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMsg {
    pub message: String,
}

/// Schreibt einen Rahmen.
pub fn write_frame(w: &mut dyn Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    w.write_all(&encode_frame(kind, payload)?)?;
    w.flush()
}

/// Kodiert einen Rahmen in einen Puffer.
pub fn encode_frame(kind: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    let len = u32::try_from(payload.len() + 1)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Rahmen zu groß"))?;
    let mut v = Vec::with_capacity(payload.len() + 5);
    v.extend_from_slice(&len.to_le_bytes());
    v.push(kind);
    v.extend_from_slice(payload);
    Ok(v)
}

/// Liest einen Rahmen; `Ok(None)` bei sauberem Ende vor dem ersten Byte.
pub fn read_frame(r: &mut dyn Read, max_payload: usize) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r.read(&mut len[got..])?;
        if n == 0 {
            return if got == 0 {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        got += n;
    }
    let len = u32::from_le_bytes(len) as usize;
    if len == 0 || len - 1 > max_payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Rahmenlänge {len} unzulässig (höchstens {})",
                max_payload + 1
            ),
        ));
    }
    let mut kind = [0u8; 1];
    r.read_exact(&mut kind)?;
    let mut payload = vec![0u8; len - 1];
    r.read_exact(&mut payload)?;
    Ok(Some((kind[0], payload)))
}

fn check(action: &str, target: &str, r: Result<(), io::Error>) -> ProbeCheck {
    ProbeCheck {
        action: action.into(),
        target: target.into(),
        denied: r.is_err(),
        detail: match r {
            Ok(()) => "ERLAUBT".into(),
            Err(e) => format!("verweigert: {e}"),
        },
    }
}

/// Versucht verbotene Aktionen. Schreibt und sendet nichts; eine
/// versehentlich angelegte Probedatei wird sofort wieder entfernt.
pub fn run_probe(p: &Probe) -> Vec<ProbeCheck> {
    let mut v = Vec::new();
    for path in &p.read_paths {
        let r = std::fs::File::open(path).and_then(|mut f| {
            let mut b = [0u8; 1];
            f.read(&mut b).map(|_| ())
        });
        v.push(check("lesen", path, r));
    }
    for path in &p.write_paths {
        let r = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map(|_| ());
        v.push(check("zum Schreiben öffnen", path, r));
    }
    for dir in &p.create_in {
        let target =
            std::path::Path::new(dir).join(format!("axsafe-probe-{}.tmp", std::process::id()));
        let r = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map(|_| {
                let _ = std::fs::remove_file(&target);
            });
        v.push(check("Datei anlegen", dir, r));
    }
    for addr in &p.connect {
        let r = addr
            .parse::<std::net::SocketAddr>()
            .map_err(io::Error::other)
            .and_then(|a| std::net::TcpStream::connect_timeout(&a, Duration::from_secs(3)))
            .map(|_| ());
        v.push(check("TCP-Verbindung", addr, r));
    }
    for prog in &p.spawn {
        let r = std::process::Command::new(prog)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|mut c| {
                let _ = c.kill();
                let _ = c.wait();
            });
        v.push(check("Programm starten", prog, r));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    const T_SCAN: u8 = 0x02;

    #[test]
    fn roundtrip_and_limits() {
        let f = encode_frame(T_SCAN, b"abc").unwrap();
        let (k, p) = read_frame(&mut &f[..], 16).unwrap().unwrap();
        assert_eq!((k, p.as_slice()), (T_SCAN, &b"abc"[..]));
        // zu groß: wird vor dem Allokieren abgelehnt
        let big = encode_frame(T_SCAN, &[0u8; 32]).unwrap();
        assert!(read_frame(&mut &big[..], 16).is_err());
        // Länge 0 ist unzulässig
        assert!(read_frame(&mut &[0u8, 0, 0, 0][..], 16).is_err());
        // abgeschnittener Kopf
        assert!(read_frame(&mut &[1u8, 0][..], 16).is_err());
        // sauberes Ende
        assert!(read_frame(&mut &[][..], 16).unwrap().is_none());
    }
}
