//! Protokoll `axsafe.worker/1` zwischen Host und Scanworker.
//!
//! Rahmen: `u32` Länge (Little Endian, zählt Typbyte + Nutzdaten), `u8` Typ,
//! Nutzdaten. Steuernachrichten sind JSON, Scan-Daten roh. Beide Seiten
//! prüfen Höchstgrößen, bevor sie Speicher anfordern.

use axsafe_engine_yarax::{RuleSource, RuleStats};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const PROTOCOL: &str = "axsafe.worker/2";

/// Höchstgröße einer JSON-Steuernachricht (Regeln, Probe).
pub const MAX_CONTROL_BYTES: usize = 16 * 1024 * 1024;
/// Höchstgröße einer Antwort des Workers.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub const T_INIT: u8 = 0x01;
pub const T_SCAN: u8 = 0x02;
pub const T_PROBE: u8 = 0x03;
pub const T_READY: u8 = 0x81;
pub const T_RESULT: u8 = 0x82;
pub const T_PROBE_RESULT: u8 = 0x83;
pub const T_ERROR: u8 = 0xFF;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Init {
    pub protocol: String,
    pub rules: Vec<RuleSource>,
    /// Größte zulässige Scan-Nutzlast in Bytes.
    pub max_scan_bytes: u64,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ready {
    pub protocol: String,
    pub worker_version: String,
    pub engine_version: String,
    pub sandbox: SandboxReport,
    /// Kennzahlen oder Ladefehler des Regelsatzes.
    pub rules: Result<RuleStats, String>,
    /// Namen (nicht Werte) der Umgebungsvariablen, die der Worker sieht.
    /// Der Host prüft, dass nur ausdrücklich festgelegte vorhanden sind.
    #[serde(default)]
    pub env_names: Vec<String>,
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

/// Antwort auf einen Scan: Ergebnis der Engine und der im Worker bestimmte
/// Dateityp (der Host parst Dateiinhalte nicht selbst).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReply {
    pub outcome: axsafe_core::engine::EngineOutcome,
    pub file_kind: axsafe_core::filetype::FileKind,
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

#[cfg(test)]
mod tests {
    use super::*;

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
