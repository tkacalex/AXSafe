//! Protokoll `axsafe.worker/1` zwischen Host und Scanworker.
//!
//! Rahmen: `u32` Länge (Little Endian, zählt Typbyte + Nutzdaten), `u8` Typ,
//! Nutzdaten. Steuernachrichten sind JSON, Scan-Daten roh. Beide Seiten
//! prüfen Höchstgrößen, bevor sie Speicher anfordern.

use axsafe_engine_yarax::{RuleSource, RuleStats};
pub use axsafe_workerproto::{
    encode_frame, read_frame, write_frame, ErrorMsg, Probe, ProbeCheck, SandboxReport,
};
use serde::{Deserialize, Serialize};

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

/// Antwort auf einen Scan: Ergebnis der Engine und der im Worker bestimmte
/// Dateityp (der Host parst Dateiinhalte nicht selbst).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReply {
    pub outcome: axsafe_core::engine::EngineOutcome,
    pub file_kind: axsafe_core::filetype::FileKind,
    /// Statische Merkmale (AXS-025), im Worker bestimmt.
    #[serde(default)]
    pub features: Option<axsafe_core::features::StaticFeatures>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_limits() {
        let f = encode_frame(T_SCAN, b"abc").unwrap();
        let (k, p) = read_frame(&mut &f[..], 16).unwrap().unwrap();
        assert_eq!((k, p.as_slice()), (T_SCAN, &b"abc"[..]));
        let big = encode_frame(T_SCAN, &[0u8; 32]).unwrap();
        assert!(read_frame(&mut &big[..], 16).is_err());
    }
}
