//! Protokoll `axsafe.clamav-worker/1` zwischen Host und ClamAV-Worker.
//! Rahmenformat und Probe aus diesem Crate. Wird vom Host (Apache-/MIT-
//! Umgebung) und vom ClamAV-Worker (GPL-2.0-verträglich) gemeinsam genutzt;
//! enthält deshalb keinen Code, der libclamav lädt.

use serde::{Deserialize, Serialize};

pub use crate::{
    encode_frame, read_frame, write_frame, ErrorMsg, Probe, ProbeCheck, SandboxReport,
};

pub const PROTOCOL: &str = "axsafe.clamav-worker/1";

/// Höchstgröße einer JSON-Steuernachricht.
pub const MAX_CONTROL_BYTES: usize = 1024 * 1024;
/// Höchstgröße einer Antwort des Workers.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub const T_INIT: u8 = 0x11;
pub const T_SCAN: u8 = 0x12;
pub const T_PROBE: u8 = 0x13;
pub const T_READY: u8 = 0x91;
pub const T_RESULT: u8 = 0x92;
pub const T_PROBE_RESULT: u8 = 0x93;
pub const T_ERROR: u8 = 0xFF;

/// Start: welche Bibliothek, welche Datenbank, welche Grenzen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Init {
    pub protocol: String,
    /// Vollständiger Pfad zu libclamav (Windows: `libclamav.dll` der
    /// ClamAV-Installation; Linux: `libclamav.so.N`).
    pub library: String,
    /// Signaturdatenbank (Ordner oder Datei).
    pub database: String,
    /// Arbeitsordner für entpackte Inhalte (einziger beschreibbarer Ort).
    pub tempdir: String,
    pub max_scan_bytes: u64,
    pub max_filesize: u64,
    pub max_scansize: u64,
    pub max_recursion: u32,
    pub max_files: u32,
    /// Interne Höchstlaufzeit je Scan in libclamav (ms).
    pub max_scantime_ms: u32,
}

/// Ergebnis des Ladens der Datenbank.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbStats {
    /// Anzahl geladener Signaturen (`cl_load`).
    pub signatures: u64,
    /// Version der daily-Datenbank laut Engine (`CL_ENGINE_DB_VERSION`).
    pub db_version: u64,
    /// Erstellzeit laut Engine (Unix-Zeit).
    pub db_time: i64,
    /// Ladedauer (Bibliothek, Datenbank, Kompilierung) in ms.
    pub load_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ready {
    pub protocol: String,
    pub worker_version: String,
    /// `cl_retver()`, z. B. `1.5.4`.
    pub engine_version: String,
    pub flevel: u32,
    pub sandbox: SandboxReport,
    pub database: Result<DbStats, String>,
    /// Namen (nicht Werte) der Umgebungsvariablen, die der Worker sieht.
    pub env_names: Vec<String>,
}

/// Ergebnis eines Scans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ScanResult {
    Clean,
    Virus { name: String },
    Error { code: i32, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReply {
    pub result: ScanResult,
    pub file_kind: axsafe_core::filetype::FileKind,
    pub scan_ms: u64,
}

/// libclamav: `CL_ETIMEOUT` (Position in `cl_error_t`, clamav.h 1.5.4).
pub const CL_ETIMEOUT: i32 = 21;
