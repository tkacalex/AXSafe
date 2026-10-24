//! Adaptervertrag für austauschbare Engines (AXS-021).
//!
//! Jede Engine bekommt denselben, bereits gelesenen und gehashten
//! Inhaltsschnappschuss. Dadurch prüfen alle Engines exakt dieselben Bytes,
//! und der Pfad wird nicht ein zweites Mal geöffnet (kein Prüf-/Nutzungs-
//! Rennen zwischen Engines).

use crate::filetype::FileKind;
use crate::verdict::{Confidence, Severity, Verdict};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Was eine Engine zu prüfen bekommt.
pub struct ScanInput<'a> {
    /// Unveränderlicher Inhaltsschnappschuss.
    pub data: &'a [u8],
    /// Inhaltlich bestimmter Typ.
    pub kind: &'a FileKind,
    /// SHA-256 des Inhalts (hex).
    pub sha256: &'a str,
    /// Zeitbudget für diese Engine und dieses Objekt.
    pub timeout: Duration,
}

/// Ein einzelner Fund mit nachvollziehbaren Belegen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    /// Name der Erkennung, z. B. `AXSafe.Test.EICAR`.
    pub name: String,
    /// Bewertung dieses Fundes.
    pub verdict: Verdict,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Regel- oder Signatur-ID, sofern vorhanden.
    pub rule_id: Option<String>,
    /// Kurze, nachvollziehbare Belege (keine vollständigen Inhalte).
    pub evidence: Vec<String>,
    /// `true` für ungefährliche Funktions-Testsignaturen (z. B. EICAR).
    /// Solche Funde belegen nur, dass der Pfad funktioniert, keine Schutzwirkung.
    pub test_signature: bool,
}

/// Ergebnis einer Engine für ein Objekt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineOutcome {
    pub engine: String,
    pub engine_version: String,
    /// Version beziehungsweise Prüfsumme der verwendeten Regeln/Signaturen.
    pub content_version: String,
    pub verdict: Verdict,
    pub detections: Vec<Detection>,
    /// Ehrliche Fehlerbeschreibung bei Prüflücken.
    pub note: Option<String>,
    pub duration_ms: u64,
}

/// Gesundheitszustand einer Engine vor dem Scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EngineHealth {
    /// Engine geladen und betriebsbereit.
    Ready,
    /// Engine nicht nutzbar; Grund steht dabei.
    Unavailable { reason: String },
}

/// Beschreibung einer Engine für Berichte und die Oberfläche.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineInfo {
    pub name: String,
    pub engine_version: String,
    pub content_version: String,
    pub health: EngineHealth,
    /// Lizenz der Engine (nicht der Regeln/Daten).
    pub license: String,
}

/// Vertrag für Engineadapter.
pub trait Engine: Send + Sync {
    /// Stabile Kurzbezeichnung, z. B. `yara-x` oder `clamav`.
    fn name(&self) -> &str;
    /// Version, Inhaltsstand und Zustand.
    fn info(&self) -> EngineInfo;
    /// Prüft einen Inhaltsschnappschuss. Darf nie paniken; Fehler werden als
    /// [`Verdict::Error`] beziehungsweise [`Verdict::Timeout`] gemeldet.
    fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome;
}
