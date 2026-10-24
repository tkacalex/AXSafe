//! Adaptervertrag für austauschbare Engines (AXS-021).
//!
//! Jede Engine bekommt denselben, bereits gelesenen und gehashten
//! Inhaltsschnappschuss. Dadurch prüfen alle Engines exakt dieselben Bytes,
//! und der Pfad wird nicht ein zweites Mal geöffnet (kein Prüf-/Nutzungs-
//! Rennen zwischen Engines).
//!
//! Jede Engine erklärt verbindlich, **welche Containerformate sie inhaltlich**
//! prüft ([`EngineCapabilities`]). Ein Rohbytescan über einen Container ist
//! keine Inhaltsprüfung; der Kern meldet dann eine Prüflücke (Befund 3).

use crate::filetype::{ContentFormat, FileKind};
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
    /// Zeitbudget für diese Engine und dieses Objekt (gesamter Aufruf).
    pub timeout: Duration,
}

/// Ein einzelner Fund mit nachvollziehbaren Belegen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    /// Name der Erkennung, z. B. `AXSafe.Test.EICAR`.
    pub name: String,
    /// Bewertung dieses Fundes (nur `Malicious`, `Suspicious` oder `PUA`).
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

/// Stabile Ursachencodes für Prüflücken (für Berichte und Oberfläche).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    /// Beauftragte Engine war nicht betriebsbereit.
    EngineUnavailable,
    /// Engine meldete einen Fehler (Absturz, ungültige Ausgabe, Startfehler).
    EngineError,
    /// Gemeinsames Zeitbudget des Engine-Aufrufs überschritten.
    EngineTimeout,
    /// Engine-Ausgabe überschritt das erlaubte Maß und wurde verworfen.
    OutputLimit,
    /// Containerinhalt wurde von keiner aktiven Engine geprüft.
    ContentNotInspected,
    /// Verschlüsselter Inhalt (von einer Engine zuverlässig festgestellt).
    Encrypted,
    /// Engine-interne Grenzwerte (Größe, Rekursion) überschritten.
    EngineLimitExceeded,
    /// Datei größer als das AXSafe-Limit.
    SizeLimit,
    /// Verzeichnistiefe überschritten.
    DepthLimit,
    /// Link, Junction oder Reparsepunkt wird nicht verfolgt.
    LinkNotFollowed,
    /// Kein reguläres Dateiobjekt (Gerät, Pipe, Socket).
    NotRegularFile,
    /// Fehlende Rechte oder Sperre.
    AccessDenied,
    /// Anderer Ein-/Ausgabefehler.
    IoError,
    /// Objekt hat sich während der Prüfung verändert.
    ChangedDuringScan,
    /// Auftrag wurde abgebrochen; restliche Objekte nicht geprüft.
    Cancelled,
    /// Keine Engine konfiguriert.
    NoEngine,
}

/// Eine Prüflücke: Was wurde nicht (vollständig) geprüft, wodurch, warum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    /// Einer der Lückenzustände aus dem Ergebnismodell
    /// (`Unsupported`, `Encrypted`, `AccessDenied`, `Timeout`, `Error`,
    /// `ChangedDuringScan`).
    pub state: Verdict,
    pub reason: GapReason,
    /// Verursacher: Engine-Name oder `axsafe`.
    pub source: String,
    /// Verständliche Erklärung.
    pub detail: String,
}

impl Gap {
    pub fn new(state: Verdict, reason: GapReason, source: &str, detail: impl Into<String>) -> Self {
        debug_assert!(state.is_incomplete(), "Lücke braucht einen Lückenzustand");
        Gap {
            state,
            reason,
            source: source.to_string(),
            detail: detail.into(),
        }
    }
}

/// Ergebnis einer Engine für ein Objekt.
///
/// `verdict` fasst das Engine-Ergebnis zusammen. Funde stehen zusätzlich in
/// `detections`, Lücken in `gaps`. Ein Fund und eine Lücke können
/// **gleichzeitig** vorliegen (z. B. Signatur gefunden und Archiv teilweise
/// verschlüsselt); der Kern wertet beide Listen getrennt aus.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineOutcome {
    pub engine: String,
    pub engine_version: String,
    /// Version beziehungsweise Prüfsumme der verwendeten Regeln/Signaturen.
    pub content_version: String,
    pub verdict: Verdict,
    pub detections: Vec<Detection>,
    #[serde(default)]
    pub gaps: Vec<Gap>,
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

/// Art des geladenen Erkennungsinhalts (Befund 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    /// Ausschließlich Funktions-Testregeln (z. B. EICAR). Keine Erkennung
    /// echter Schadsoftware ableitbar.
    TestOnly,
    /// Produktive Regeln/Signaturen (ggf. zusätzlich Testregeln).
    Production,
    /// Offizielle Signaturen des Engine-Herstellers (z. B. ClamAV CVD).
    OfficialSignatures,
    /// Eigene, nicht offizielle Signaturdatenbank (Zweck unbekannt).
    CustomSignatures,
    /// Nicht feststellbar oder nicht geladen.
    Unknown,
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
    /// Was für Erkennungsinhalt geladen ist (getrennt von der Bereitschaft).
    pub content_kind: ContentKind,
    /// Verständliche Beschreibung des Inhalts, z. B. Regelanzahl, Signaturdatum.
    pub content_note: String,
    /// Formate, deren Inhalt die Engine nachweislich prüft.
    pub inspects_contents_of: Vec<ContentFormat>,
    /// Wo und wie abgeschottet die Engine läuft (AXS-013, P02).
    #[serde(default)]
    pub isolation: Isolation,
}

/// Ausführungsort einer Engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationKind {
    /// Im Prozess des Aufrufers, mit dessen Rechten.
    #[default]
    InProcess,
    /// Eigener Kindprozess mit Zeit-, Speicher- und Prozessbaumgrenzen,
    /// aber mit den Rechten des Aufrufers.
    ChildProcess,
    /// Eigener Worker-Prozess mit Grenzen UND eingeschränkten Rechten
    /// (Windows: AppContainer ohne Fähigkeiten; Linux: Landlock).
    SandboxedWorker,
}

/// Isolationsstand einer Engine, so wie er zur Laufzeit festgestellt wurde.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Isolation {
    pub kind: IsolationKind,
    /// `true` nur, wenn die Rechtebeschränkung zur Laufzeit nachgewiesen
    /// wurde (z. B. Schreib- und Verbindungsversuch scheiterten).
    pub enforced: bool,
    /// Verständliche Beschreibung, inkl. bekannter Grenzen.
    pub detail: String,
}

impl Isolation {
    pub fn in_process() -> Self {
        Isolation {
            kind: IsolationKind::InProcess,
            enforced: false,
            detail: "läuft im AXSafe-Prozess mit den Rechten des Benutzers".into(),
        }
    }
}

/// Vertrag für Engineadapter.
pub trait Engine: Send + Sync {
    /// Stabile Kurzbezeichnung, z. B. `yara-x` oder `clamav`.
    fn name(&self) -> &str;
    /// Version, Inhaltsstand, Zustand und Fähigkeiten.
    fn info(&self) -> EngineInfo;
    /// Prüft einen Inhaltsschnappschuss. Darf nie paniken; Fehler werden als
    /// [`Verdict::Error`] beziehungsweise [`Verdict::Timeout`] gemeldet.
    fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome;
}
