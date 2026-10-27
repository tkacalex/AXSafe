//! # axsafe-core
//!
//! Der Kern von AXSafe. Er enthält bewusst **keine** Erkennungslogik einer
//! bestimmten Engine, sondern die Verträge, die jede Engine erfüllen muss:
//!
//! * [`verdict`]: das ehrliche Ergebnismodell (AXS-015). Fehler, fehlende
//!   Rechte, Zeitüberschreitungen und nicht unterstützte Formate werden nie
//!   zu „sauber“ umgedeutet.
//! * [`identity`]: Dateiidentität über Volume, Datei-ID, Größe und
//!   Änderungszeit statt nur über den Pfad (AXS-018, erster Schritt).
//! * [`filetype`]: Typbestimmung nach Inhalt statt nach Dateiendung (AXS-023).
//! * [`engine`]: der Adaptervertrag für austauschbare Engines (AXS-021).
//! * [`scan`]: Orchestrierung eines Scanauftrags mit Grenzen und Teilstatus.
//! * [`report`]: maschinenlesbarer Scanbericht mit Versionen und Umfang.
//!
//! Status: Vorversion. Dies ist **kein** Echtzeitschutz und kein Ersatz für
//! einen aktiven Virenschutz.

// Unsicherer Code ist verboten. Einzige Ausnahme: der dokumentierte
// Windows-Aufruf GetFileInformationByHandle in `identity` (eng gekapselt).
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

pub mod cache;
pub mod engine;
pub mod features;
pub mod filetype;
pub mod health;
pub mod heuristics;
pub mod identity;
pub mod policy;
pub mod report;
pub mod resume;
pub mod scan;
pub mod scanjob;
pub mod trust;
pub mod verdict;

/// Version des Berichtsschemas. Wird bei inkompatiblen Änderungen erhöht.
pub const REPORT_SCHEMA_VERSION: &str = "axsafe.scan-report/2";

/// Version der eingebauten Standardpolicy (Limits, Aggregationsregeln).
pub const POLICY_VERSION: &str = "policy-2026.10.24-2";

/// Paketversion von AXSafe.
pub const AXSAFE_VERSION: &str = env!("CARGO_PKG_VERSION");
