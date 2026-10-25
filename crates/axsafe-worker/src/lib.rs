//! # axsafe-worker (Phase P02, AXS-013)
//!
//! Isolierter Scanworker für YARA-X und der Host-Adapter, der ihn als
//! [`axsafe_core::engine::Engine`] anbietet.
//!
//! * Der **Worker** (`axsafe-worker`) bekommt Regeltexte und Dateibytes über
//!   stdin, nie Pfade. Er läuft unter Windows im **AppContainer ohne
//!   Fähigkeiten** und im **Job Object** (1 Prozess, Speicher, Zeit); unter
//!   Linux beschränkt er sich selbst mit **Landlock**.
//! * Der **Host** ([`host::WorkerEngine`]) startet ihn, prüft die
//!   Abschottung mit einer Probe (Lese-, Schreib-, Anlege-, Verbindungs- und
//!   Startversuch müssen scheitern), begrenzt jede Anfrage zeitlich, beendet
//!   den Worker bei Zeitüberschreitung, Absturz oder Protokollfehler und
//!   startet ihn für das nächste Objekt neu (begrenzte Anzahl).

#![deny(unsafe_code)]

pub mod host;
pub mod probe;
pub mod protocol;
mod sandbox;
mod worker;

pub use worker::{worker_main, worker_main_with, Fault, CRASH_PAYLOAD};
