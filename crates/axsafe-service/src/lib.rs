//! # axsafe-service (Phase P02, AXS-013, AXS-014)
//!
//! Hintergrunddienst `AXSafeService` mit der lokalen Schnittstelle
//! `axsafe.ipc/1` über die Named Pipe `\\.\pipe\AXSafe.v1`.
//!
//! * **Dienstkonto:** `NT AUTHORITY\LocalService` mit eigener Dienst-SID
//!   (`NT SERVICE\AXSafeService`) und nur den Privilegien
//!   `SeImpersonatePrivilege` (Dateien mit den Rechten des Auftraggebers
//!   öffnen) und `SeChangeNotifyPrivilege`. Kein SYSTEM, keine
//!   Netzwerkanmeldedaten des Rechners.
//! * **Identität** des Auftraggebers ausschließlich aus dem Token der
//!   Verbindung (Benutzer-SID, Anmeldesitzung, Sitzungsnummer des Clients);
//!   nie aus Nachrichtenfeldern.
//! * **Dateizugriff** per Impersonation; scheitert sie, wird nicht mit
//!   Dienstrechten gelesen, sondern eine Lücke gemeldet.
//! * **Typerkennung und YARA-X** im abgeschotteten Worker, **ClamAV** im
//!   AppContainer – der Dienst selbst parst keine Dateiinhalte.
//! * **Grenzen:** Nachrichten, Leerlauf, langsame Übertragung, Anfragerate,
//!   Wiederholungen, parallele und wartende Aufträge.

#![deny(unsafe_code)]

pub mod client;
pub mod handler;
pub mod identity;
pub mod ipc;
pub mod jobs;
pub mod log;
pub mod runner;
#[cfg(windows)]
pub mod win;
