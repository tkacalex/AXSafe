//! Identität des Auftraggebers – ausschließlich vom Dienst festgestellt.

use serde::Serialize;

/// Aus dem Windows-Token der Pipe-Verbindung ermittelt (nie vom Client
/// übernommen).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Identity {
    /// Benutzer-SID (`TokenUser`).
    pub user_sid: String,
    /// Anmeldesitzung (`TokenStatistics.AuthenticationId`, LUID).
    pub logon_id: u64,
    /// Terminaldienst-Sitzung (`TokenSessionId`). Der Dienst selbst läuft in
    /// Sitzung 0; diese Nummer ist die des CLIENTS.
    pub session_id: u32,
    /// Anzeigename (nur Anzeige/Protokoll, nie für Entscheidungen).
    pub display: String,
}

impl Identity {
    /// Eigentümergleichheit: gleicher Benutzer UND gleiche Anmeldesitzung.
    /// Ein zweites Anmelden desselben Benutzers (z. B. RunAs, andere
    /// Sitzung) ist ein anderer Eigentümer.
    pub fn same_owner(&self, other: &Identity) -> bool {
        self.user_sid == other.user_sid && self.logon_id == other.logon_id
    }

    /// Nur interaktive Benutzersitzungen dürfen Aufträge erteilen; Dienste
    /// in Sitzung 0 und anonyme/Systemkonten nicht.
    pub fn check_allowed(&self) -> Result<(), String> {
        if self.session_id == 0 {
            return Err("Aufrufer läuft in Sitzung 0 (Dienstsitzung) – nicht zulässig".into());
        }
        for (sid, what) in [
            ("S-1-5-7", "anonym"),
            ("S-1-5-18", "SYSTEM"),
            ("S-1-5-19", "LocalService"),
            ("S-1-5-20", "NetworkService"),
        ] {
            if self.user_sid == sid {
                return Err(format!("Konto {what} darf keine Aufträge erteilen"));
            }
        }
        // Lokale/Domänenkonten (S-1-5-21-…) und Entra-ID-Konten (S-1-12-1-…).
        if !(self.user_sid.starts_with("S-1-5-21-") || self.user_sid.starts_with("S-1-12-1-")) {
            return Err(format!("Kontotyp {} nicht zulässig", self.user_sid));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(sid: &str, session: u32) -> Identity {
        Identity {
            user_sid: sid.into(),
            logon_id: 1,
            session_id: session,
            display: "x".into(),
        }
    }

    #[test]
    fn session_zero_and_service_accounts_are_rejected() {
        assert!(id("S-1-5-21-1-2-3-1001", 1).check_allowed().is_ok());
        assert!(id("S-1-5-21-1-2-3-1001", 0).check_allowed().is_err());
        for sid in [
            "S-1-5-18",
            "S-1-5-19",
            "S-1-5-20",
            "S-1-5-7",
            "S-1-5-80-1-2",
        ] {
            assert!(id(sid, 1).check_allowed().is_err(), "{sid}");
        }
    }
}
