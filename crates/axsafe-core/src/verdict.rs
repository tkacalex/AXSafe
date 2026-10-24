//! Ehrliches Ergebnismodell (AXS-015, T-015).
//!
//! Grundregel: Nur [`Verdict::NoDetection`] bedeutet „im angegebenen Umfang
//! nichts erkannt“. Jeder andere Zustand ist entweder ein Fund oder eine
//! Prüflücke. Eine Prüflücke wird niemals zu „sauber“ zusammengefasst.

use serde::{Deserialize, Serialize};

/// Bewertung eines Objekts durch eine Engine oder durch AXSafe insgesamt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Verdict {
    /// Genügend belegte schädliche Merkmale gemäß Policy.
    Malicious,
    /// Auffälligkeit mit verbleibender Unsicherheit.
    Suspicious,
    /// Potenziell unerwünschte Anwendung gemäß gesonderter Regelung.
    #[serde(rename = "PUA")]
    Pua,
    /// Im angegebenen Umfang nichts erkannt. Kein Beweis für Harmlosigkeit.
    NoDetection,
    /// Format, Größe oder Pfadart nicht unterstützt: Prüflücke.
    Unsupported,
    /// Inhalt verschlüsselt und ohne Zugang nicht vollständig prüfbar.
    Encrypted,
    /// Berechtigung oder Sperre verhindert die Prüfung.
    AccessDenied,
    /// Zeitbudget überschritten, Ergebnis unvollständig.
    Timeout,
    /// Engine-, Parser- oder Infrastrukturfehler.
    Error,
    /// Objekt hat sich während der Prüfung verändert; Ergebnis verworfen.
    ChangedDuringScan,
}

impl Verdict {
    /// Alle Zustände in stabiler Reihenfolge (für Zählungen und Berichte).
    pub const ALL: [Verdict; 10] = [
        Verdict::Malicious,
        Verdict::Suspicious,
        Verdict::Pua,
        Verdict::NoDetection,
        Verdict::Unsupported,
        Verdict::Encrypted,
        Verdict::AccessDenied,
        Verdict::Timeout,
        Verdict::Error,
        Verdict::ChangedDuringScan,
    ];

    /// `true` für echte Funde (schädlich, verdächtig, PUA).
    pub fn is_detection(self) -> bool {
        matches!(
            self,
            Verdict::Malicious | Verdict::Suspicious | Verdict::Pua
        )
    }

    /// `true` für Zustände, bei denen die Prüfung unvollständig blieb.
    pub fn is_incomplete(self) -> bool {
        matches!(
            self,
            Verdict::Unsupported
                | Verdict::Encrypted
                | Verdict::AccessDenied
                | Verdict::Timeout
                | Verdict::Error
                | Verdict::ChangedDuringScan
        )
    }

    /// Rang für die Zusammenfassung mehrerer Teilergebnisse.
    ///
    /// Ein höherer Rang gewinnt. `NoDetection` hat den niedrigsten Rang,
    /// damit eine einzelne Prüflücke oder ein einzelner Fund nie durch ein
    /// „nichts gefunden“ einer anderen Engine überdeckt wird.
    fn rank(self) -> u8 {
        match self {
            Verdict::NoDetection => 0,
            Verdict::Unsupported => 10,
            Verdict::Encrypted => 11,
            Verdict::AccessDenied => 12,
            Verdict::Timeout => 13,
            Verdict::Error => 14,
            Verdict::Pua => 20,
            Verdict::Suspicious => 21,
            Verdict::Malicious => 22,
            // Ein während der Prüfung verändertes Objekt macht jede
            // Teilbewertung unzuverlässig: neu prüfen.
            Verdict::ChangedDuringScan => 30,
        }
    }

    /// Kurzer deutscher Anzeigetext.
    pub fn label_de(self) -> &'static str {
        match self {
            Verdict::Malicious => "Schädlich",
            Verdict::Suspicious => "Verdächtig",
            Verdict::Pua => "Potenziell unerwünscht (PUA)",
            Verdict::NoDetection => "Nichts erkannt (im geprüften Umfang)",
            Verdict::Unsupported => "Nicht unterstützt (nicht geprüft)",
            Verdict::Encrypted => "Verschlüsselt (nicht vollständig geprüft)",
            Verdict::AccessDenied => "Zugriff verweigert (nicht geprüft)",
            Verdict::Timeout => "Zeitüberschreitung (unvollständig)",
            Verdict::Error => "Fehler (nicht geprüft)",
            Verdict::ChangedDuringScan => "Während der Prüfung geändert (neu prüfen)",
        }
    }
}

/// Fasst mehrere Teilbewertungen zu einer Gesamtbewertung zusammen.
///
/// Eine leere Liste ergibt [`Verdict::Error`]: ohne eine einzige tatsächlich
/// gelaufene Prüfung gibt es keine Aussage, also auch kein „nichts erkannt“.
pub fn aggregate<I: IntoIterator<Item = Verdict>>(verdicts: I) -> Verdict {
    verdicts
        .into_iter()
        .max_by_key(|v| v.rank())
        .unwrap_or(Verdict::Error)
}

/// Schweregrad eines Fundes. Getrennt von Konfidenz und Aktion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Konfidenz eines Fundes. Kein kalibrierter Wahrscheinlichkeitswert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Aktion, die AXSafe tatsächlich ausgeführt hat.
///
/// In dieser Vorversion führt der Scanner **keine** verändernden Aktionen aus
/// (keine Quarantäne, kein Löschen). Quarantäne folgt in Phase P05.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Nur gemeldet, nichts verändert.
    ReportOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_error_not_clean() {
        assert_eq!(aggregate([]), Verdict::Error);
    }

    #[test]
    fn no_incomplete_state_becomes_clean() {
        // T-015: Kein Fehler- oder Teilzustand darf zu NoDetection werden,
        // auch nicht, wenn eine andere Engine nichts gefunden hat.
        for v in Verdict::ALL {
            if v == Verdict::NoDetection {
                continue;
            }
            let combined = aggregate([Verdict::NoDetection, v, Verdict::NoDetection]);
            assert_ne!(combined, Verdict::NoDetection, "{v:?} wurde zu sauber");
            assert_eq!(combined, v);
        }
    }

    #[test]
    fn detection_beats_gap_but_change_beats_all() {
        assert_eq!(
            aggregate([Verdict::Error, Verdict::Malicious]),
            Verdict::Malicious
        );
        assert_eq!(
            aggregate([Verdict::Malicious, Verdict::ChangedDuringScan]),
            Verdict::ChangedDuringScan
        );
    }

    #[test]
    fn only_all_clean_is_clean() {
        assert_eq!(
            aggregate([Verdict::NoDetection, Verdict::NoDetection]),
            Verdict::NoDetection
        );
    }

    #[test]
    fn classification_is_disjoint() {
        for v in Verdict::ALL {
            let classes = [
                v.is_detection(),
                v.is_incomplete(),
                v == Verdict::NoDetection,
            ];
            assert_eq!(classes.iter().filter(|c| **c).count(), 1, "{v:?}");
        }
    }

    #[test]
    fn serde_names_are_stable() {
        let json = serde_json::to_string(&Verdict::Pua).unwrap();
        assert_eq!(json, "\"PUA\"");
        let json = serde_json::to_string(&Verdict::ChangedDuringScan).unwrap();
        assert_eq!(json, "\"ChangedDuringScan\"");
    }
}
