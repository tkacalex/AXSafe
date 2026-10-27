//! Herkunft und Heuristiken (AXS-025).
//!
//! **Herkunft:** Mark of the Web aus dem Datenstrom `Zone.Identifier`
//! (Windows). Gespeichert werden nur Zone und Rechnername der Quelle –
//! vollständige Adressen können Kennungen oder persönliche Daten enthalten.
//!
//! **Heuristiken** erzeugen einen Fund nur bei eindeutigen Täuschungsmustern
//! und nennen immer ihre Belege. Jede Heuristik hat gutartige Gegenfälle in
//! den Tests. Bewusst KEINE Funde aus: hoher Entropie, fehlender Signatur,
//! wenigen Importen, Overlay, Herkunft aus dem Internet – das sind nur
//! Hinweise, denn gutartige Programme (Installer, gepackte Werkzeuge, .NET,
//! frisch heruntergeladene Software) zeigen sie ebenso.

use crate::engine::{Detection, EngineOutcome};
use crate::features::StaticFeatures;
use crate::filetype::FileKind;
use crate::verdict::{Confidence, Severity, Verdict};
use serde::{Deserialize, Serialize};

/// Version der Heuristiken (geht in Berichte und Cache-Schlüssel ein).
pub const HEURISTICS_VERSION: &str = "heuristik-1";
pub const HEURISTICS_ENGINE: &str = "axsafe-heuristik";
/// Höchstgröße des gelesenen `Zone.Identifier`.
pub const MAX_ZONE_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    /// 0 Lokal, 1 Intranet, 2 Vertrauenswürdig, 3 Internet, 4 Eingeschränkt.
    pub zone_id: Option<u32>,
    pub zone: String,
    /// Nur der Rechnername der Download-Adresse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer_host: Option<String>,
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?; // Zugangsdaten nie übernehmen
    let host = host.split(':').next()?;
    (!host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')))
    .then(|| host.to_ascii_lowercase())
}

/// `Zone.Identifier` lesen (INI-Format). Unbekannte Zeilen werden ignoriert.
pub fn parse_zone_identifier(text: &str) -> Option<Origin> {
    let text: String = text.chars().take(MAX_ZONE_BYTES).collect();
    let mut zone_id = None;
    let mut host = None;
    let mut referrer = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "zoneid" => zone_id = v.trim().parse::<u32>().ok(),
            "hosturl" => host = host_of(v.trim()),
            "referrerurl" => referrer = host_of(v.trim()),
            _ => {}
        }
    }
    let zone = match zone_id {
        Some(0) => "Lokaler Computer",
        Some(1) => "Intranet",
        Some(2) => "Vertrauenswürdige Sites",
        Some(3) => "Internet",
        Some(4) => "Eingeschränkte Sites",
        Some(_) => "unbekannte Zone",
        None => return None,
    };
    Some(Origin {
        zone_id,
        zone: zone.into(),
        host,
        referrer_host: referrer,
    })
}

/// Authenticode-Ergebnis (Windows `WinVerifyTrust`, ohne Netzabfrage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authenticode {
    /// `gueltig`, `unsigniert`, `manipuliert`, `nicht_vertrauenswuerdig`,
    /// `abgelaufen`, `widerrufen_oder_misstraut`, `fehler`, `nicht_pruefbar`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    pub detail: String,
}

const EXEC_EXT: &[&str] = &[
    "exe", "scr", "com", "pif", "cpl", "msi", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "ps1", "lnk", "dll",
];
const DOC_EXT: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "jpg", "jpeg", "png", "gif",
    "bmp", "mp3", "mp4", "avi", "wav", "zip", "rar", "7z", "csv", "htm", "html",
];

fn is_program(kind: &FileKind) -> bool {
    matches!(
        kind,
        FileKind::Pe { .. } | FileKind::PeMalformed | FileKind::Script { .. } | FileKind::Lnk
    )
}

fn det(id: &str, name: &str, conf: Confidence, evidence: Vec<String>) -> Detection {
    Detection {
        name: name.into(),
        verdict: Verdict::Suspicious,
        severity: Severity::Medium,
        confidence: conf,
        rule_id: Some(id.into()),
        rule_version: Some(HEURISTICS_VERSION.into()),
        evidence,
        test_signature: false,
    }
}

/// Bewertet Name, Typ und Merkmale. Liefert Funde (nur Täuschungsmuster)
/// und Hinweise (nie ein Fund).
pub fn evaluate(
    file_name: &str,
    kind: &FileKind,
    features: Option<&StaticFeatures>,
    origin: Option<&Origin>,
    authenticode: Option<&Authenticode>,
) -> (Vec<Detection>, Vec<String>) {
    let mut dets = Vec::new();
    let mut hints = Vec::new();
    let lower = file_name.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    let ext = if parts.len() > 1 {
        parts[parts.len() - 1]
    } else {
        ""
    };

    // H1: Steuerzeichen zur Umkehr der Schreibrichtung im Namen (z. B. U+202E).
    let rtl: Vec<String> = file_name
        .chars()
        .filter(|c| matches!(*c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
        .map(|c| format!("U+{:04X}", c as u32))
        .collect();
    if !rtl.is_empty() && is_program(kind) {
        dets.push(det(
            "AXS-HEUR-0001",
            "AXSafe.Heuristik.Schreibrichtungstrick",
            Confidence::High,
            vec![
                format!(
                    "Dateiname enthält Richtungssteuerzeichen {}",
                    rtl.join(", ")
                ),
                format!("Inhalt ist ausführbar: {}", kind.label()),
            ],
        ));
    }
    // H2: doppelte Endung – Dokument-Endung vor einer Programm-Endung,
    // Inhalt ist tatsächlich ein Programm oder Skript.
    if parts.len() >= 3 && is_program(kind) {
        let inner = parts[parts.len() - 2];
        if DOC_EXT.contains(&inner) && EXEC_EXT.contains(&ext) {
            dets.push(det(
                "AXS-HEUR-0002",
                "AXSafe.Heuristik.DoppelteEndung",
                Confidence::Medium,
                vec![
                    format!("Name endet auf .{inner}.{ext}"),
                    format!("Inhalt ist ausführbar: {}", kind.label()),
                ],
            ));
        }
    }
    // H3: Endung gibt ein Dokument vor, Inhalt ist ein Windows-Programm.
    if DOC_EXT.contains(&ext) && matches!(kind, FileKind::Pe { .. } | FileKind::PeMalformed) {
        dets.push(det(
            "AXS-HEUR-0003",
            "AXSafe.Heuristik.ProgrammMitDokumentEndung",
            Confidence::Medium,
            vec![
                format!("Endung .{ext} erwartet ein Dokument/Medium"),
                format!("Inhalt ist ein Windows-Programm: {}", kind.label()),
            ],
        ));
    }

    // Hinweise – nie ein Fund.
    if let Some(o) = origin {
        if o.zone_id.unwrap_or(0) >= 3 {
            hints.push(format!(
                "Herkunft: {}{}",
                o.zone,
                o.host
                    .as_ref()
                    .map(|h| format!(" ({h})"))
                    .unwrap_or_default()
            ));
        }
    }
    if let Some(a) = authenticode {
        if a.status != "gueltig" && a.status != "nicht_pruefbar" {
            hints.push(format!("Authenticode: {} – {}", a.status, a.detail));
        }
    }
    if let Some(c) = features.and_then(|f| f.container.as_ref()) {
        if !c.escaping_names.is_empty() {
            hints.push(format!(
                "{}-Einträge mit Pfadausbruch-Muster ({}) – AXSafe entpackt nicht auf die Platte",
                c.format,
                c.escaping_names.join(", ")
            ));
        }
    }
    if let Some(pe) = features.and_then(|f| f.pe.as_ref()) {
        let packed: Vec<&str> = pe
            .sections
            .iter()
            .filter(|s| {
                let n = s.name.to_ascii_uppercase();
                n.starts_with("UPX") || n == ".ASPACK" || n == ".MPRESS1" || n == ".THEMIDA"
            })
            .map(|s| s.name.as_str())
            .collect();
        if !packed.is_empty() {
            hints.push(format!(
                "Packer-Abschnitte {} (auch bei gutartiger Software üblich)",
                packed.join(", ")
            ));
        }
        for s in &pe.sections {
            if s.executable && s.writable {
                hints.push(format!(
                    "Abschnitt {} ist zugleich ausführbar und beschreibbar",
                    s.name
                ));
            }
            if s.executable && s.entropy >= 7.2 && s.raw_size >= 4096 {
                hints.push(format!(
                    "Abschnitt {} hat hohe Entropie {:.2} (komprimiert oder verschlüsselt – kein Fund)",
                    s.name, s.entropy
                ));
            }
        }
        if pe.imports.is_empty() {
            hints.push("keine Importe (gepackt oder .NET/ungewöhnlich – kein Fund)".into());
        }
        if pe.entry_section.is_none() && pe.entry_point_rva != 0 {
            hints.push("Einsprungpunkt liegt außerhalb aller Abschnitte".into());
        }
        if pe.overlay_bytes > 1024 * 1024 {
            hints.push(format!(
                "{} Bytes Overlay hinter den Abschnitten",
                pe.overlay_bytes
            ));
        }
    }
    (dets, hints)
}

/// Engine-Ergebnis der Heuristiken für den Bericht.
pub fn outcome(dets: Vec<Detection>, hints: &[String]) -> EngineOutcome {
    let verdict = if dets.is_empty() {
        Verdict::NoDetection
    } else {
        Verdict::Suspicious
    };
    EngineOutcome {
        engine: HEURISTICS_ENGINE.into(),
        engine_version: crate::AXSAFE_VERSION.into(),
        content_version: HEURISTICS_VERSION.into(),
        verdict,
        detections: dets,
        gaps: Vec::new(),
        note: (!hints.is_empty()).then(|| format!("Hinweise (kein Fund): {}", hints.join("; "))),
        duration_ms: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filetype::{PeMachine, ScriptLanguage};

    fn pe() -> FileKind {
        FileKind::Pe {
            machine: PeMachine::Amd64,
            pe64: true,
            dll: false,
            dotnet: false,
        }
    }

    fn ids(d: &[Detection]) -> Vec<String> {
        d.iter().filter_map(|x| x.rule_id.clone()).collect()
    }

    #[test]
    fn deception_patterns_are_found_with_evidence() {
        let (d, _) = evaluate("Rechnung.pdf.exe", &pe(), None, None, None);
        assert_eq!(ids(&d), vec!["AXS-HEUR-0002"]);
        assert!(d[0].evidence.iter().any(|e| e.contains(".pdf.exe")));
        let (d, _) = evaluate("foto\u{202E}gpj.exe", &pe(), None, None, None);
        assert!(ids(&d).contains(&"AXS-HEUR-0001".to_string()));
        let (d, _) = evaluate("Angebot.pdf", &pe(), None, None, None);
        assert_eq!(ids(&d), vec!["AXS-HEUR-0003"]);
        let js = FileKind::Script {
            language: ScriptLanguage::JavaScript,
        };
        let (d, _) = evaluate("lieferschein.docx.js", &js, None, None, None);
        assert_eq!(ids(&d), vec!["AXS-HEUR-0002"]);
    }

    /// Gutartige Gegenfälle: keine Funde.
    #[test]
    fn benign_counterexamples_give_no_detection() {
        for (name, kind) in [
            ("setup.x64.exe", pe()),
            ("app-1.2.3.exe", pe()),
            ("archiv.tar.gz", FileKind::Gzip),
            ("bericht.pdf", FileKind::Pdf),
            ("bericht.pdf.zip", FileKind::Zip),
            ("notizen.txt", FileKind::Text),
            ("Programm.exe", pe()),
            ("daten.bin", pe()),
            ("\u{0645}\u{0644}\u{0641}.pdf", FileKind::Pdf), // arabischer Name, PDF-Inhalt
        ] {
            let (d, _) = evaluate(name, &kind, None, None, None);
            assert!(d.is_empty(), "{name}: {d:?}");
        }
    }

    /// Hohe Entropie, fehlende Signatur, Internet-Herkunft, Packer: nur Hinweise.
    #[test]
    fn weak_signals_are_hints_never_detections() {
        let mut f = crate::features::pe_features(&crate::features::tests::tiny_pe(0, 0));
        f.sections[0].name = "UPX0".into();
        f.sections[0].entropy = 7.9;
        f.sections[0].raw_size = 8192;
        f.sections[0].writable = true;
        f.imports.clear();
        let feats = StaticFeatures {
            entropy: 7.9,
            pe: Some(f),
            container: None,
        };
        let origin = parse_zone_identifier("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://user:pw@download.example.org/a.exe?token=geheim\r\n").unwrap();
        let auth = Authenticode {
            status: "unsigniert".into(),
            signer: None,
            detail: "keine eingebettete Signatur".into(),
        };
        let (d, h) = evaluate("tool.exe", &pe(), Some(&feats), Some(&origin), Some(&auth));
        assert!(d.is_empty(), "{d:?}");
        assert!(h
            .iter()
            .any(|x| x.contains("Internet") && x.contains("download.example.org")));
        assert!(h.iter().any(|x| x.contains("unsigniert")));
        assert!(h.iter().any(|x| x.contains("UPX0")));
        assert!(h.iter().any(|x| x.contains("hohe Entropie")));
        assert!(!h.iter().any(|x| x.contains("geheim") || x.contains("pw@")));
        let o = outcome(d, &h);
        assert_eq!(o.verdict, Verdict::NoDetection);
    }

    #[test]
    fn zone_identifier_parsing_is_bounded_and_strips_secrets() {
        let o = parse_zone_identifier("[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://www.example.com/x\nHostUrl=https://a:b@cdn.example.net:8443/f?k=v").unwrap();
        assert_eq!(o.zone_id, Some(3));
        assert_eq!(o.host.as_deref(), Some("cdn.example.net"));
        assert_eq!(o.referrer_host.as_deref(), Some("www.example.com"));
        assert!(parse_zone_identifier("kein ini").is_none());
        let long = format!("[ZoneTransfer]\nZoneId=3\n{}", "x".repeat(100_000));
        assert!(parse_zone_identifier(&long).is_some());
    }
}
