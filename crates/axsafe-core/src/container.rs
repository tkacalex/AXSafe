//! Strukturprüfung von Containern (AXS-024), unabhängig von den Engines.
//!
//! AXSafe entpackt **nichts** selbst und schreibt keine Archivinhalte auf
//! die Platte – ein Pfadausbruch („Zip Slip“) durch AXSafe ist damit
//! ausgeschlossen. Diese Prüfung liest nur Verzeichnisstrukturen (begrenzt)
//! und meldet, was die Engine-Aussage einschränkt:
//!
//! * **beschädigt**: Verzeichnis fehlt, Einträge zeigen außerhalb der Datei,
//!   Prüfsumme des Kopfes falsch → Inhalt evtl. nur teilweise geprüft;
//! * **verschlüsselte Einträge** (ZIP-Flag) → werden als Lücke gemeldet,
//!   auch wenn eine Engine nichts dazu sagt;
//! * **Entpackgröße/Verhältnis** (Archivbombe) → über der Grenze ist nicht
//!   belegt, dass Engines den ganzen Inhalt geprüft haben;
//! * **auffällige Namen** (`..`, absolute Pfade, Laufwerksbuchstaben) –
//!   nur Hinweis, weil AXSafe nicht entpackt.
//!
//! Läuft im Dienst im abgeschotteten Worker (wie die Typerkennung).

use crate::filetype::FileKind;
use serde::{Deserialize, Serialize};

pub const MAX_ENTRIES: usize = 100_000;
/// Ab dieser angegebenen Entpackgröße gilt der Inhalt als nicht sicher
/// vollständig geprüft (ClamAV-Standard MaxScanSize 400 MB).
pub const MAX_EXPANDED_BYTES: u64 = 400 * 1024 * 1024;
/// Ab diesem Verhältnis Entpackgröße : Dateigröße (Archivbombe).
pub const MAX_RATIO: u64 = 1000;
const MAX_NAMES: usize = 16;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerCheck {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<u64>,
    /// Laut Verzeichnis angegebene Entpackgröße (nicht geprüft, nur gelesen).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_expanded_bytes: Option<u64>,
    #[serde(default)]
    pub encrypted_entries: u64,
    /// Strukturfehler (beschädigt/abgeschnitten).
    #[serde(default)]
    pub damage: Vec<String>,
    /// Namen mit Pfadausbruch-Muster (höchstens 16).
    #[serde(default)]
    pub escaping_names: Vec<String>,
    /// Weitere Angaben (z. B. ZIP64 nicht ausgewertet).
    #[serde(default)]
    pub notes: Vec<String>,
}

impl ContainerCheck {
    /// Überschreitet die angegebene Entpackgröße die Grenze?
    pub fn exceeds_expansion(&self, file_len: u64) -> Option<String> {
        let exp = self.declared_expanded_bytes?;
        let ratio = exp / file_len.max(1);
        if exp > MAX_EXPANDED_BYTES || ratio > MAX_RATIO {
            Some(format!(
                "{} entpackt sich laut Verzeichnis auf {} Bytes (Verhältnis {}:1) – über der Grenze \
                 ({} Bytes bzw. {}:1); nicht belegt, dass Engines den gesamten Inhalt geprüft haben",
                self.format, exp, ratio, MAX_EXPANDED_BYTES, MAX_RATIO
            ))
        } else {
            None
        }
    }
}

fn u16le(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn u64le(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}

/// CRC-32 (IEEE), bitweise – nur für kleine Köpfe.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// Name mit Pfadausbruch-Muster?
pub fn escapes(name: &str) -> bool {
    let n = name.replace('\\', "/");
    n.starts_with('/') || n.as_bytes().get(1) == Some(&b':') || n.split('/').any(|c| c == "..")
}

/// Strukturprüfung für unterstützte Formate; `None` für andere.
pub fn check(data: &[u8], kind: &FileKind) -> Option<ContainerCheck> {
    match kind {
        FileKind::Zip | FileKind::Ooxml => Some(zip(data)),
        FileKind::SevenZip => Some(sevenzip(data)),
        FileKind::Cab => Some(cab(data)),
        _ => None,
    }
}

fn zip(d: &[u8]) -> ContainerCheck {
    let mut c = ContainerCheck {
        format: "ZIP".into(),
        ..Default::default()
    };
    // Ende des zentralen Verzeichnisses in den letzten 64 KiB + 22 Bytes.
    let start = d.len().saturating_sub(65_535 + 22);
    let eocd = (start..d.len().saturating_sub(21))
        .rev()
        .find(|&i| d[i..].starts_with(b"PK\x05\x06"));
    let Some(e) = eocd else {
        c.damage
            .push("Ende des zentralen Verzeichnisses fehlt (abgeschnitten oder beschädigt)".into());
        return c;
    };
    let (Some(total), Some(cd_size), Some(cd_off)) =
        (u16le(d, e + 10), u32le(d, e + 12), u32le(d, e + 16))
    else {
        c.damage.push("Verzeichnisende unvollständig".into());
        return c;
    };
    if total == 0xFFFF || cd_off == 0xFFFF_FFFF {
        c.notes
            .push("ZIP64: Verzeichnis nicht ausgewertet (Größenangaben unbekannt)".into());
        return c;
    }
    let (cd_off, cd_size) = (cd_off as usize, cd_size as usize);
    if cd_off.checked_add(cd_size).is_none_or(|end| end > e) {
        c.damage
            .push("zentrales Verzeichnis liegt außerhalb der Datei".into());
        return c;
    }
    let mut p = cd_off;
    let mut n = 0u64;
    let mut expanded = 0u64;
    while p < cd_off + cd_size && (n as usize) < MAX_ENTRIES {
        if !d[p..].starts_with(b"PK\x01\x02") {
            c.damage.push(format!("Verzeichniseintrag {n} beschädigt"));
            break;
        }
        let (Some(flags), Some(usize_), Some(nlen), Some(xlen), Some(clen), Some(loff)) = (
            u16le(d, p + 8),
            u32le(d, p + 24),
            u16le(d, p + 28),
            u16le(d, p + 30),
            u16le(d, p + 32),
            u32le(d, p + 42),
        ) else {
            c.damage
                .push(format!("Verzeichniseintrag {n} abgeschnitten"));
            break;
        };
        let name_end = p + 46 + nlen as usize;
        let name = d
            .get(p + 46..name_end)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        if flags & 1 != 0 {
            c.encrypted_entries += 1;
        }
        if escapes(&name) && c.escaping_names.len() < MAX_NAMES {
            c.escaping_names.push(name.chars().take(256).collect());
        }
        if usize_ == 0xFFFF_FFFF {
            c.notes
                .push("ZIP64-Eintrag: Größe nicht ausgewertet".into());
        } else {
            expanded = expanded.saturating_add(u64::from(usize_));
        }
        if loff as usize >= d.len() || !d[loff as usize..].starts_with(b"PK\x03\x04") {
            c.damage.push(format!(
                "Eintrag {name:?}: lokaler Kopf fehlt oder liegt außerhalb"
            ));
        }
        n += 1;
        p = name_end + xlen as usize + clen as usize;
    }
    if n as usize >= MAX_ENTRIES {
        c.notes.push(format!(
            "mehr als {MAX_ENTRIES} Einträge: Rest nicht gezählt"
        ));
    } else if n != u64::from(total) && c.damage.is_empty() {
        c.damage
            .push(format!("Verzeichnis nennt {total} Einträge, gefunden {n}"));
    }
    c.damage.truncate(MAX_NAMES);
    c.entries = Some(n);
    c.declared_expanded_bytes = Some(expanded);
    c
}

fn sevenzip(d: &[u8]) -> ContainerCheck {
    let mut c = ContainerCheck {
        format: "7z".into(),
        ..Default::default()
    };
    let (Some(start_crc), Some(next_off), Some(next_size), Some(next_crc)) =
        (u32le(d, 8), u64le(d, 12), u64le(d, 20), u32le(d, 28))
    else {
        c.damage.push("Signaturkopf abgeschnitten".into());
        return c;
    };
    if crc32(&d[12..32]) != start_crc {
        c.damage.push("Prüfsumme des Startkopfs falsch".into());
        return c;
    }
    let begin = 32u64.checked_add(next_off);
    let end = begin.and_then(|b| b.checked_add(next_size));
    match (begin, end) {
        (Some(b), Some(e)) if e <= d.len() as u64 => {
            if crc32(&d[b as usize..e as usize]) != next_crc {
                c.damage
                    .push("Prüfsumme des Verzeichniskopfs falsch".into());
            }
        }
        _ => c
            .damage
            .push("Verzeichniskopf liegt außerhalb der Datei (abgeschnitten)".into()),
    }
    c
}

fn cab(d: &[u8]) -> ContainerCheck {
    let mut c = ContainerCheck {
        format: "CAB".into(),
        ..Default::default()
    };
    let (Some(size), Some(files_off), Some(nfiles)) = (u32le(d, 8), u32le(d, 16), u16le(d, 28))
    else {
        c.damage.push("Kopf abgeschnitten".into());
        return c;
    };
    if size as usize != d.len() {
        c.damage.push(format!(
            "Kopf nennt {size} Bytes, Datei hat {} (abgeschnitten oder angehängte Daten)",
            d.len()
        ));
    }
    if files_off as usize >= d.len() {
        c.damage.push("Dateiliste liegt außerhalb der Datei".into());
    }
    c.entries = Some(u64::from(nfiles));
    c
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Minimales, gültiges ZIP (gespeichert, ohne Kompression).
    pub(crate) fn zip_of(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (name, data, enc) in entries {
            let off = out.len() as u32;
            let crc = crc32(data);
            let flags: u16 = if *enc { 1 } else { 0 };
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&flags.to_le_bytes());
            cd.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            cd.extend_from_slice(&crc.to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0u8; 12]);
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn intact_zip_has_no_findings() {
        let z = zip_of(&[("a.txt", b"hallo", false), ("ordner/b.txt", b"welt", false)]);
        let c = check(&z, &FileKind::Zip).unwrap();
        assert!(c.damage.is_empty(), "{c:?}");
        assert_eq!(c.entries, Some(2));
        assert_eq!(c.declared_expanded_bytes, Some(9));
        assert!(c.escaping_names.is_empty());
        assert!(c.exceeds_expansion(z.len() as u64).is_none());
    }

    #[test]
    fn truncated_zip_is_damaged() {
        let z = zip_of(&[("a.txt", b"hallo", false)]);
        for cut in [z.len() - 1, z.len() / 2, 10] {
            let c = check(&z[..cut], &FileKind::Zip).unwrap();
            assert!(!c.damage.is_empty(), "abgeschnitten bei {cut}: {c:?}");
        }
    }

    #[test]
    fn escaping_names_and_encrypted_entries_are_reported() {
        let z = zip_of(&[
            ("../../ausbruch.txt", b"x", false),
            ("/etc/x", b"x", false),
            ("C:\\Windows\\x.dll", b"x", false),
            ("..\\..\\y", b"x", false),
            ("normal/..datei", b"x", false),
            ("geheim.txt", b"x", true),
        ]);
        let c = check(&z, &FileKind::Zip).unwrap();
        assert_eq!(c.escaping_names.len(), 4, "{c:?}");
        assert!(!c.escaping_names.iter().any(|n| n.contains("..datei")));
        assert_eq!(c.encrypted_entries, 1);
    }

    #[test]
    fn declared_bomb_exceeds_limit() {
        // Verzeichnis behauptet 4 GiB Entpackgröße bei winziger Datei.
        let mut z = zip_of(&[("null.bin", b"", false)]);
        let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        z[cd + 24..cd + 28].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
        let c = check(&z, &FileKind::Zip).unwrap();
        let msg = c.exceeds_expansion(z.len() as u64).unwrap();
        assert!(msg.contains("über der Grenze"));
    }

    #[test]
    fn sevenzip_header_crc_and_bounds() {
        let next = b"\x01\x04\x06\x00";
        let mut d = b"7z\xbc\xaf\x27\x1c\x00\x04".to_vec();
        let mut sh = Vec::new();
        sh.extend_from_slice(&0u64.to_le_bytes());
        sh.extend_from_slice(&(next.len() as u64).to_le_bytes());
        sh.extend_from_slice(&crc32(next).to_le_bytes());
        d.extend_from_slice(&crc32(&sh).to_le_bytes());
        d.extend_from_slice(&sh);
        d.extend_from_slice(next);
        assert!(check(&d, &FileKind::SevenZip).unwrap().damage.is_empty());
        assert!(!check(&d[..d.len() - 2], &FileKind::SevenZip)
            .unwrap()
            .damage
            .is_empty());
        let mut bad = d.clone();
        bad[33] ^= 0xFF;
        assert!(!check(&bad, &FileKind::SevenZip).unwrap().damage.is_empty());
    }

    #[test]
    fn mutated_containers_never_panic() {
        let z = zip_of(&[("a.txt", b"hallo", false), ("b", b"x", true)]);
        for i in 0..z.len() {
            for bit in [0x01u8, 0x80, 0xFF] {
                let mut m = z.clone();
                m[i] ^= bit;
                let _ = check(&m, &FileKind::Zip);
                let _ = check(&m, &FileKind::SevenZip);
                let _ = check(&m, &FileKind::Cab);
            }
            let _ = check(&z[..i], &FileKind::Zip);
            let _ = check(&z[..i], &FileKind::Cab);
            let _ = check(&z[..i], &FileKind::SevenZip);
        }
    }
}
