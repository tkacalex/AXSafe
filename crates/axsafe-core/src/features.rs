//! Statische Merkmale (AXS-025): Entropie, PE-Struktur, Abschnitte, Importe.
//!
//! Läuft auf UNVERTRAUTEN Bytes und deshalb – wie die Typerkennung – im
//! abgeschotteten Worker. Der Parser ist begrenzt: feste Höchstzahlen für
//! Abschnitte, DLLs, Funktionsnamen und Namenslängen; jeder Zugriff ist
//! bereichsgeprüft (`get`), es gibt keine Rekursion und keine Schleife ohne
//! Obergrenze. Beschädigte Strukturen ergeben Hinweise in `notes`, nie
//! einen Absturz.
//!
//! Merkmale sind **keine** Bewertung. Hohe Entropie, fehlende Signatur oder
//! wenige Importe kommen auch in gutartigen Programmen vor (Installer,
//! komprimierte Ressourcen, .NET). Bewertungen entstehen nur in
//! [`crate::heuristics`] mit Belegen und gutartigen Gegenfällen.

use crate::filetype::FileKind;
use serde::{Deserialize, Serialize};

pub const MAX_SECTIONS: usize = 96;
pub const MAX_DLLS: usize = 256;
pub const MAX_FUNCS_PER_DLL: usize = 512;
pub const MAX_TOTAL_FUNCS: usize = 4096;
pub const MAX_NAME: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticFeatures {
    /// Shannon-Entropie der ganzen Datei in Bit je Byte (0–8), 2 Nachkommastellen.
    pub entropy: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeFeatures>,
    /// Strukturprüfung von Containern (AXS-024).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<crate::container::ContainerCheck>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeFeatures {
    pub subsystem: u16,
    /// Zeitstempel aus dem Dateikopf (oft absichtlich verfälscht – nur Hinweis).
    pub timestamp: u32,
    pub entry_point_rva: u32,
    /// Abschnitt, in dem der Einsprungpunkt liegt (`None` = außerhalb).
    pub entry_section: Option<String>,
    pub sections: Vec<Section>,
    pub imports: Vec<ImportDll>,
    pub import_function_count: usize,
    /// Bytes hinter dem letzten Abschnitt (Overlay), ohne Signaturbereich.
    pub overlay_bytes: u64,
    /// Größe des eingebetteten Authenticode-Bereichs (0 = keine eingebettete Signatur).
    pub security_dir_size: u32,
    /// Probleme beim Lesen der Struktur (beschädigt, gekürzt, Grenze erreicht).
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub entropy: f64,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportDll {
    pub dll: String,
    pub functions: Vec<String>,
    /// Weitere Funktionen jenseits der Grenze nicht aufgeführt.
    #[serde(default)]
    pub truncated: bool,
}

/// Shannon-Entropie in Bit je Byte, gerundet auf 2 Stellen.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f64;
    let e: f64 = counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum();
    (e * 100.0).round() / 100.0
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o.checked_add(2)?)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o.checked_add(4)?)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o.checked_add(8)?)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Nullterminierter ASCII-Name ab `o`, höchstens `MAX_NAME` Bytes.
fn cstr_at(d: &[u8], o: usize) -> Option<String> {
    let s = d.get(o..)?;
    let end = s.iter().take(MAX_NAME).position(|b| *b == 0)?;
    let raw = &s[..end];
    if raw.is_empty() || !raw.iter().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    Some(String::from_utf8_lossy(raw).into_owned())
}

struct RawSection {
    va: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
}

fn rva_to_offset(secs: &[RawSection], rva: u32, len: usize) -> Option<usize> {
    for s in secs {
        let size = s.vsize.max(s.raw_size);
        if rva >= s.va && rva < s.va.checked_add(size)? {
            let delta = rva - s.va;
            if delta >= s.raw_size {
                return None;
            }
            let off = (s.raw_ptr as usize).checked_add(delta as usize)?;
            return (off < len).then_some(off);
        }
    }
    None
}

/// Merkmale bestimmen. Für PE-Dateien zusätzlich die Struktur.
pub fn analyze(data: &[u8], kind: &FileKind) -> StaticFeatures {
    StaticFeatures {
        entropy: entropy(data),
        pe: matches!(kind, FileKind::Pe { .. }).then(|| pe_features(data)),
        container: crate::container::check(data, kind),
    }
}

/// PE-Struktur lesen (begrenzt, bereichsgeprüft).
pub fn pe_features(d: &[u8]) -> PeFeatures {
    let mut f = PeFeatures {
        subsystem: 0,
        timestamp: 0,
        entry_point_rva: 0,
        entry_section: None,
        sections: Vec::new(),
        imports: Vec::new(),
        import_function_count: 0,
        overlay_bytes: 0,
        security_dir_size: 0,
        notes: Vec::new(),
    };
    let Some(pe) = u32_at(d, 0x3c).map(|v| v as usize) else {
        f.notes.push("DOS-Kopf gekürzt".into());
        return f;
    };
    if d.get(pe..pe.saturating_add(4)) != Some(b"PE\0\0") {
        f.notes.push("PE-Signatur fehlt".into());
        return f;
    }
    let coff = pe + 4;
    let nsec = u16_at(d, coff + 2).unwrap_or(0) as usize;
    f.timestamp = u32_at(d, coff + 4).unwrap_or(0);
    let opt_size = u16_at(d, coff + 16).unwrap_or(0) as usize;
    let opt = coff + 20;
    let magic = u16_at(d, opt).unwrap_or(0);
    let pe64 = match magic {
        0x10b => false,
        0x20b => true,
        _ => {
            f.notes
                .push(format!("unbekannter Optional-Header 0x{magic:x}"));
            return f;
        }
    };
    f.entry_point_rva = u32_at(d, opt + 16).unwrap_or(0);
    f.subsystem = u16_at(d, opt + 68).unwrap_or(0);
    let dd = opt + if pe64 { 112 } else { 96 };
    let ndd = u32_at(d, dd - 4).unwrap_or(0).min(16) as usize;
    let dir = |i: usize| -> (u32, u32) {
        if i >= ndd {
            return (0, 0);
        }
        (
            u32_at(d, dd + i * 8).unwrap_or(0),
            u32_at(d, dd + i * 8 + 4).unwrap_or(0),
        )
    };
    // Abschnitte
    let sec_tab = opt + opt_size;
    if nsec > MAX_SECTIONS {
        f.notes.push(format!(
            "{nsec} Abschnitte – nur die ersten {MAX_SECTIONS} gelesen"
        ));
    }
    let mut raw = Vec::new();
    let mut end_of_sections = 0usize;
    for i in 0..nsec.min(MAX_SECTIONS) {
        let s = sec_tab + i * 40;
        let Some(name_b) = d.get(s..s + 8) else {
            f.notes.push("Abschnittstabelle gekürzt".into());
            break;
        };
        let name: String = name_b
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| {
                if b.is_ascii_graphic() {
                    *b as char
                } else {
                    '?'
                }
            })
            .collect();
        let vsize = u32_at(d, s + 8).unwrap_or(0);
        let va = u32_at(d, s + 12).unwrap_or(0);
        let raw_size = u32_at(d, s + 16).unwrap_or(0);
        let raw_ptr = u32_at(d, s + 20).unwrap_or(0);
        let ch = u32_at(d, s + 36).unwrap_or(0);
        let start = raw_ptr as usize;
        let end = start.saturating_add(raw_size as usize).min(d.len());
        let body = d.get(start.min(d.len())..end).unwrap_or(&[]);
        if (raw_size as usize) > body.len() {
            f.notes.push(format!("Abschnitt {name}: Rohdaten gekürzt"));
        }
        end_of_sections = end_of_sections.max(end);
        f.sections.push(Section {
            name: name.clone(),
            virtual_size: vsize,
            raw_size,
            entropy: entropy(body),
            executable: ch & 0x2000_0000 != 0,
            writable: ch & 0x8000_0000 != 0,
        });
        raw.push(RawSection {
            va,
            vsize,
            raw_ptr,
            raw_size,
        });
        if f.entry_section.is_none()
            && f.entry_point_rva >= va
            && f.entry_point_rva < va.saturating_add(vsize.max(raw_size))
        {
            f.entry_section = Some(name);
        }
    }
    // Signaturbereich (Datenverzeichnis 4; Offset ist ein Dateioffset).
    let (sec_off, sec_size) = dir(4);
    f.security_dir_size = sec_size;
    let file_end = if sec_size > 0 && (sec_off as usize) >= end_of_sections {
        (sec_off as usize).min(d.len())
    } else {
        d.len()
    };
    f.overlay_bytes = file_end.saturating_sub(end_of_sections) as u64;
    // Importe (Datenverzeichnis 1).
    let (imp_rva, _) = dir(1);
    if imp_rva != 0 {
        match rva_to_offset(&raw, imp_rva, d.len()) {
            None => f.notes.push("Importverzeichnis außerhalb der Datei".into()),
            Some(mut desc) => {
                let mut total = 0usize;
                for _ in 0..MAX_DLLS {
                    let (Some(ilt), Some(name_rva), Some(iat)) =
                        (u32_at(d, desc), u32_at(d, desc + 12), u32_at(d, desc + 16))
                    else {
                        f.notes.push("Importverzeichnis gekürzt".into());
                        break;
                    };
                    if ilt == 0 && name_rva == 0 && iat == 0 {
                        break;
                    }
                    let dll = rva_to_offset(&raw, name_rva, d.len())
                        .and_then(|o| cstr_at(d, o))
                        .unwrap_or_else(|| "?".into());
                    let thunks = if ilt != 0 { ilt } else { iat };
                    let mut entry = ImportDll {
                        dll,
                        functions: Vec::new(),
                        truncated: false,
                    };
                    if let Some(mut t) = rva_to_offset(&raw, thunks, d.len()) {
                        let step = if pe64 { 8 } else { 4 };
                        for _ in 0..MAX_FUNCS_PER_DLL + 1 {
                            let v = if pe64 {
                                u64_at(d, t)
                            } else {
                                u32_at(d, t).map(u64::from)
                            };
                            let Some(v) = v else { break };
                            if v == 0 {
                                break;
                            }
                            if entry.functions.len() >= MAX_FUNCS_PER_DLL
                                || total >= MAX_TOTAL_FUNCS
                            {
                                entry.truncated = true;
                                break;
                            }
                            let ordinal_flag = if pe64 { 1u64 << 63 } else { 1u64 << 31 };
                            let name = if v & ordinal_flag != 0 {
                                format!("#{}", v & 0xffff)
                            } else {
                                rva_to_offset(&raw, (v & 0x7fff_ffff) as u32, d.len())
                                    .and_then(|o| cstr_at(d, o + 2))
                                    .unwrap_or_else(|| "?".into())
                            };
                            entry.functions.push(name);
                            total += 1;
                            t += step;
                        }
                    }
                    f.import_function_count += entry.functions.len();
                    f.imports.push(entry);
                    desc += 20;
                }
                if f.imports.len() >= MAX_DLLS {
                    f.notes
                        .push(format!("mehr als {MAX_DLLS} Import-DLLs – gekürzt"));
                }
            }
        }
    }
    f
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Baut eine kleine, gültige PE32+-Datei mit zwei Abschnitten und einem
    /// Import (`KERNEL32.dll!ExitProcess`). Nur zum Testen; nicht lauffähig
    /// gedacht und wird nie ausgeführt.
    pub fn tiny_pe(text_fill: u8, extra_overlay: usize) -> Vec<u8> {
        let mut d = vec![0u8; 0x400];
        d[0] = b'M';
        d[1] = b'Z';
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        d[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        d[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        d[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        d[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());
        let opt = coff + 20;
        d[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        d[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        d[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        // Importverzeichnis bei RVA 0x2000
        d[opt + 112 + 8..opt + 112 + 12].copy_from_slice(&0x2000u32.to_le_bytes());
        d[opt + 112 + 12..opt + 112 + 16].copy_from_slice(&40u32.to_le_bytes());
        let st = opt + 240;
        let sec = |d: &mut Vec<u8>, i: usize, name: &[u8], va: u32, ptr: u32, ch: u32| {
            let s = st + i * 40;
            d[s..s + name.len()].copy_from_slice(name);
            d[s + 8..s + 12].copy_from_slice(&0x200u32.to_le_bytes());
            d[s + 12..s + 16].copy_from_slice(&va.to_le_bytes());
            d[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes());
            d[s + 20..s + 24].copy_from_slice(&ptr.to_le_bytes());
            d[s + 36..s + 40].copy_from_slice(&ch.to_le_bytes());
        };
        sec(&mut d, 0, b".text", 0x1000, 0x200, 0x6000_0020);
        sec(&mut d, 1, b".rdata", 0x2000, 0x400, 0x4000_0040);
        for b in &mut d[0x200..0x400] {
            *b = text_fill;
        }
        let mut r = vec![0u8; 0x200];
        // Importdeskriptor: ILT 0x2040, Name 0x2080, IAT 0x2040
        r[0..4].copy_from_slice(&0x2040u32.to_le_bytes());
        r[12..16].copy_from_slice(&0x2080u32.to_le_bytes());
        r[16..20].copy_from_slice(&0x2040u32.to_le_bytes());
        r[0x40..0x48].copy_from_slice(&0x20a0u64.to_le_bytes());
        r[0x80..0x80 + 13].copy_from_slice(b"KERNEL32.dll\0");
        r[0xa2..0xa2 + 12].copy_from_slice(b"ExitProcess\0");
        d.extend_from_slice(&r);
        d.extend(std::iter::repeat_n(0x41u8, extra_overlay));
        d
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7u8; 1000]), 0.0);
        let all: Vec<u8> = (0..=255u8).cycle().take(256 * 16).collect();
        assert_eq!(entropy(&all), 8.0);
    }

    #[test]
    fn pe_sections_imports_and_overlay() {
        let d = tiny_pe(0x90, 100);
        let f = pe_features(&d);
        assert!(f.notes.is_empty(), "{:?}", f.notes);
        assert_eq!(f.sections.len(), 2);
        assert_eq!(f.sections[0].name, ".text");
        assert!(f.sections[0].executable && !f.sections[0].writable);
        assert_eq!(f.entry_section.as_deref(), Some(".text"));
        assert_eq!(f.subsystem, 3);
        assert_eq!(f.imports.len(), 1);
        assert_eq!(f.imports[0].dll, "KERNEL32.dll");
        assert_eq!(f.imports[0].functions, vec!["ExitProcess".to_string()]);
        assert_eq!(f.overlay_bytes, 100);
        assert_eq!(f.security_dir_size, 0);
    }

    #[test]
    fn every_truncation_and_bitflip_is_safe() {
        let d = tiny_pe(0x90, 10);
        for n in 0..d.len() {
            let _ = pe_features(&d[..n]);
        }
        let mut x: u64 = 0x1234_5678;
        for _ in 0..5000 {
            let mut m = d.clone();
            for _ in 0..4 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x as usize) % m.len();
                m[i] = (x >> 32) as u8;
            }
            let f = pe_features(&m);
            assert!(f.sections.len() <= MAX_SECTIONS);
            assert!(f.import_function_count <= MAX_TOTAL_FUNCS);
        }
    }

    #[test]
    fn non_pe_has_only_entropy() {
        let f = analyze(b"hallo welt", &FileKind::Text);
        assert!(f.pe.is_none());
        assert!(f.entropy > 0.0);
    }
}
