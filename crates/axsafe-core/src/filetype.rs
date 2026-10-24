//! Typbestimmung nach Inhalt (AXS-023, T-023).
//!
//! Die Dateiendung wird bewusst **nicht** verwendet: Ein Umbenennen darf die
//! Typbestimmung nicht umgehen. Erkannt werden die Formate über ihre
//! Signaturen („Magic Bytes“) und, bei PE-Dateien, über eine begrenzte und
//! grenzgeprüfte Auswertung der Header.
//!
//! Grenzen dieser Version (in der Fähigkeitsmatrix dokumentiert):
//! * Skriptsprachen (PowerShell, JS, VBS) werden aus dem Inhalt noch nicht
//!   sicher unterschieden und erscheinen als `Text` beziehungsweise `Script`
//!   (nur mit Shebang).
//! * MSI und alte Office-Dokumente teilen das OLE/CFB-Containerformat und
//!   werden noch nicht unterschieden.

use serde::{Deserialize, Serialize};

/// Prozessorarchitektur einer PE-Datei laut `IMAGE_FILE_HEADER.Machine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeMachine {
    I386,
    Amd64,
    Arm64,
    Other,
}

/// Inhaltlich bestimmter Dateityp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileKind {
    /// Leere Datei.
    Empty,
    /// Windows PE (EXE, DLL, SYS …).
    Pe {
        machine: PeMachine,
        /// `true` für PE32+ (64 Bit), `false` für PE32.
        pe64: bool,
        /// `IMAGE_FILE_DLL` gesetzt.
        dll: bool,
        /// CLR-Header vorhanden (.NET-Assembly).
        dotnet: bool,
    },
    /// Beginnt mit `MZ`, aber der PE-Header ist beschädigt oder fehlt.
    PeMalformed,
    Elf,
    /// ZIP-Container (allgemein).
    Zip,
    /// Office Open XML (docx/xlsx/pptx, ZIP-basiert).
    Ooxml,
    /// OLE Compound File (alte Office-Formate oder MSI; nicht unterschieden).
    OleCfb,
    Pdf,
    Rtf,
    /// Windows-Verknüpfung (Shell Link).
    Lnk,
    SevenZip,
    Rar,
    Gzip,
    Cab,
    /// ISO-9660-Abbild.
    Iso,
    Vhdx,
    /// Skript mit Shebang-Zeile.
    Script,
    /// Text ohne sicher bestimmte Sprache.
    Text,
    /// Unbekanntes Binärformat.
    Unknown,
}

impl FileKind {
    /// Kurzer Anzeigename.
    pub fn label(&self) -> String {
        match self {
            FileKind::Pe {
                pe64, dll, dotnet, ..
            } => {
                let base = if *pe64 { "PE64" } else { "PE32" };
                let role = if *dll { " DLL" } else { "" };
                let net = if *dotnet { " .NET" } else { "" };
                format!("{base}{role}{net}")
            }
            other => {
                let s = serde_json::to_value(other)
                    .ok()
                    .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_owned));
                s.unwrap_or_else(|| "unknown".into())
            }
        }
    }

    /// `true` für Containerformate, die weitere Objekte enthalten können.
    pub fn is_container(&self) -> bool {
        matches!(
            self,
            FileKind::Zip
                | FileKind::Ooxml
                | FileKind::OleCfb
                | FileKind::SevenZip
                | FileKind::Rar
                | FileKind::Gzip
                | FileKind::Cab
                | FileKind::Iso
                | FileKind::Vhdx
        )
    }
}

/// Formate mit eingebettetem oder komprimiertem Inhalt. Ein Rohbytescan über
/// die Containerbytes ist bei diesen Formaten **keine** Inhaltsprüfung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentFormat {
    Zip,
    Ooxml,
    OleCfb,
    SevenZip,
    Rar,
    Gzip,
    Cab,
    Iso,
    Vhdx,
    /// PDF enthält meist komprimierte Streams.
    Pdf,
    /// RTF kann eingebettete OLE-Objekte enthalten.
    Rtf,
}

impl ContentFormat {
    pub fn label(self) -> &'static str {
        match self {
            ContentFormat::Zip => "ZIP",
            ContentFormat::Ooxml => "Office (OOXML)",
            ContentFormat::OleCfb => "OLE (Office 97–2003/MSI)",
            ContentFormat::SevenZip => "7z",
            ContentFormat::Rar => "RAR",
            ContentFormat::Gzip => "GZIP",
            ContentFormat::Cab => "CAB",
            ContentFormat::Iso => "ISO",
            ContentFormat::Vhdx => "VHDX",
            ContentFormat::Pdf => "PDF",
            ContentFormat::Rtf => "RTF",
        }
    }
}

/// Liefert das Inhaltsformat, falls der Dateityp eine eigene Inhaltsprüfung
/// braucht; `None` für Formate, bei denen die Rohbytes der Inhalt sind.
pub fn content_format(kind: &FileKind) -> Option<ContentFormat> {
    Some(match kind {
        FileKind::Zip => ContentFormat::Zip,
        FileKind::Ooxml => ContentFormat::Ooxml,
        FileKind::OleCfb => ContentFormat::OleCfb,
        FileKind::SevenZip => ContentFormat::SevenZip,
        FileKind::Rar => ContentFormat::Rar,
        FileKind::Gzip => ContentFormat::Gzip,
        FileKind::Cab => ContentFormat::Cab,
        FileKind::Iso => ContentFormat::Iso,
        FileKind::Vhdx => ContentFormat::Vhdx,
        FileKind::Pdf => ContentFormat::Pdf,
        FileKind::Rtf => ContentFormat::Rtf,
        _ => return None,
    })
}

fn u16_le(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Bestimmt den Typ aus dem Inhalt. Liest nie außerhalb von `data`.
pub fn detect(data: &[u8]) -> FileKind {
    if data.is_empty() {
        return FileKind::Empty;
    }
    if data.starts_with(b"MZ") {
        return parse_pe(data).unwrap_or(FileKind::PeMalformed);
    }
    if data.starts_with(b"\x7fELF") {
        return FileKind::Elf;
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        let head = &data[..data.len().min(64 * 1024)];
        if find(head, b"[Content_Types].xml") {
            return FileKind::Ooxml;
        }
        return FileKind::Zip;
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return FileKind::OleCfb;
    }
    if data.starts_with(b"%PDF-") {
        return FileKind::Pdf;
    }
    if data.starts_with(b"{\\rtf") {
        return FileKind::Rtf;
    }
    if data.starts_with(&[
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ]) {
        return FileKind::Lnk;
    }
    if data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return FileKind::SevenZip;
    }
    if data.starts_with(b"Rar!\x1a\x07") {
        return FileKind::Rar;
    }
    if data.starts_with(&[0x1F, 0x8B]) {
        return FileKind::Gzip;
    }
    if data.starts_with(b"MSCF") {
        return FileKind::Cab;
    }
    if data.starts_with(b"vhdxfile") {
        return FileKind::Vhdx;
    }
    if data.get(0x8001..0x8006) == Some(b"CD001") {
        return FileKind::Iso;
    }
    if data.starts_with(b"#!") {
        return FileKind::Script;
    }
    let head = &data[..data.len().min(8 * 1024)];
    let utf16 = head.starts_with(&[0xFF, 0xFE]) || head.starts_with(&[0xFE, 0xFF]);
    if utf16 || (!head.contains(&0) && std::str::from_utf8(head).is_ok()) {
        return FileKind::Text;
    }
    FileKind::Unknown
}

fn parse_pe(d: &[u8]) -> Option<FileKind> {
    let e_lfanew = u32_le(d, 0x3C)? as usize;
    if d.get(e_lfanew..e_lfanew.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let machine_raw = u16_le(d, coff)?;
    let characteristics = u16_le(d, coff + 18)?;
    let opt = coff + 20;
    let magic = u16_le(d, opt)?;
    let (pe64, n_rva_off, dirs_off) = match magic {
        0x10B => (false, opt + 92, opt + 96),
        0x20B => (true, opt + 108, opt + 112),
        _ => return None,
    };
    let n_rva = u32_le(d, n_rva_off)? as usize;
    // Datenverzeichnis 14 = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (CLR).
    let dotnet = n_rva > 14 && u32_le(d, dirs_off + 14 * 8).unwrap_or(0) != 0;
    let machine = match machine_raw {
        0x014C => PeMachine::I386,
        0x8664 => PeMachine::Amd64,
        0xAA64 => PeMachine::Arm64,
        _ => PeMachine::Other,
    };
    Some(FileKind::Pe {
        machine,
        pe64,
        dll: characteristics & 0x2000 != 0,
        dotnet,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Baut einen minimalen, grenzgültigen PE-Header (nicht ausführbar).
    fn fake_pe(pe64: bool, dll: bool, dotnet: bool) -> Vec<u8> {
        let mut d = vec![0u8; 1024];
        d[0] = b'M';
        d[1] = b'Z';
        let e_lfanew = 0x80u32;
        d[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let coff = 0x80;
        d[coff..coff + 4].copy_from_slice(b"PE\0\0");
        let machine: u16 = if pe64 { 0x8664 } else { 0x014C };
        d[coff + 4..coff + 6].copy_from_slice(&machine.to_le_bytes());
        let ch: u16 = if dll { 0x2000 } else { 0x0002 };
        d[coff + 22..coff + 24].copy_from_slice(&ch.to_le_bytes());
        let opt = coff + 24;
        let magic: u16 = if pe64 { 0x20B } else { 0x10B };
        d[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        let (n_off, dirs) = if pe64 {
            (opt + 108, opt + 112)
        } else {
            (opt + 92, opt + 96)
        };
        d[n_off..n_off + 4].copy_from_slice(&16u32.to_le_bytes());
        if dotnet {
            d[dirs + 14 * 8..dirs + 14 * 8 + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        }
        d
    }

    #[test]
    fn pe_variants() {
        assert_eq!(
            fake_pe(false, false, false).as_slice().pipe(detect).label(),
            "PE32"
        );
        assert_eq!(
            fake_pe(true, false, false).as_slice().pipe(detect).label(),
            "PE64"
        );
        assert_eq!(
            fake_pe(true, true, false).as_slice().pipe(detect).label(),
            "PE64 DLL"
        );
        assert_eq!(
            fake_pe(false, false, true).as_slice().pipe(detect).label(),
            "PE32 .NET"
        );
        match detect(&fake_pe(true, false, false)) {
            FileKind::Pe { machine, .. } => assert_eq!(machine, PeMachine::Amd64),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn truncated_or_hostile_pe_is_malformed_not_panic() {
        assert_eq!(detect(b"MZ"), FileKind::PeMalformed);
        let mut d = vec![0u8; 64];
        d[0] = b'M';
        d[1] = b'Z';
        d[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes()); // Überlauf
        assert_eq!(detect(&d), FileKind::PeMalformed);
        let full = fake_pe(true, false, true);
        for cut in 0..full.len() {
            let _ = detect(&full[..cut]); // darf nie paniken
        }
    }

    #[test]
    fn containers_need_content_inspection() {
        assert_eq!(content_format(&FileKind::Zip), Some(ContentFormat::Zip));
        assert_eq!(content_format(&FileKind::Pdf), Some(ContentFormat::Pdf));
        assert_eq!(content_format(&FileKind::Text), None);
        assert_eq!(content_format(&detect(&fake_pe(true, false, false))), None);
        // Jeder Container im Sinne von is_container braucht Inhaltsprüfung.
        for k in [
            FileKind::Zip,
            FileKind::Ooxml,
            FileKind::OleCfb,
            FileKind::SevenZip,
            FileKind::Rar,
            FileKind::Gzip,
            FileKind::Cab,
            FileKind::Iso,
            FileKind::Vhdx,
        ] {
            assert!(k.is_container() && content_format(&k).is_some(), "{k:?}");
        }
    }

    #[test]
    fn renaming_does_not_change_type() {
        // T-023: detect() kennt keinen Dateinamen; der Typ hängt nur am Inhalt.
        let pe = fake_pe(true, false, false);
        assert!(matches!(detect(&pe), FileKind::Pe { .. }));
    }

    #[test]
    fn common_signatures() {
        assert_eq!(detect(b""), FileKind::Empty);
        assert_eq!(detect(b"%PDF-1.7\n"), FileKind::Pdf);
        assert_eq!(
            detect(b"PK\x03\x04....[Content_Types].xml"),
            FileKind::Ooxml
        );
        assert_eq!(detect(b"PK\x03\x04....word"), FileKind::Zip);
        assert_eq!(detect(&[0x1F, 0x8B, 8, 0]), FileKind::Gzip);
        assert_eq!(detect(b"#!/bin/sh\necho hi\n"), FileKind::Script);
        assert_eq!(detect(b"Hallo Welt"), FileKind::Text);
        assert_eq!(detect(&[0, 1, 2, 3, 0xFF]), FileKind::Unknown);
        let mut iso = vec![0u8; 0x9000];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(detect(&iso), FileKind::Iso);
        assert!(FileKind::Iso.is_container());
        assert!(!FileKind::Pdf.is_container());
    }

    trait Pipe: Sized {
        fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
            f(self)
        }
    }
    impl<T> Pipe for T {}
}
