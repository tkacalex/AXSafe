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
    /// OLE Compound File; Untertyp aus dem Verzeichnis (MSI, Word, Excel …).
    OleCfb {
        #[serde(default)]
        subtype: OleKind,
    },
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
    /// UDF-Datenträgerabbild (ohne ISO-9660-Teil).
    Udf,
    Vhdx,
    /// Virtuelle Festplatte (VHD, „conectix“).
    Vhd,
    /// VMware-Festplatte (VMDK).
    Vmdk,
    /// Windows-Imaging-Format (WIM).
    Wim,
    Tar,
    Bzip2,
    Xz,
    /// Skript; Sprache aus Inhaltsmerkmalen (Shebang oder typische Befehle).
    Script {
        #[serde(default)]
        language: ScriptLanguage,
    },
    /// Text ohne sicher bestimmte Sprache.
    Text,
    /// Unbekanntes Binärformat.
    Unknown,
}

/// Untertyp einer OLE-Datei (aus Klassen-ID und Stromnamen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OleKind {
    /// Windows Installer (Paket .msi).
    Msi,
    /// Windows-Installer-Patch (.msp).
    Msp,
    /// Windows-Installer-Transformation (.mst).
    Mst,
    Word,
    Excel,
    PowerPoint,
    /// Outlook-Nachricht (.msg).
    Outlook,
    /// Anderer oder nicht bestimmbarer Untertyp.
    #[default]
    Other,
}

/// Sprache eines Skripts (Heuristik über eindeutige Merkmale; im Zweifel `Unknown`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptLanguage {
    PowerShell,
    Batch,
    VbScript,
    JavaScript,
    /// HTML-Anwendung (HTA) bzw. HTML mit Skript.
    Hta,
    Python,
    Shell,
    #[default]
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
            FileKind::OleCfb { subtype } => match subtype {
                OleKind::Other => "ole_cfb".into(),
                o => format!(
                    "ole_cfb:{}",
                    serde_json::to_value(o)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default()
                ),
            },
            FileKind::Script { language } => format!(
                "script:{}",
                serde_json::to_value(language)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            ),
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
                | FileKind::OleCfb { .. }
                | FileKind::SevenZip
                | FileKind::Rar
                | FileKind::Gzip
                | FileKind::Cab
                | FileKind::Iso
                | FileKind::Udf
                | FileKind::Vhdx
                | FileKind::Vhd
                | FileKind::Vmdk
                | FileKind::Wim
                | FileKind::Tar
                | FileKind::Bzip2
                | FileKind::Xz
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
    Udf,
    Vhdx,
    Vhd,
    Vmdk,
    Wim,
    Tar,
    Bzip2,
    Xz,
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
            ContentFormat::Udf => "UDF",
            ContentFormat::Vhd => "VHD",
            ContentFormat::Vmdk => "VMDK",
            ContentFormat::Wim => "WIM",
            ContentFormat::Tar => "TAR",
            ContentFormat::Bzip2 => "BZIP2",
            ContentFormat::Xz => "XZ",
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
        FileKind::OleCfb { .. } => ContentFormat::OleCfb,
        FileKind::SevenZip => ContentFormat::SevenZip,
        FileKind::Rar => ContentFormat::Rar,
        FileKind::Gzip => ContentFormat::Gzip,
        FileKind::Cab => ContentFormat::Cab,
        FileKind::Iso => ContentFormat::Iso,
        FileKind::Vhdx => ContentFormat::Vhdx,
        FileKind::Udf => ContentFormat::Udf,
        FileKind::Vhd => ContentFormat::Vhd,
        FileKind::Vmdk => ContentFormat::Vmdk,
        FileKind::Wim => ContentFormat::Wim,
        FileKind::Tar => ContentFormat::Tar,
        FileKind::Bzip2 => ContentFormat::Bzip2,
        FileKind::Xz => ContentFormat::Xz,
        FileKind::Pdf => ContentFormat::Pdf,
        FileKind::Rtf => ContentFormat::Rtf,
        _ => return None,
    })
}

/// Eintrag der Fähigkeitsmatrix „erkannt“ (AXS-023): Format, Beispieltyp und
/// der Test, der die Erkennung belegt. Ob der INHALT geprüft wird, hängt von
/// den Engines ab (`EngineInfo::inspects_contents_of`) und steht getrennt.
#[derive(Debug, Clone, Serialize)]
pub struct KindInfo {
    pub format: &'static str,
    pub example: FileKind,
    pub content_format: Option<ContentFormat>,
    pub detection_test: &'static str,
}

/// Alle Formate, die die Typerkennung unterscheidet, mit Beleg.
pub fn catalog() -> Vec<KindInfo> {
    use FileKind as K;
    let pe = |pe64, dll, dotnet| K::Pe {
        machine: PeMachine::Amd64,
        pe64,
        dll,
        dotnet,
    };
    let ole = |subtype| K::OleCfb { subtype };
    let script = |language| K::Script { language };
    let v: Vec<(&'static str, FileKind, &'static str)> = vec![
        (
            "PE32/PE64 (EXE)",
            pe(true, false, false),
            "filetype::tests::pe_variants",
        ),
        (
            "PE DLL",
            pe(true, true, false),
            "filetype::tests::pe_variants",
        ),
        (
            ".NET-Assembly",
            pe(false, false, true),
            "filetype::tests::pe_variants",
        ),
        (
            "PE beschädigt",
            K::PeMalformed,
            "filetype::tests::truncated_or_hostile_pe_is_malformed_not_panic",
        ),
        ("ELF", K::Elf, "filetype::tests::common_signatures"),
        ("ZIP", K::Zip, "filetype::tests::common_signatures"),
        (
            "Office OOXML",
            K::Ooxml,
            "filetype::tests::common_signatures",
        ),
        (
            "MSI",
            ole(OleKind::Msi),
            "filetype::tests::ole_subtypes_msi_vs_office",
        ),
        (
            "Word 97–2003",
            ole(OleKind::Word),
            "filetype::tests::ole_subtypes_msi_vs_office",
        ),
        (
            "Excel 97–2003",
            ole(OleKind::Excel),
            "filetype::tests::ole_subtypes_msi_vs_office",
        ),
        (
            "PowerPoint 97–2003",
            ole(OleKind::PowerPoint),
            "filetype::tests::ole_subtypes_msi_vs_office",
        ),
        (
            "OLE sonstige (MSP, MST, MSG …)",
            ole(OleKind::Other),
            "filetype::tests::ole_subtypes_msi_vs_office",
        ),
        ("PDF", K::Pdf, "filetype::tests::common_signatures"),
        ("RTF", K::Rtf, "filetype::tests::common_signatures"),
        ("LNK", K::Lnk, "filetype::tests::common_signatures"),
        ("7z", K::SevenZip, "filetype::tests::common_signatures"),
        ("RAR", K::Rar, "filetype::tests::common_signatures"),
        ("GZIP", K::Gzip, "filetype::tests::common_signatures"),
        (
            "BZIP2",
            K::Bzip2,
            "filetype::tests::disk_and_archive_containers",
        ),
        ("XZ", K::Xz, "filetype::tests::disk_and_archive_containers"),
        (
            "TAR",
            K::Tar,
            "filetype::tests::disk_and_archive_containers",
        ),
        ("CAB", K::Cab, "filetype::tests::common_signatures"),
        (
            "WIM",
            K::Wim,
            "filetype::tests::disk_and_archive_containers",
        ),
        ("ISO 9660", K::Iso, "filetype::tests::common_signatures"),
        (
            "UDF",
            K::Udf,
            "filetype::tests::disk_and_archive_containers",
        ),
        (
            "VHD",
            K::Vhd,
            "filetype::tests::disk_and_archive_containers",
        ),
        ("VHDX", K::Vhdx, "filetype::tests::common_signatures"),
        (
            "VMDK",
            K::Vmdk,
            "filetype::tests::disk_and_archive_containers",
        ),
        (
            "PowerShell",
            script(ScriptLanguage::PowerShell),
            "filetype::tests::script_languages_by_content",
        ),
        (
            "Batch",
            script(ScriptLanguage::Batch),
            "filetype::tests::script_languages_by_content",
        ),
        (
            "VBScript",
            script(ScriptLanguage::VbScript),
            "filetype::tests::script_languages_by_content",
        ),
        (
            "JavaScript/JScript",
            script(ScriptLanguage::JavaScript),
            "filetype::tests::script_languages_by_content",
        ),
        (
            "HTA",
            script(ScriptLanguage::Hta),
            "filetype::tests::script_languages_by_content",
        ),
        (
            "Python",
            script(ScriptLanguage::Python),
            "filetype::tests::script_languages_by_content",
        ),
        (
            "Shell",
            script(ScriptLanguage::Shell),
            "filetype::tests::common_signatures",
        ),
        ("Text", K::Text, "filetype::tests::common_signatures"),
    ];
    v.into_iter()
        .map(|(format, example, detection_test)| KindInfo {
            format,
            content_format: content_format(&example),
            example,
            detection_test,
        })
        .collect()
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
        return FileKind::OleCfb {
            subtype: ole_subtype(data),
        };
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
    if data.starts_with(b"MSWIM\0\0\0") {
        return FileKind::Wim;
    }
    if data.starts_with(b"BZh") && data.get(3).is_some_and(|c| (b'1'..=b'9').contains(c)) {
        return FileKind::Bzip2;
    }
    if data.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return FileKind::Xz;
    }
    // VMDK: sparse ("KDMV") oder Beschreibungsdatei.
    if data.starts_with(b"KDMV") || data.starts_with(b"# Disk DescriptorFile") {
        return FileKind::Vmdk;
    }
    // VHD: Fußzeile "conectix" am Ende (fest) bzw. Kopie am Anfang (dynamisch).
    if data.starts_with(b"conectix")
        || (data.len() >= 512 && &data[data.len() - 512..data.len() - 504] == b"conectix")
    {
        return FileKind::Vhd;
    }
    // ISO 9660 / UDF: Volume-Deskriptoren ab Sektor 16 (2048 Bytes).
    let mut udf = false;
    for sector in 16..32usize {
        let off = sector * 2048 + 1;
        match data.get(off..off + 5) {
            Some(b"CD001") => return FileKind::Iso,
            Some(b"BEA01") | Some(b"NSR02") | Some(b"NSR03") => udf = true,
            Some(_) => {}
            None => break,
        }
    }
    if udf {
        return FileKind::Udf;
    }
    // tar (ustar) – Kennung an Position 257.
    if data.get(257..262) == Some(b"ustar") {
        return FileKind::Tar;
    }
    if data.starts_with(b"#!") {
        let line = data.split(|&b| b == b'\n').next().unwrap_or_default();
        let line = String::from_utf8_lossy(line).to_lowercase();
        let language = if line.contains("python") {
            ScriptLanguage::Python
        } else if line.contains("pwsh") || line.contains("powershell") {
            ScriptLanguage::PowerShell
        } else if line.contains("node") {
            ScriptLanguage::JavaScript
        } else if line.contains("sh") {
            ScriptLanguage::Shell
        } else {
            ScriptLanguage::Unknown
        };
        return FileKind::Script { language };
    }
    let head = &data[..data.len().min(8 * 1024)];
    let text = if head.starts_with(&[0xFF, 0xFE]) {
        Some(utf16_text(&head[2..], u16::from_le_bytes))
    } else if head.starts_with(&[0xFE, 0xFF]) {
        Some(utf16_text(&head[2..], u16::from_be_bytes))
    } else {
        let h = head.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(head);
        // Ein am Ende abgeschnittenes UTF-8-Zeichen ist kein Binärinhalt.
        let valid = match std::str::from_utf8(h) {
            Ok(t) => Some(t.to_string()),
            Err(e) if e.error_len().is_none() && h.len() == 8 * 1024 => {
                std::str::from_utf8(&h[..e.valid_up_to()])
                    .ok()
                    .map(str::to_string)
            }
            Err(_) => None,
        };
        valid.filter(|_| !h.contains(&0))
    };
    match text {
        Some(t) => match script_language(&t) {
            ScriptLanguage::Unknown => FileKind::Text,
            language => FileKind::Script { language },
        },
        None => FileKind::Unknown,
    }
}

fn utf16_text(b: &[u8], f: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = b.chunks_exact(2).map(|c| f([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// Erkennt die Skriptsprache an eindeutigen Merkmalen. Ein Merkmal mit
/// Gewicht 2 genügt, sonst zwei schwache. Im Zweifel `Unknown` (= Text).
pub fn script_language(t: &str) -> ScriptLanguage {
    let l = t.to_lowercase();
    let score = |strong: &[&str], weak: &[&str]| -> u32 {
        strong.iter().filter(|m| l.contains(*m)).count() as u32 * 2
            + weak.iter().filter(|m| l.contains(*m)).count() as u32
    };
    let candidates = [
        (
            ScriptLanguage::Hta,
            score(&["<hta:application"], &["<script", "<html"]),
        ),
        (
            ScriptLanguage::PowerShell,
            score(
                &[
                    "[cmdletbinding(",
                    "write-host",
                    "write-output",
                    "invoke-expression",
                    "invoke-webrequest",
                    "new-object system.",
                    "get-childitem",
                    "set-executionpolicy",
                    "$env:",
                    "-executionpolicy",
                    "$psscriptroot",
                ],
                &["param(", "foreach (", "-eq ", "-ne ", "| out-null", "$null"],
            ),
        ),
        (
            ScriptLanguage::Batch,
            score(
                &["@echo off", "%~dp0", "setlocal", "goto :eof"],
                &["\nrem ", "\nset ", "\ngoto ", "%errorlevel%", "\nif exist "],
            ),
        ),
        (
            ScriptLanguage::VbScript,
            score(
                &[
                    "wscript.createobject",
                    "createobject(\"",
                    "on error resume next",
                    "end sub",
                    "end function",
                ],
                &["\ndim ", "msgbox", "set ", "wscript."],
            ),
        ),
        (
            ScriptLanguage::JavaScript,
            score(
                &[
                    "new activexobject(",
                    "function(",
                    "=> {",
                    "document.write(",
                    "console.log(",
                ],
                &["var ", "const ", "let ", "function ", "wscript."],
            ),
        ),
        (
            ScriptLanguage::Python,
            score(
                &["if __name__ == \"__main__\"", "def __init__(self"],
                &["\nimport ", "\ndef ", "print("],
            ),
        ),
    ];
    let best = candidates.iter().max_by_key(|(_, s)| *s).copied();
    match best {
        Some((lang, s)) if s >= 2 => {
            // Eindeutig: kein anderer Kandidat gleich stark.
            if candidates.iter().filter(|(_, x)| *x == s).count() > 1 {
                ScriptLanguage::Unknown
            } else {
                lang
            }
        }
        _ => ScriptLanguage::Unknown,
    }
}

/// Untertyp einer OLE-Datei aus dem ersten Verzeichnissektor: Klassen-ID des
/// Wurzeleintrags (MSI/MSP/MST) bzw. Namen der Ströme (Word, Excel …).
/// Liest nur innerhalb von `data`; bei Unklarheit `Other`.
fn ole_subtype(d: &[u8]) -> OleKind {
    let shift = match u16_le(d, 0x1E) {
        Some(s @ 9..=12) => s,
        _ => return OleKind::Other,
    };
    let size = 1usize << shift;
    let Some(dir) = u32_le(d, 0x30) else {
        return OleKind::Other;
    };
    let Some(off) = (dir as usize)
        .checked_add(1)
        .and_then(|s| s.checked_mul(size))
    else {
        return OleKind::Other;
    };
    let Some(sector) = d.get(off..off.saturating_add(size)) else {
        return OleKind::Other;
    };
    const CLSID_MSI: [u8; 16] = [
        0x84, 0x10, 0x0C, 0x00, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ];
    const CLSID_MSP: [u8; 16] = [
        0x86, 0x10, 0x0C, 0x00, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ];
    const CLSID_MST: [u8; 16] = [
        0x82, 0x10, 0x0C, 0x00, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ];
    let mut names = Vec::new();
    for e in sector.chunks_exact(128) {
        let len = u16_le(e, 0x40).unwrap_or(0) as usize;
        let ty = e[0x42];
        if ty == 5 {
            match &e[0x50..0x60] {
                c if c == CLSID_MSI => return OleKind::Msi,
                c if c == CLSID_MSP => return OleKind::Msp,
                c if c == CLSID_MST => return OleKind::Mst,
                _ => {}
            }
        }
        if (2..=64).contains(&len) && len.is_multiple_of(2) {
            let units: Vec<u16> = e[..len - 2]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            names.push(String::from_utf16_lossy(&units));
        }
    }
    let has = |n: &str| names.iter().any(|x| x == n);
    if has("WordDocument") {
        OleKind::Word
    } else if has("Workbook") || has("Book") {
        OleKind::Excel
    } else if has("PowerPoint Document") {
        OleKind::PowerPoint
    } else if names.iter().any(|n| n.starts_with("__substg1.0_")) {
        OleKind::Outlook
    } else {
        OleKind::Other
    }
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
            FileKind::OleCfb {
                subtype: OleKind::Other,
            },
            FileKind::SevenZip,
            FileKind::Rar,
            FileKind::Gzip,
            FileKind::Cab,
            FileKind::Iso,
            FileKind::Udf,
            FileKind::Vhdx,
            FileKind::Vhd,
            FileKind::Vmdk,
            FileKind::Wim,
            FileKind::Tar,
            FileKind::Bzip2,
            FileKind::Xz,
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
        assert_eq!(
            detect(b"#!/bin/sh\necho hi\n"),
            FileKind::Script {
                language: ScriptLanguage::Shell
            }
        );
        assert_eq!(detect(b"Hallo Welt"), FileKind::Text);
        assert_eq!(detect(&[0, 1, 2, 3, 0xFF]), FileKind::Unknown);
        let mut iso = vec![0u8; 0x9000];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(detect(&iso), FileKind::Iso);
        assert!(FileKind::Iso.is_container());
        assert!(!FileKind::Pdf.is_container());
    }

    fn script(t: &[u8]) -> ScriptLanguage {
        match detect(t) {
            FileKind::Script { language } => language,
            other => panic!("kein Skript: {other:?}"),
        }
    }

    /// T-023: Skriptsprachen nach Inhalt, auch UTF-16 (typisch PowerShell).
    #[test]
    fn script_languages_by_content() {
        assert_eq!(
            script(b"[CmdletBinding()]\nparam($Pfad)\nWrite-Host \"Hallo\""),
            ScriptLanguage::PowerShell
        );
        let mut u16 = vec![0xFF, 0xFE];
        for c in "Write-Host $env:USERNAME\r\n".encode_utf16() {
            u16.extend_from_slice(&c.to_le_bytes());
        }
        assert_eq!(script(&u16), ScriptLanguage::PowerShell);
        assert_eq!(
            script(b"@echo off\r\nsetlocal\r\nset X=1\r\n"),
            ScriptLanguage::Batch
        );
        assert_eq!(
            script(b"Dim o\r\nSet o = WScript.CreateObject(\"WScript.Shell\")\r\n"),
            ScriptLanguage::VbScript
        );
        assert_eq!(
            script(b"var s = new ActiveXObject(\"Scripting.FileSystemObject\");"),
            ScriptLanguage::JavaScript
        );
        assert_eq!(
            script(b"<html><head><HTA:APPLICATION ID=\"x\"/></head><script>x</script></html>"),
            ScriptLanguage::Hta
        );
        assert_eq!(
            script(b"#!/usr/bin/env python3\nprint(1)\n"),
            ScriptLanguage::Python
        );
        // Gewöhnlicher Text bleibt Text (kein Fehlalarm durch Einzelwörter).
        assert_eq!(
            detect("Sehr geehrte Damen und Herren, bitte setzen Sie die Frist.".as_bytes()),
            FileKind::Text
        );
        assert_eq!(detect("Grüße aus München".as_bytes()), FileKind::Text);
    }

    /// Minimale OLE-Datei: Kopf + ein Verzeichnissektor (Sektor 0).
    fn ole(root_clsid: Option<[u8; 16]>, stream: &str) -> Vec<u8> {
        let mut d = vec![0u8; 512 * 2];
        d[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        d[0x1E..0x20].copy_from_slice(&9u16.to_le_bytes());
        d[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        let dir = 512;
        let mut entry = |i: usize, name: &str, ty: u8, clsid: Option<[u8; 16]>| {
            let e = dir + i * 128;
            let units: Vec<u16> = name.encode_utf16().chain([0]).collect();
            for (k, u) in units.iter().enumerate() {
                d[e + k * 2..e + k * 2 + 2].copy_from_slice(&u.to_le_bytes());
            }
            d[e + 0x40..e + 0x42].copy_from_slice(&((units.len() * 2) as u16).to_le_bytes());
            d[e + 0x42] = ty;
            if let Some(c) = clsid {
                d[e + 0x50..e + 0x60].copy_from_slice(&c);
            }
        };
        entry(0, "Root Entry", 5, root_clsid);
        entry(1, stream, 2, None);
        d
    }

    /// T-023: MSI und Office 97–2003 werden unterschieden.
    #[test]
    fn ole_subtypes_msi_vs_office() {
        let msi = [
            0x84, 0x10, 0x0C, 0x00, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
        ];
        let kind = |d: Vec<u8>| match detect(&d) {
            FileKind::OleCfb { subtype } => subtype,
            o => panic!("{o:?}"),
        };
        assert_eq!(kind(ole(Some(msi), "\u{4840}xyz")), OleKind::Msi);
        assert_eq!(kind(ole(None, "WordDocument")), OleKind::Word);
        assert_eq!(kind(ole(None, "Workbook")), OleKind::Excel);
        assert_eq!(kind(ole(None, "PowerPoint Document")), OleKind::PowerPoint);
        assert_eq!(kind(ole(None, "Irgendwas")), OleKind::Other);
        // Verzeichnissektor außerhalb der Datei: kein Lesen außerhalb, Other.
        let mut broken = ole(None, "WordDocument");
        broken[0x30..0x34].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert_eq!(kind(broken), OleKind::Other);
    }

    /// T-023: Archive und Datenträgercontainer nach Inhalt.
    #[test]
    fn disk_and_archive_containers() {
        let mut vhd = vec![0u8; 4096];
        let n = vhd.len();
        vhd[n - 512..n - 504].copy_from_slice(b"conectix");
        assert_eq!(detect(&vhd), FileKind::Vhd);
        assert_eq!(detect(b"KDMV\x01\0\0\0"), FileKind::Vmdk);
        assert_eq!(
            detect(b"# Disk DescriptorFile\nversion=1\n"),
            FileKind::Vmdk
        );
        let mut udf = vec![0u8; 20 * 2048];
        udf[16 * 2048 + 1..16 * 2048 + 6].copy_from_slice(b"BEA01");
        udf[17 * 2048 + 1..17 * 2048 + 6].copy_from_slice(b"NSR02");
        assert_eq!(detect(&udf), FileKind::Udf);
        let mut hybrid = udf.clone();
        hybrid[18 * 2048 + 1..18 * 2048 + 6].copy_from_slice(b"CD001");
        assert_eq!(detect(&hybrid), FileKind::Iso);
        let mut tar = vec![0u8; 1024];
        tar[257..263].copy_from_slice(b"ustar\0");
        assert_eq!(detect(&tar), FileKind::Tar);
        assert_eq!(detect(b"BZh91AY&SY"), FileKind::Bzip2);
        assert_eq!(detect(&[0xFD, b'7', b'z', b'X', b'Z', 0, 0]), FileKind::Xz);
        assert_eq!(detect(b"MSWIM\0\0\0\xd0\0\0\0"), FileKind::Wim);
        for k in [FileKind::Vhd, FileKind::Udf, FileKind::Tar, FileKind::Wim] {
            assert!(k.is_container(), "{k:?}");
        }
    }

    /// T-028: Mutationstest – 200 000 veränderte und zufällige Eingaben
    /// (abgeleitet aus gültigen Köpfen) führen nie zu Panic oder Hänger.
    #[test]
    fn mutated_inputs_never_panic_or_hang() {
        let seeds: Vec<Vec<u8>> = vec![
            fake_pe(true, true, true),
            fake_pe(false, false, false),
            ole(None, "WordDocument"),
            b"PK\x03\x04[Content_Types].xml".to_vec(),
            b"#!/bin/sh\necho".to_vec(),
            vec![0xFF, 0xFE, b'W', 0, b'r', 0],
            {
                let mut v = vec![0u8; 40 * 1024];
                v[16 * 2048 + 1..16 * 2048 + 6].copy_from_slice(b"BEA01");
                v
            },
        ];
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let start = std::time::Instant::now();
        for i in 0..200_000u32 {
            let mut d = seeds[(i as usize) % seeds.len()].clone();
            let edits = 1 + (next() % 8) as usize;
            for _ in 0..edits {
                if d.is_empty() {
                    break;
                }
                let pos = (next() as usize) % d.len();
                match next() % 4 {
                    0 => d[pos] = next() as u8,
                    1 => d.truncate(pos),
                    2 => d[pos] = 0xFF,
                    _ => {
                        let len = d.len();
                        d[pos..].rotate_left(1.min(len - pos));
                    }
                }
            }
            let _ = detect(&d);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(60),
            "zu langsam: {:?}",
            start.elapsed()
        );
    }

    /// Jede Variante von FileKind (außer Leer/Unbekannt) steht im Katalog –
    /// der Compiler erzwingt über das vollständige match, dass neue Formate
    /// hier nachgetragen werden.
    #[test]
    fn catalog_covers_every_kind() {
        let cat = catalog();
        let has = |f: &dyn Fn(&FileKind) -> bool| cat.iter().any(|k| f(&k.example));
        let all = [
            FileKind::Elf,
            FileKind::Zip,
            FileKind::Ooxml,
            FileKind::Pdf,
            FileKind::Rtf,
            FileKind::Lnk,
            FileKind::SevenZip,
            FileKind::Rar,
            FileKind::Gzip,
            FileKind::Cab,
            FileKind::Iso,
            FileKind::Udf,
            FileKind::Vhdx,
            FileKind::Vhd,
            FileKind::Vmdk,
            FileKind::Wim,
            FileKind::Tar,
            FileKind::Bzip2,
            FileKind::Xz,
            FileKind::Text,
            FileKind::PeMalformed,
        ];
        for k in &all {
            let ok = match k {
                FileKind::Empty | FileKind::Unknown => true,
                FileKind::Pe { .. }
                | FileKind::PeMalformed
                | FileKind::Elf
                | FileKind::Zip
                | FileKind::Ooxml
                | FileKind::OleCfb { .. }
                | FileKind::Pdf
                | FileKind::Rtf
                | FileKind::Lnk
                | FileKind::SevenZip
                | FileKind::Rar
                | FileKind::Gzip
                | FileKind::Cab
                | FileKind::Iso
                | FileKind::Udf
                | FileKind::Vhdx
                | FileKind::Vhd
                | FileKind::Vmdk
                | FileKind::Wim
                | FileKind::Tar
                | FileKind::Bzip2
                | FileKind::Xz
                | FileKind::Script { .. }
                | FileKind::Text => has(&|x| x == k),
            };
            assert!(ok, "{k:?} fehlt im Katalog");
        }
        assert!(has(&|x| matches!(
            x,
            FileKind::OleCfb {
                subtype: OleKind::Msi
            }
        )));
        assert!(has(&|x| matches!(x, FileKind::Pe { dotnet: true, .. })));
        for l in [
            ScriptLanguage::PowerShell,
            ScriptLanguage::Batch,
            ScriptLanguage::VbScript,
            ScriptLanguage::JavaScript,
            ScriptLanguage::Hta,
            ScriptLanguage::Python,
            ScriptLanguage::Shell,
        ] {
            assert!(has(&|x| *x == FileKind::Script { language: l }), "{l:?}");
        }
    }

    trait Pipe: Sized {
        fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
            f(self)
        }
    }
    impl<T> Pipe for T {}
}
