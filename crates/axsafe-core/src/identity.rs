//! Dateiidentität (AXS-018, erster Schritt).
//!
//! Ein Pfad ist keine Identität: zwischen Prüfen und Handeln kann eine Datei
//! umbenannt, ersetzt oder über einen Link umgelenkt werden. AXSafe liest die
//! Identität deshalb **über das geöffnete Handle** (nicht über den Pfad) und
//! vergleicht sie vor und nach dem Lesen.
//!
//! * Windows: Volume-Seriennummer + 64-Bit-Dateiindex über
//!   `GetFileInformationByHandle` (dokumentierte Win32-API).
//! * Unix (Entwicklung/CI): `st_dev` + `st_ino`.
//!
//! * Windows zusätzlich: 128-Bit-Datei-ID (`FileIdInfo`, nötig für ReFS,
//!   wo der 64-Bit-Index nicht eindeutig sein muss) und die benannten
//!   Datenströme (Alternate Data Streams) über das Handle (`FileStreamInfo`).
//!
//! Offen: USN-basierte Änderungserkennung (P08).

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::time::UNIX_EPOCH;

/// Identität eines geöffneten Dateiobjekts zu einem Zeitpunkt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    /// Volume beziehungsweise Gerät (Windows: Volume-Seriennummer).
    pub volume: Option<u64>,
    /// Datei-ID auf dem Volume (Windows: Dateiindex, Unix: Inode).
    pub file_id: Option<u64>,
    /// Größe in Bytes zum Zeitpunkt der Abfrage.
    pub size: u64,
    /// Letzte Änderung in Nanosekunden seit 1970 (UTC), falls verfügbar.
    pub modified_unix_nanos: Option<i128>,
    /// Windows: 128-Bit-Datei-ID (hex) aus `FileIdInfo`; hat Vorrang vor
    /// `file_id`, wenn beide Seiten sie kennen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id_128: Option<String>,
}

impl FileIdentity {
    /// Liest die Identität über das bereits geöffnete Handle.
    pub fn from_file(file: &File) -> io::Result<Self> {
        let meta = file.metadata()?;
        let modified_unix_nanos = meta.modified().ok().and_then(|t| {
            t.duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_nanos() as i128)
        });
        let (volume, file_id) = platform_ids(file)?;
        Ok(FileIdentity {
            volume,
            file_id,
            size: meta.len(),
            modified_unix_nanos,
            file_id_128: file_id_128(file),
        })
    }

    /// `true`, wenn beide Werte dasselbe Dateiobjekt bezeichnen.
    ///
    /// Sind Volume oder Datei-ID unbekannt, wird **nicht** Gleichheit
    /// angenommen: Unsicherheit führt zu einer erneuten Prüfung.
    pub fn same_object(&self, other: &FileIdentity) -> bool {
        if let (Some(a), Some(b)) = (&self.file_id_128, &other.file_id_128) {
            return self.volume.is_some() && self.volume == other.volume && a == b;
        }
        match (self.volume, self.file_id, other.volume, other.file_id) {
            (Some(v1), Some(f1), Some(v2), Some(f2)) => v1 == v2 && f1 == f2,
            _ => false,
        }
    }

    /// `true`, wenn dasselbe Objekt unverändert ist (Größe und Änderungszeit).
    pub fn unchanged(&self, other: &FileIdentity) -> bool {
        self.same_object(other)
            && self.size == other.size
            && self.modified_unix_nanos.is_some()
            && self.modified_unix_nanos == other.modified_unix_nanos
    }
}

#[cfg(unix)]
fn platform_ids(file: &File) -> io::Result<(Option<u64>, Option<u64>)> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok((Some(meta.dev()), Some(meta.ino())))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_ids(file: &File) -> io::Result<(Option<u64>, Option<u64>)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    // SAFETY: `info` ist ein gültiger, beschreibbarer Puffer der richtigen
    // Größe; das Handle stammt aus einem geöffneten `File` und bleibt für die
    // Dauer des Aufrufs gültig. Die Funktion liest nur Metadaten.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    Ok((Some(info.dwVolumeSerialNumber as u64), Some(index)))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn file_id_128(file: &File) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
    };
    // SAFETY: Puffer der richtigen Größe, gültiges Handle.
    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as _,
            FileIdInfo,
            &mut info as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    (ok != 0).then(|| {
        info.FileId
            .Identifier
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    })
}

#[cfg(not(windows))]
fn file_id_128(_file: &File) -> Option<String> {
    None
}

/// Benannte Datenströme (Alternate Data Streams) einer Datei, ohne den
/// Hauptstrom, z. B. `Zone.Identifier`. Unter Unix gibt es keine.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn alternate_streams(file: &File) -> io::Result<Vec<String>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FileStreamInfo, GetFileInformationByHandleEx};
    let mut buf = vec![0u64; 8 * 1024]; // 64 KiB, 8-Byte-ausgerichtet
                                        // SAFETY: Puffer mit angegebener Größe; das Ergebnis wird nur innerhalb
                                        // des Puffers gelesen (Offsets werden geprüft).
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as _,
            FileStreamInfo,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            (buf.len() * 8) as u32,
        )
    };
    if ok == 0 {
        let e = io::Error::last_os_error();
        // ERROR_HANDLE_EOF (38): keine Ströme (z. B. Ordner).
        return if e.raw_os_error() == Some(38) {
            Ok(Vec::new())
        } else {
            Err(e)
        };
    }
    let bytes: &[u8] =
        // SAFETY: gleicher Puffer als Bytes.
        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * 8) };
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        // FILE_STREAM_INFO: NextEntryOffset u32, StreamNameLength u32,
        // StreamSize i64, StreamAllocationSize i64, StreamName [u16].
        if off + 24 > bytes.len() {
            break;
        }
        let rd =
            |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        let next = rd(off) as usize;
        let len = rd(off + 4) as usize;
        let start = off + 24;
        if start + len > bytes.len() || !len.is_multiple_of(2) {
            break;
        }
        let name: Vec<u16> = bytes[start..start + len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&name);
        // Format ":Name:$DATA"; der Hauptstrom heißt "::$DATA".
        if let Some(n) = name
            .strip_prefix(':')
            .and_then(|r| r.strip_suffix(":$DATA"))
        {
            if !n.is_empty() {
                out.push(n.to_string());
            }
        }
        if next == 0 {
            break;
        }
        off += next;
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn alternate_streams(_file: &File) -> io::Result<Vec<String>> {
    Ok(Vec::new())
}

#[cfg(not(any(unix, windows)))]
fn platform_ids(_file: &File) -> io::Result<(Option<u64>, Option<u64>)> {
    Ok((None, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn ident(path: &std::path::Path) -> FileIdentity {
        FileIdentity::from_file(&File::open(path).unwrap()).unwrap()
    }

    #[test]
    fn same_file_is_same_object() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.txt");
        std::fs::write(&p, b"hallo").unwrap();
        let a = ident(&p);
        let b = ident(&p);
        assert!(a.same_object(&b));
        assert!(a.unchanged(&b));
    }

    #[test]
    fn swapped_file_with_same_name_is_detected() {
        // T-018 (Teil): Austausch unter gleichem Namen wird nicht verwechselt.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.txt");
        let q = dir.path().join("b.txt");
        std::fs::write(&p, b"original").unwrap();
        std::fs::write(&q, b"anderer!").unwrap(); // gleiche Länge
        let before = ident(&p);
        std::fs::rename(&q, &p).unwrap();
        let after = ident(&p);
        assert!(!before.same_object(&after));
        assert!(!before.unchanged(&after));
    }

    #[test]
    fn appended_file_is_changed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.txt");
        std::fs::write(&p, b"abc").unwrap();
        let before = ident(&p);
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"def").unwrap();
        drop(f);
        let after = ident(&p);
        assert!(before.same_object(&after));
        assert!(!before.unchanged(&after));
    }

    #[test]
    fn unknown_ids_are_never_equal() {
        let a = FileIdentity {
            volume: None,
            file_id: None,
            size: 1,
            modified_unix_nanos: Some(1),
            file_id_128: None,
        };
        assert!(!a.same_object(&a.clone()));
    }
}
