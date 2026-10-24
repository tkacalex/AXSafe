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
//! Offene Punkte (siehe `docs/BLOCKERS.md`): 128-Bit-IDs für ReFS
//! (`GetFileInformationByHandleEx(FileIdInfo)`), Alternate Data Streams,
//! USN-basierte Änderungserkennung, Tests auf Windows 10 LTSC (T-018).

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
        })
    }

    /// `true`, wenn beide Werte dasselbe Dateiobjekt bezeichnen.
    ///
    /// Sind Volume oder Datei-ID unbekannt, wird **nicht** Gleichheit
    /// angenommen: Unsicherheit führt zu einer erneuten Prüfung.
    pub fn same_object(&self, other: &FileIdentity) -> bool {
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
        };
        assert!(!a.same_object(&a.clone()));
    }
}
