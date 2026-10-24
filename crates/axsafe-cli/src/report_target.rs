//! Sicheres Berichtsziel (Befund 1).
//!
//! * Das Ziel wird **vor** dem Scan mit exklusiver Neuerstellung angelegt
//!   (`O_CREAT|O_EXCL` bzw. `CREATE_NEW`). Existiert unter dem Pfad bereits
//!   irgendetwas – Datei, Hardlink, symbolischer Link (auch ins Leere),
//!   Junction, Reparsepunkt oder Ordner –, schlägt das Anlegen fehl und
//!   nichts wird verändert. Es gibt keine vorgelagerte, rennanfällige
//!   Existenzprüfung und keinen Pfadstring-Vergleich.
//! * Die Identität (Volume + Datei-ID) der neu angelegten Datei wird über das
//!   Handle gelesen und vom Scan **ausgeschlossen**. Das greift auch, wenn
//!   dieselbe Datei während des Scans über einen anderen Namen (Hardlink,
//!   Junction, Symlink-Ordner) erreichbar wird.
//! * Geschrieben wird über das gehaltene Handle, nie erneut über den Pfad.

use axsafe_core::identity::FileIdentity;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct ReportTarget {
    file: File,
    path: PathBuf,
    identity: FileIdentity,
}

#[derive(Debug)]
pub enum ReserveError {
    /// Unter dem Pfad existiert bereits ein Objekt.
    Exists(PathBuf),
    /// Anderer Fehler beim Anlegen.
    Io(PathBuf, io::Error),
}

impl std::fmt::Display for ReserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReserveError::Exists(p) => write!(
                f,
                "Berichtsziel existiert bereits: {}\n\
                 AXSafe überschreibt keine vorhandenen Dateien (auch keine Links oder Ordner). \
                 Bitte einen neuen, noch nicht vorhandenen Dateinamen angeben.",
                p.display()
            ),
            ReserveError::Io(p, e) => write!(
                f,
                "Berichtsziel {} kann nicht angelegt werden: {e}",
                p.display()
            ),
        }
    }
}

impl ReportTarget {
    /// Legt das Berichtsziel exklusiv neu an.
    pub fn reserve(path: &Path) -> Result<Self, ReserveError> {
        let file = match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(ReserveError::Exists(path.to_path_buf()))
            }
            // Manche Systeme melden einen vorhandenen Ordner als IsADirectory.
            Err(e) if path.symlink_metadata().is_ok() => {
                let _ = e;
                return Err(ReserveError::Exists(path.to_path_buf()));
            }
            Err(e) => return Err(ReserveError::Io(path.to_path_buf(), e)),
        };
        let identity =
            FileIdentity::from_file(&file).map_err(|e| ReserveError::Io(path.to_path_buf(), e))?;
        Ok(ReportTarget {
            file,
            path: path.to_path_buf(),
            identity,
        })
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Schreibt den Bericht über das gehaltene Handle und sichert ihn auf Platte.
    pub fn write(mut self, content: &[u8]) -> io::Result<()> {
        let result = self
            .file
            .write_all(content)
            .and_then(|_| self.file.sync_all());
        if result.is_err() {
            // Keinen halben Bericht hinterlassen, der als gültig gelesen werden könnte.
            let _ = self.file.set_len(0);
        }
        result
    }
}
