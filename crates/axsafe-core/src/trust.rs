//! Herkunft (Mark of the Web) und Authenticode im Host (AXS-025).
//!
//! Beides läuft unter dem Zugriffswächter auf dem bereits geöffneten
//! Handle bzw. dem Datenstrom der Datei. Es wird nichts ausgeführt und
//! nichts aus dem Netz geladen: `WinVerifyTrust` läuft ohne
//! Oberfläche, ohne Sperrlistenabfrage und nur mit zwischengespeicherten
//! Adressen (`WTD_CACHE_ONLY_URL_RETRIEVAL`). Ohne Netz kann ein Widerruf
//! nicht erkannt werden – das steht im Ergebnis.

use crate::heuristics::{Authenticode, Origin};
use std::fs::File;
use std::path::Path;

/// Liest `Zone.Identifier` (höchstens 4 KiB). `None`: kein Datenstrom.
#[cfg(windows)]
pub fn read_origin(path: &Path) -> Option<Origin> {
    use std::io::Read;
    let mut p = path.as_os_str().to_owned();
    p.push(":Zone.Identifier");
    let f = crate::scan::open_no_follow(Path::new(&p)).ok()?;
    let mut buf = Vec::new();
    f.take(crate::heuristics::MAX_ZONE_BYTES as u64)
        .read_to_end(&mut buf)
        .ok()?;
    crate::heuristics::parse_zone_identifier(&String::from_utf8_lossy(&buf))
}

#[cfg(not(windows))]
pub fn read_origin(_path: &Path) -> Option<Origin> {
    None
}

/// Statuscode von `WinVerifyTrust` in eine ehrliche Aussage übersetzen.
pub fn map_status(code: i32) -> (&'static str, &'static str) {
    match code as u32 {
        0 => (
            "gueltig",
            "eingebettete Signatur gültig (ohne Online-Widerrufsprüfung)",
        ),
        0x800B_0100 => (
            "unsigniert",
            "keine eingebettete Signatur (Katalogsignatur nicht geprüft)",
        ),
        0x8009_6010 => ("manipuliert", "Signatur passt nicht zum Inhalt"),
        0x800B_0109 => (
            "nicht_vertrauenswuerdig",
            "Signatur endet bei einer nicht vertrauenswürdigen Stammzertifizierungsstelle",
        ),
        0x800B_0101 => ("abgelaufen", "Zertifikat abgelaufen und kein Zeitstempel"),
        0x800B_0111 | 0x800B_010C => (
            "widerrufen_oder_misstraut",
            "Zertifikat widerrufen oder ausdrücklich misstraut",
        ),
        0x800B_0003 | 0x800B_0001 => (
            "nicht_pruefbar",
            "Dateiformat für Authenticode nicht unterstützt",
        ),
        0x8009_2026 | 0x800B_010A => (
            "nicht_pruefbar",
            "Zertifikatskette offline nicht vollständig prüfbar",
        ),
        _ => ("fehler", "Signaturprüfung fehlgeschlagen"),
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn authenticode(file: &File, path: &Path) -> Authenticode {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Cryptography::{
        CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    };
    use windows_sys::Win32::Security::WinTrust::*;

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: file.as_raw_handle() as _,
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` und `info` leben bis nach STATEACTION_CLOSE; der Handle
    // gehört `file` und bleibt geöffnet.
    let code = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut _ as *mut core::ffi::c_void,
        )
    };
    let mut signer = None;
    if !data.hWVTStateData.is_null() {
        // SAFETY: Zeiger stammen aus WinTrust und gelten bis CLOSE; jede
        // Ebene wird auf null geprüft, die Namenslänge ist begrenzt.
        unsafe {
            let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
            if !prov.is_null() {
                let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
                if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                    let cert = (*(*sgnr).pasCertChain).pCert;
                    if !cert.is_null() {
                        let mut buf = [0u16; 256];
                        let n = CertGetNameStringW(
                            cert,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            std::ptr::null(),
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                        );
                        if n > 1 {
                            signer = Some(String::from_utf16_lossy(&buf[..n as usize - 1]));
                        }
                    }
                }
            }
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action,
                &mut data as *mut _ as *mut core::ffi::c_void,
            );
        }
    }
    let (status, detail) = map_status(code);
    Authenticode {
        status: status.into(),
        signer,
        detail: format!("{detail} (Code 0x{:08X})", code as u32),
    }
}

#[cfg(not(windows))]
pub fn authenticode(_file: &File, _path: &Path) -> Authenticode {
    Authenticode {
        status: "nicht_pruefbar".into(),
        signer: None,
        detail: "Authenticode wird nur unter Windows geprüft".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_is_honest() {
        assert_eq!(map_status(0).0, "gueltig");
        assert_eq!(map_status(0x800B_0100u32 as i32).0, "unsigniert");
        assert_eq!(map_status(0x8009_6010u32 as i32).0, "manipuliert");
        assert_eq!(map_status(0x1234_5678).0, "fehler");
        assert!(map_status(0).1.contains("ohne Online"));
    }

    /// Windows: ein signiertes Systemprogramm ist gültig, eine eigene
    /// unsignierte PE-Datei ist unsigniert, eine manipulierte Kopie wird
    /// erkannt.
    #[cfg(windows)]
    #[test]
    fn authenticode_on_real_files() {
        let dir = std::env::temp_dir().join(format!("axsafe-ac-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let own = dir.join("eigen.exe");
        std::fs::write(&own, crate::features::tests::tiny_pe(0x90, 0)).unwrap();
        let a = authenticode(&File::open(&own).unwrap(), &own);
        assert_eq!(a.status, "unsigniert", "{a:?}");

        // Eine Datei mit eingebetteter Signatur aus dem System suchen.
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
        let mut checked = false;
        for cand in [
            r"explorer.exe",
            r"regedit.exe",
            r"System32\WindowsPowerShell\v1.0\powershell.exe",
        ] {
            let p = Path::new(&windir).join(cand);
            let Ok(f) = File::open(&p) else { continue };
            let a = authenticode(&f, &p);
            if a.status != "gueltig" {
                continue; // nur katalogsigniert
            }
            assert!(
                a.signer.as_deref().unwrap_or("").contains("Microsoft"),
                "{a:?}"
            );
            // Manipulierte Kopie: ein Byte im Code ändern.
            let mut bytes = std::fs::read(&p).unwrap();
            let pos = bytes.len() / 3;
            bytes[pos] ^= 0xFF;
            let bad = dir.join("manipuliert.exe");
            std::fs::write(&bad, bytes).unwrap();
            let b = authenticode(&File::open(&bad).unwrap(), &bad);
            assert_eq!(b.status, "manipuliert", "{b:?}");
            checked = true;
            break;
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(checked, "keine eingebettet signierte Systemdatei gefunden");
    }

    #[cfg(windows)]
    #[test]
    fn origin_from_zone_identifier_stream() {
        let dir = std::env::temp_dir().join(format!("axsafe-motw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("geladen.txt");
        std::fs::write(&f, b"harmlos").unwrap();
        assert!(read_origin(&f).is_none());
        let mut ads = f.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        std::fs::write(
            Path::new(&ads),
            b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://x:y@dl.example.org/a?t=1\r\n",
        )
        .unwrap();
        let o = read_origin(&f).unwrap();
        assert_eq!(o.zone_id, Some(3));
        assert_eq!(o.host.as_deref(), Some("dl.example.org"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
