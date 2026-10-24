//! Prüft, dass der Worker in einem AppContainer ohne Fähigkeiten läuft.

#![allow(unsafe_code)]

use crate::protocol::SandboxReport;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenCapabilities, TokenIsAppContainer, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub fn verify() -> SandboxReport {
    // SAFETY: dokumentierte Token-APIs mit lokal bereitgestellten Puffern.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return none(format!(
                "Token nicht lesbar: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut is_ac: u32 = 0;
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenIsAppContainer,
            &mut is_ac as *mut u32 as *mut core::ffi::c_void,
            4,
            &mut len,
        );
        if ok == 0 || is_ac == 0 {
            CloseHandle(token);
            return none("Worker läuft NICHT in einem AppContainer".into());
        }
        // TOKEN_GROUPS: erstes Feld ist die Anzahl (u32).
        let mut buf = vec![0u8; 4096];
        let ok = GetTokenInformation(
            token,
            TokenCapabilities,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            buf.len() as u32,
            &mut len,
        );
        CloseHandle(token);
        if ok == 0 {
            return none(format!(
                "Fähigkeiten nicht lesbar: {}",
                std::io::Error::last_os_error()
            ));
        }
        let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if count != 0 {
            return none(format!(
                "AppContainer hat {count} Fähigkeit(en); erwartet: keine"
            ));
        }
        SandboxReport {
            kind: "appcontainer".into(),
            filesystem: true,
            network: true,
            detail: "AppContainer ohne Fähigkeiten: kein Netzwerk, kein Zugriff auf \
                     Benutzerdateien; dazu Job Object (1 Prozess, Speicher- und Zeitgrenze)"
                .into(),
        }
    }
}

fn none(detail: String) -> SandboxReport {
    SandboxReport {
        kind: "none".into(),
        filesystem: false,
        network: false,
        detail,
    }
}
