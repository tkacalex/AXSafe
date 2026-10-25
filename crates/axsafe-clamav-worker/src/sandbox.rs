//! Rechtebeschränkung des ClamAV-Workers.
//!
//! * **Windows:** Der Host startet den Worker mit eingeschränktem Token
//!   (`Sandbox::Restricted`: keine Privilegien, Integritätsstufe Niedrig,
//!   Einschränkungs-SIDs) im Job Object. Ein AppContainer ist für libclamav
//!   1.5 nicht möglich (Pfadauflösung des Zertifikatsordners wird dort
//!   verweigert, gemessen). Der Worker prüft sein Token beim Start und
//!   arbeitet ohne diese Beschränkung nicht (fail closed). Netzwerk sperrt
//!   das Token nicht; dafür setzen die Einrichtungsskripte eine ausgehende
//!   Firewall-Sperrregel für dieses Programm.
//! * **Linux (Entwicklung/CI):** Nach dem Laden der Datenbank beschränkt sich
//!   der Worker selbst mit Landlock: nur sein Arbeitsordner ist les- und
//!   schreibbar, kein anderer Dateizugriff, kein Programmstart, kein TCP
//!   (ab ABI 4). UDP erfasst Landlock nicht.

#![allow(unsafe_code)]

use crate::protocol::SandboxReport;

/// Vor dem Lesen jeder Eingabe: Windows prüft das Token; Linux setzt
/// PDEATHSIG (die eigentliche Beschränkung folgt nach dem Laden).
pub fn before_input() -> Option<SandboxReport> {
    #[cfg(windows)]
    {
        Some(windows::verify())
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: einfacher Systemaufruf.
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        }
        None
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

/// Nach dem Laden der Datenbank (Linux: Landlock mit nur `tempdir`).
pub fn after_load(tempdir: &str, before: Option<SandboxReport>) -> SandboxReport {
    if let Some(r) = before {
        return r;
    }
    #[cfg(target_os = "linux")]
    {
        linux::apply(tempdir)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = tempdir;
        SandboxReport {
            kind: "none".into(),
            filesystem: false,
            network: false,
            detail: "keine Rechtebeschränkung auf dieser Plattform".into(),
        }
    }
}

/// Unter Windows ist ein nicht abgeschotteter Worker unzulässig.
pub fn required() -> bool {
    cfg!(windows)
}

#[cfg(windows)]
mod windows {
    use crate::protocol::SandboxReport;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsTokenRestricted,
        TokenIntegrityLevel, TOKEN_MANDATORY_LABEL,
    };

    pub fn verify() -> SandboxReport {
        // SAFETY: dokumentierte Token-APIs mit lokalen Puffern.
        unsafe {
            // Pseudo-Handle GetCurrentProcessToken() (-4): erlaubt TOKEN_QUERY
            // ohne Zugriffsprüfung. OpenProcessToken liefert unter dem
            // eingeschränkten Token „Zugriff verweigert“ (gemessen in CI,
            // Lauf 40206964605).
            let tok: HANDLE = -4isize as HANDLE;
            let restricted = IsTokenRestricted(tok) != 0;
            let mut buf = vec![0u64; 16];
            let mut len = 0u32;
            let ok = GetTokenInformation(
                tok,
                TokenIntegrityLevel,
                buf.as_mut_ptr() as _,
                (buf.len() * 8) as u32,
                &mut len,
            );
            if ok == 0 {
                return none("Integritätsstufe nicht lesbar".into());
            }
            let tml = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let n = *GetSidSubAuthorityCount(tml.Label.Sid);
            let rid = *GetSidSubAuthority(tml.Label.Sid, u32::from(n) - 1);
            if !restricted || rid > 0x1000 {
                return none(format!(
                    "Worker läuft NICHT mit eingeschränktem Token niedriger Integrität \
                     (eingeschränkt: {restricted}, Integrität 0x{rid:X})"
                ));
            }
            SandboxReport {
                kind: "restricted_token".into(),
                filesystem: true,
                network: false,
                detail: "eingeschränktes Token (geprüft im Worker): keine Privilegien, \
                         Integritätsstufe Niedrig, nur Arbeitsordner beschreibbar; Job Object \
                         (1 Prozess, Speicher- und Zeitgrenze). Netzwerk: ausgehende \
                         Firewall-Sperrregel der Einrichtung, nicht durch das Token"
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
}

#[cfg(target_os = "linux")]
mod linux {
    use crate::protocol::SandboxReport;

    const FS_EXECUTE: u64 = 1 << 0;
    const FS_WRITE_FILE: u64 = 1 << 1;
    const FS_READ_FILE: u64 = 1 << 2;
    const FS_READ_DIR: u64 = 1 << 3;
    const FS_REMOVE_DIR: u64 = 1 << 4;
    const FS_REMOVE_FILE: u64 = 1 << 5;
    const FS_MAKE_DIR: u64 = 1 << 7;
    const FS_MAKE_REG: u64 = 1 << 8;
    const FS_ABI1: u64 = (1 << 13) - 1;
    const FS_REFER: u64 = 1 << 13;
    const FS_TRUNCATE: u64 = 1 << 14;
    const FS_IOCTL_DEV: u64 = 1 << 15;
    const NET_BIND_TCP: u64 = 1 << 0;
    const NET_CONNECT_TCP: u64 = 1 << 1;
    const SCOPE_ABSTRACT_UNIX: u64 = 1 << 0;
    const SCOPE_SIGNAL: u64 = 1 << 1;
    const RULE_PATH_BENEATH: u32 = 1;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }

    #[repr(C, packed)]
    struct PathBeneath {
        allowed_access: u64,
        parent_fd: i32,
    }

    fn report(fs: bool, net: bool, detail: String) -> SandboxReport {
        SandboxReport {
            kind: if fs { "landlock" } else { "none" }.into(),
            filesystem: fs,
            network: net,
            detail,
        }
    }

    pub fn apply(tempdir: &str) -> SandboxReport {
        // SAFETY: Systemaufrufe mit gültigen Argumenten; Strukturen leben bis
        // nach dem Aufruf; Deskriptoren werden geschlossen.
        unsafe {
            let abi = libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                1u32,
            );
            if abi < 1 {
                return report(false, false, "Landlock nicht verfügbar".into());
            }
            let abi = abi as u32;
            let mut fs = FS_ABI1;
            if abi >= 2 {
                fs |= FS_REFER;
            }
            if abi >= 3 {
                fs |= FS_TRUNCATE;
            }
            if abi >= 5 {
                fs |= FS_IOCTL_DEV;
            }
            let net = if abi >= 4 {
                NET_BIND_TCP | NET_CONNECT_TCP
            } else {
                0
            };
            let scoped = if abi >= 6 {
                SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL
            } else {
                0
            };
            let attr = RulesetAttr {
                handled_access_fs: fs,
                handled_access_net: net,
                scoped,
            };
            let size = if abi >= 6 {
                24
            } else if abi >= 4 {
                16
            } else {
                8
            };
            let fd = libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                size as usize,
                0u32,
            );
            if fd < 0 {
                return report(false, false, "Landlock-Regelsatz nicht anlegbar".into());
            }
            let fd = fd as libc::c_int;
            // Einziger erlaubter Ort: der Arbeitsordner (lesen, schreiben,
            // anlegen, löschen; kein Ausführen).
            let c = match std::ffi::CString::new(tempdir) {
                Ok(c) => c,
                Err(_) => {
                    libc::close(fd);
                    return report(false, false, "Arbeitsordner ungültig".into());
                }
            };
            let dfd = libc::open(
                c.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
            );
            if dfd < 0 {
                libc::close(fd);
                return report(
                    false,
                    false,
                    format!(
                        "Arbeitsordner nicht öffnbar: {}",
                        std::io::Error::last_os_error()
                    ),
                );
            }
            let mut allowed = FS_WRITE_FILE
                | FS_READ_FILE
                | FS_READ_DIR
                | FS_REMOVE_DIR
                | FS_REMOVE_FILE
                | FS_MAKE_DIR
                | FS_MAKE_REG;
            if abi >= 3 {
                allowed |= FS_TRUNCATE;
            }
            let _ = FS_EXECUTE;
            let rule = PathBeneath {
                allowed_access: allowed,
                parent_fd: dfd,
            };
            let rc = libc::syscall(
                libc::SYS_landlock_add_rule,
                fd,
                RULE_PATH_BENEATH,
                &rule as *const PathBeneath,
                0u32,
            );
            libc::close(dfd);
            if rc != 0 {
                let e = std::io::Error::last_os_error();
                libc::close(fd);
                return report(false, false, format!("landlock_add_rule: {e}"));
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                libc::close(fd);
                return report(false, false, "no_new_privs fehlgeschlagen".into());
            }
            let rc = libc::syscall(libc::SYS_landlock_restrict_self, fd, 0u32);
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            if rc != 0 {
                return report(false, false, format!("landlock_restrict_self: {err}"));
            }
            let mut detail = format!(
                "Landlock ABI {abi} nach dem Laden der Datenbank: nur der Arbeitsordner ist \
                 les- und schreibbar, kein anderer Dateizugriff, kein Programmstart"
            );
            if net != 0 {
                detail.push_str(", keine TCP-Verbindungen");
            }
            detail.push_str("; UDP wird von Landlock nicht erfasst");
            report(true, net != 0, detail)
        }
    }
}
