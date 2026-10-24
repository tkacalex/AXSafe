//! Landlock-Selbstbeschränkung (ohne Root, ohne Namespaces).

#![allow(unsafe_code)]

use crate::protocol::SandboxReport;

const CREATE_RULESET_VERSION: u32 = 1;

// Dateizugriffsrechte (ABI 1–5).
const FS_ABI1: u64 = (1 << 13) - 1; // EXECUTE … MAKE_SYM
const FS_REFER: u64 = 1 << 13; // ABI 2
const FS_TRUNCATE: u64 = 1 << 14; // ABI 3
const FS_IOCTL_DEV: u64 = 1 << 15; // ABI 5
const NET_BIND_TCP: u64 = 1 << 0; // ABI 4
const NET_CONNECT_TCP: u64 = 1 << 1; // ABI 4
const SCOPE_ABSTRACT_UNIX: u64 = 1 << 0; // ABI 6
const SCOPE_SIGNAL: u64 = 1 << 1; // ABI 6

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

fn report(fs: bool, net: bool, detail: String) -> SandboxReport {
    SandboxReport {
        kind: if fs { "landlock" } else { "none" }.into(),
        filesystem: fs,
        network: net,
        detail,
    }
}

pub fn apply() -> SandboxReport {
    // SAFETY: Systemaufrufe mit gültigen Argumenten; die Struktur lebt bis
    // nach dem Aufruf; der Deskriptor wird geschlossen.
    unsafe {
        // Stirbt der Host, stirbt der Worker.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);

        let abi = libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        );
        if abi < 1 {
            return report(
                false,
                false,
                format!(
                    "Landlock nicht verfügbar ({}); keine Rechtebeschränkung",
                    std::io::Error::last_os_error()
                ),
            );
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
            return report(
                false,
                false,
                format!(
                    "Landlock-Regelsatz nicht anlegbar: {}",
                    std::io::Error::last_os_error()
                ),
            );
        }
        let fd = fd as libc::c_int;
        // Ohne Regeln: alle behandelten Zugriffe sind überall verboten.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return report(false, false, format!("no_new_privs fehlgeschlagen: {e}"));
        }
        let rc = libc::syscall(libc::SYS_landlock_restrict_self, fd, 0u32);
        let err = std::io::Error::last_os_error();
        libc::close(fd);
        if rc != 0 {
            return report(false, false, format!("landlock_restrict_self: {err}"));
        }
        let mut detail =
            format!("Landlock ABI {abi}: kein Datei- und Ordnerzugriff, kein Programmstart");
        if net != 0 {
            detail.push_str(", keine TCP-Verbindungen");
        } else {
            detail.push_str("; TCP nicht beschränkt (ABI < 4)");
        }
        detail.push_str("; UDP wird von Landlock nicht erfasst");
        report(true, net != 0, detail)
    }
}
