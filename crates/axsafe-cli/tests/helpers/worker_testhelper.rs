//! Testdoppel des Scanworkers mit eingebautem Fehler. NUR für Tests.
//!
//!   axsafe-worker-testhelper <crash|hang|alloc|garbage|oversized|crash-on-payload|reject-rules|wrong-content|no-sandbox> [marker]

use axsafe_worker::{worker_main_with, Fault};

/// Messmodus (nur Windows-Tests): Wie verhält sich Pfadauflösung im
/// AppContainer? ClamAV 1.5 löst seinen Zertifikatsordner mit
/// `std::fs::canonicalize` auf; im AppContainer scheitert das mit
/// „Zugriff verweigert“. Dieser Modus misst, welcher Schritt scheitert.
#[cfg(windows)]
fn diag_paths(paths: impl Iterator<Item = String>) -> i32 {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFinalPathNameByHandleW(
            h: *mut core::ffi::c_void,
            buf: *mut u16,
            len: u32,
            flags: u32,
        ) -> u32;
    }
    for p in paths {
        let canon = std::fs::canonicalize(&p).map(|c| c.display().to_string());
        println!("canonicalize {p}: {canon:?}");
        match std::fs::OpenOptions::new()
            .access_mode(0)
            .custom_flags(0x0200_0000) // FILE_FLAG_BACKUP_SEMANTICS
            .open(&p)
        {
            Err(e) => println!("open {p}: Err({e})"),
            Ok(f) => {
                println!("open {p}: Ok");
                for (name, flags) in [("DOS", 0u32), ("GUID", 1), ("NT", 2), ("NONE", 4)] {
                    let mut buf = vec![0u16; 1024];
                    // SAFETY: gültiges Handle, Puffergröße passt.
                    let n = unsafe {
                        GetFinalPathNameByHandleW(
                            f.as_raw_handle(),
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                            flags,
                        )
                    };
                    if n == 0 || n as usize >= buf.len() {
                        println!(
                            "final_path {name}: Err({})",
                            std::io::Error::last_os_error()
                        );
                    } else {
                        println!(
                            "final_path {name}: Ok({})",
                            String::from_utf16_lossy(&buf[..n as usize])
                        );
                    }
                }
            }
        }
    }
    0
}

fn main() {
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("diag-pfad") {
        std::process::exit(diag_paths(std::env::args().skip(2)));
    }
    let mut a = std::env::args().skip(1);
    let fault = match a.next().as_deref() {
        Some("crash") => Fault::CrashOnScan,
        Some("hang") => Fault::HangOnScan,
        Some("alloc") => Fault::AllocOnScan,
        Some("reject-rules") => Fault::RejectRules,
        Some("wrong-content") => Fault::WrongContentVersion,
        Some("no-sandbox") => Fault::NoSandbox,
        Some("garbage") => Fault::GarbageOnScan,
        Some("oversized") => Fault::OversizedOnScan,
        Some("crash-on-payload") => Fault::CrashOnPayload,
        _ => Fault::None,
    };
    std::process::exit(worker_main_with(fault, a.next().map(Into::into)));
}
