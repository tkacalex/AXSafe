//! Windows: Named Pipe `axsafe.ipc/1`, Client-Identität aus dem Token,
//! Dateizugriff per Impersonation, Dienststeuerung (SCM).

#![allow(unsafe_code)]

use crate::handler::{serve, ConnAuth, ConnEnd, ServiceCtx};
use crate::identity::Identity;
use crate::ipc::{Conn, PIPE_NAME};
use crate::log::Log;
use axsafe_core::scan::{AccessGuard, FileAccess};
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, RevertToSelf, SecurityImpersonation,
    TokenImpersonationLevel, TokenSessionId, TokenStatistics, TokenUser, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
    TOKEN_STATISTICS, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentThread, OpenThreadToken, ResetEvent, SetThreadToken,
    WaitForSingleObject,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// Sicherheitsbeschreibung der Pipe:
/// * Netzwerkanmeldungen (NU) verweigert, zusätzlich `PIPE_REJECT_REMOTE_CLIENTS`,
/// * SYSTEM, Administratoren und das Dienstkonto (LocalService) Vollzugriff,
/// * interaktive Benutzer (IU) nur `FILE_READ_DATA | FILE_WRITE_DATA |
///   FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE`
///   (0x0012018B) – **kein** `FILE_APPEND_DATA` (= FILE_CREATE_PIPE_INSTANCE),
///   damit kein Benutzer eine eigene Serverinstanz unterschieben kann.
///   Clients öffnen deshalb mit genau dieser Zugriffsmaske.
pub const PIPE_SDDL: &str =
    "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;0x0012018b;;;IU)";

/// Zugriffsmaske der Clients (siehe [`PIPE_SDDL`]).
pub const CLIENT_ACCESS: u32 = 0x0012_018B;

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_err(what: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: eigenes Handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
// SAFETY: Handles werden nur vom Besitzer verwendet.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

/// Pipe-Verbindung mit überlappender E/A und Ablaufdaten.
pub struct PipeConn {
    h: OwnedHandle,
    ev: OwnedHandle,
    rd: Option<Instant>,
    wd: Option<Instant>,
}

impl PipeConn {
    fn io(
        &mut self,
        write: bool,
        buf: *mut u8,
        len: u32,
        deadline: Option<Instant>,
    ) -> io::Result<usize> {
        // SAFETY: OVERLAPPED und Puffer leben bis zum Abschluss der E/A; vor
        // jeder Rückkehr wird auf Abschluss bzw. Abbruch gewartet.
        unsafe {
            let mut ov: OVERLAPPED = std::mem::zeroed();
            ov.hEvent = self.ev.0;
            ResetEvent(self.ev.0);
            let mut n = 0u32;
            let ok = if write {
                WriteFile(self.h.0, buf, len, &mut n, &mut ov)
            } else {
                ReadFile(self.h.0, buf, len, &mut n, &mut ov)
            };
            if ok == 0 {
                let err = GetLastError();
                if err == ERROR_BROKEN_PIPE && !write {
                    return Ok(0);
                }
                if err != ERROR_IO_PENDING {
                    return Err(io::Error::from_raw_os_error(err as i32));
                }
                let ms = match deadline {
                    None => u32::MAX,
                    Some(d) => {
                        let now = Instant::now();
                        if now >= d {
                            0
                        } else {
                            (d - now).as_millis().min(u32::MAX as u128 - 1) as u32
                        }
                    }
                };
                let w = WaitForSingleObject(self.ev.0, ms);
                if w == WAIT_TIMEOUT {
                    CancelIoEx(self.h.0, &ov);
                    GetOverlappedResult(self.h.0, &ov, &mut n, 1);
                    return Err(io::ErrorKind::TimedOut.into());
                }
                if w != WAIT_OBJECT_0 {
                    CancelIoEx(self.h.0, &ov);
                    GetOverlappedResult(self.h.0, &ov, &mut n, 1);
                    return Err(last_err("WaitForSingleObject"));
                }
            }
            if GetOverlappedResult(self.h.0, &ov, &mut n, 1) == 0 {
                let err = GetLastError();
                if err == ERROR_BROKEN_PIPE && !write {
                    return Ok(0);
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            Ok(n as usize)
        }
    }
}

impl Read for PipeConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(u32::MAX as usize) as u32;
        let d = self.rd;
        self.io(false, buf.as_mut_ptr(), len, d)
    }
}

impl Write for PipeConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len().min(u32::MAX as usize) as u32;
        let d = self.wd;
        self.io(true, buf.as_ptr() as *mut u8, len, d)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Conn for PipeConn {
    fn set_read_deadline(&mut self, d: Option<Instant>) -> io::Result<()> {
        self.rd = d;
        Ok(())
    }
    fn set_write_deadline(&mut self, d: Option<Instant>) -> io::Result<()> {
        self.wd = d;
        Ok(())
    }
}

/// Dateizugriff mit dem Impersonation-Token des Auftraggebers.
pub struct ImpersonationAccess {
    token: OwnedHandle,
    display: String,
}

struct Revert;
impl AccessGuard for Revert {}
impl Drop for Revert {
    fn drop(&mut self) {
        // SAFETY: setzt den Thread auf das Prozess-Token zurück.
        let ok = unsafe { RevertToSelf() };
        if ok == 0 {
            // Ohne Rückkehr zur eigenen Identität darf nichts weiterlaufen.
            std::process::abort();
        }
    }
}

impl FileAccess for ImpersonationAccess {
    fn enter(&self) -> io::Result<Box<dyn AccessGuard>> {
        // SAFETY: gültiges Impersonation-Token; Rücknahme im Wächter.
        let ok = unsafe { SetThreadToken(std::ptr::null(), self.token.0) };
        if ok == 0 {
            return Err(last_err("SetThreadToken"));
        }
        Ok(Box::new(Revert))
    }
    fn describe(&self) -> String {
        format!("Rechte von {} (Impersonation)", self.display)
    }
}

fn token_info(tok: HANDLE, class: i32) -> io::Result<Vec<u8>> {
    // SAFETY: zweistufige Größenabfrage, Puffer lokal.
    unsafe {
        let mut len = 0u32;
        GetTokenInformation(tok, class, std::ptr::null_mut(), 0, &mut len);
        if len == 0 {
            return Err(last_err("GetTokenInformation"));
        }
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(tok, class, buf.as_mut_ptr() as *mut _, len, &mut len) == 0 {
            return Err(last_err("GetTokenInformation"));
        }
        Ok(buf)
    }
}

/// Identität des Clients aus dessen Token (Impersonation der Verbindung).
fn client_identity(pipe: HANDLE) -> io::Result<(Identity, ImpersonationAccess)> {
    // SAFETY: Impersonation nur in diesem Block; RevertToSelf wird immer
    // ausgeführt, scheitert es, endet der Prozess.
    let tok = unsafe {
        if ImpersonateNamedPipeClient(pipe) == 0 {
            return Err(last_err("ImpersonateNamedPipeClient"));
        }
        let mut tok: HANDLE = std::ptr::null_mut();
        let ok = OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            1,
            &mut tok,
        );
        let err = io::Error::last_os_error();
        if RevertToSelf() == 0 {
            std::process::abort();
        }
        if ok == 0 {
            return Err(io::Error::new(
                err.kind(),
                format!("OpenThreadToken: {err}"),
            ));
        }
        OwnedHandle(tok)
    };
    let lvl = token_info(tok.0, TokenImpersonationLevel)?;
    let lvl = i32::from_ne_bytes([lvl[0], lvl[1], lvl[2], lvl[3]]);
    if lvl < SecurityImpersonation {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Client erlaubt keine Impersonation – Dateizugriff mit seinen Rechten unmöglich",
        ));
    }
    let user = token_info(tok.0, TokenUser)?;
    // SAFETY: Puffer enthält TOKEN_USER mit Zeiger in denselben Puffer.
    let (sid_str, display) = unsafe {
        let tu = &*(user.as_ptr() as *const TOKEN_USER);
        let sid = tu.User.Sid;
        let mut p: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut p) == 0 {
            return Err(last_err("ConvertSidToStringSidW"));
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
        LocalFree(p as _);
        let mut name = [0u16; 256];
        let mut dom = [0u16; 256];
        let (mut nl, mut dl) = (256u32, 256u32);
        let mut use_: SID_NAME_USE = 0;
        let disp = if LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut nl,
            dom.as_mut_ptr(),
            &mut dl,
            &mut use_,
        ) != 0
        {
            format!(
                "{}\\{}",
                String::from_utf16_lossy(&dom[..dl as usize]),
                String::from_utf16_lossy(&name[..nl as usize])
            )
        } else {
            s.clone()
        };
        (s, disp)
    };
    let stats = token_info(tok.0, TokenStatistics)?;
    // SAFETY: Puffergröße von der API, Struktur POD.
    let logon_id = unsafe {
        let st = &*(stats.as_ptr() as *const TOKEN_STATISTICS);
        (st.AuthenticationId.LowPart as u64) | ((st.AuthenticationId.HighPart as u32 as u64) << 32)
    };
    let sess = token_info(tok.0, TokenSessionId)?;
    let session_id = u32::from_ne_bytes([sess[0], sess[1], sess[2], sess[3]]);
    let id = Identity {
        user_sid: sid_str,
        logon_id,
        session_id,
        display: display.clone(),
    };
    Ok((
        id,
        ImpersonationAccess {
            token: tok,
            display,
        },
    ))
}

fn create_instance(first: bool, sa: &SECURITY_ATTRIBUTES, max: u32) -> io::Result<OwnedHandle> {
    let name = wide(PIPE_NAME);
    let mut mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    // SAFETY: gültige Parameter; Sicherheitsattribute leben im Aufrufer.
    let h = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            max,
            64 * 1024,
            64 * 1024,
            0,
            sa,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(last_err("CreateNamedPipeW"));
    }
    Ok(OwnedHandle(h))
}

fn new_event() -> io::Result<OwnedHandle> {
    // SAFETY: anonymes, manuell zurückgesetztes Ereignis.
    let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if ev.is_null() {
        return Err(last_err("CreateEventW"));
    }
    Ok(OwnedHandle(ev))
}

/// Pipe-Server bis `stop` gesetzt ist.
pub fn run_server(
    ctx: Arc<ServiceCtx>,
    stop: Arc<AtomicBool>,
    max_instances: u32,
    log: Arc<Log>,
    on_listening: &dyn Fn(),
) -> io::Result<()> {
    let sddl = wide(PIPE_SDDL);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: SDDL ist nullterminiert; sd wird am Ende freigegeben.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(last_err("ConvertStringSecurityDescriptor"));
    }
    struct Sd(PSECURITY_DESCRIPTOR);
    impl Drop for Sd {
        fn drop(&mut self) {
            // SAFETY: von LocalAlloc stammend.
            unsafe {
                LocalFree(self.0 as _);
            }
        }
    }
    let _sd = Sd(sd);
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let active = Arc::new(AtomicUsize::new(0));
    let mut first = true;
    while !stop.load(Ordering::SeqCst) {
        let pipe = match create_instance(first, &sa, max_instances) {
            Ok(p) => p,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => {
                if first {
                    // Erste Instanz gehört nicht uns (Pipe-Hijacking) oder Fehler.
                    return Err(io::Error::new(
                        e.kind(),
                        format!("Pipe {PIPE_NAME} nicht exklusiv anlegbar: {e}"),
                    ));
                }
                log.line(&format!("Pipe-Instanz nicht anlegbar: {e}"));
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        if first {
            on_listening();
        }
        first = false;
        let ev = new_event()?;
        // SAFETY: OVERLAPPED lebt bis zum Abschluss (wir warten bzw. brechen ab).
        let connected = unsafe {
            let mut ov: OVERLAPPED = std::mem::zeroed();
            ov.hEvent = ev.0;
            if ConnectNamedPipe(pipe.0, &mut ov) == 0 {
                match GetLastError() {
                    ERROR_PIPE_CONNECTED => true,
                    ERROR_IO_PENDING => loop {
                        let w = WaitForSingleObject(ev.0, 500);
                        if w == WAIT_OBJECT_0 {
                            let mut n = 0;
                            break GetOverlappedResult(pipe.0, &ov, &mut n, 0) != 0;
                        }
                        if stop.load(Ordering::SeqCst) {
                            CancelIoEx(pipe.0, &ov);
                            let mut n = 0;
                            GetOverlappedResult(pipe.0, &ov, &mut n, 1);
                            break false;
                        }
                    },
                    _ => false,
                }
            } else {
                true
            }
        };
        if !connected {
            continue;
        }
        let ctx = Arc::clone(&ctx);
        let log = Arc::clone(&log);
        let active = Arc::clone(&active);
        active.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let end = handle_client(pipe, ev, &ctx, &log);
            active.fetch_sub(1, Ordering::SeqCst);
            if !matches!(end, ConnEnd::ClientClosed) {
                log.line(&format!("Verbindung beendet: {end:?}"));
            }
        });
    }
    Ok(())
}

/// PID des Pipe-Clients laut Windows plus dessen Startzeit (AXS-016).
fn client_process(pipe: HANDLE) -> Option<axsafe_core::report::ProcessIdentity> {
    let mut pid = 0u32;
    // SAFETY: gültiges Pipe-Handle, Ausgabe in lokale Variable.
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 || pid == 0 {
        return None;
    }
    axsafe_proc::process_start(pid)
        .ok()
        .map(|p| axsafe_core::report::ProcessIdentity::new(p.pid, p.start_unix_ns, p.image))
}

fn handle_client(pipe: OwnedHandle, ev: OwnedHandle, ctx: &ServiceCtx, log: &Log) -> ConnEnd {
    let ph = pipe.0;
    let mut conn = PipeConn {
        h: pipe,
        ev,
        rd: None,
        wd: None,
    };
    let end = match client_identity(ph) {
        Ok((identity, access)) => {
            let auth = ConnAuth {
                identity,
                access: Arc::new(access),
                client_process: client_process(ph),
            };
            let end = serve(&mut conn, &auth, ctx);
            if !matches!(end, ConnEnd::ClientClosed | ConnEnd::Idle) {
                log.line(&format!(
                    "Abgewiesen/beendet: {} (Sitzung {}): {end:?}",
                    auth.identity.display, auth.identity.session_id
                ));
            }
            end
        }
        Err(e) => {
            log.line(&format!(
                "Identität nicht feststellbar, Verbindung abgewiesen: {e}"
            ));
            ConnEnd::Forbidden(e.to_string())
        }
    };
    // SAFETY: gültiges Pipe-Handle; wird danach mit `conn` geschlossen.
    unsafe {
        DisconnectNamedPipe(ph);
    }
    end
}

/// Client-Seite (CLI, Tests): Verbindung zur Dienst-Pipe mit erlaubter
/// Impersonation.
pub fn connect_client(timeout: Duration) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
    const SECURITY_IMPERSONATION: u32 = 2 << 16;
    let t = Instant::now();
    loop {
        match std::fs::OpenOptions::new()
            .access_mode(CLIENT_ACCESS)
            .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION)
            .open(PIPE_NAME)
        {
            Ok(f) => return Ok(f),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && t.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Dienststeuerung
// ---------------------------------------------------------------------------

pub mod scm {
    use super::*;
    use std::sync::OnceLock;
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN,
        SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
        SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
        SERVICE_WIN32_OWN_PROCESS,
    };

    pub const SERVICE_NAME: &str = "AXSafeService";

    static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    static HANDLE_: OnceLock<usize> = OnceLock::new();
    /// Dienstkörper: läuft bis zum Stopp-Signal.
    pub type Body = Box<dyn Fn(Arc<AtomicBool>) -> io::Result<()> + Send + Sync>;
    static BODY: OnceLock<Body> = OnceLock::new();

    fn report(state: u32, exit: u32, wait_hint: u32) {
        let Some(h) = HANDLE_.get() else { return };
        let st = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: exit,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: wait_hint,
        };
        // SAFETY: gültiges Status-Handle aus RegisterServiceCtrlHandlerExW.
        unsafe {
            SetServiceStatus(*h as SERVICE_STATUS_HANDLE, &st);
        }
    }

    unsafe extern "system" fn handler(
        control: u32,
        _t: u32,
        _d: *mut core::ffi::c_void,
        _c: *mut core::ffi::c_void,
    ) -> u32 {
        if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
            report(SERVICE_STOP_PENDING, 0, 30_000);
            if let Some(s) = STOP.get() {
                s.store(true, Ordering::SeqCst);
            }
        }
        0
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
        let name = wide(SERVICE_NAME);
        // SAFETY: Handler ist eine statische Funktion.
        let h = unsafe {
            RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), std::ptr::null())
        };
        if h.is_null() {
            return;
        }
        let _ = HANDLE_.set(h as usize);
        report(SERVICE_START_PENDING, 0, 10_000);
        let stop = Arc::new(AtomicBool::new(false));
        let _ = STOP.set(Arc::clone(&stop));
        let result = match BODY.get() {
            Some(b) => b(stop),
            None => Err(io::Error::other("kein Dienstkörper")),
        };
        report(SERVICE_STOPPED, if result.is_ok() { 0 } else { 1 }, 0);
    }

    /// Meldet „läuft“ (vom Dienstkörper aufzurufen, sobald die Pipe steht).
    pub fn running() {
        report(SERVICE_RUNNING, 0, 0);
    }

    /// Übergibt an den Dienststeuerungs-Manager. Kehrt zurück, wenn der
    /// Dienst beendet ist.
    pub fn dispatch(body: Body) -> io::Result<()> {
        let _ = BODY.set(body);
        let mut name = wide(SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_mut_ptr(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];
        // SAFETY: Tabelle ist nullterminiert und lebt bis zur Rückkehr.
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            return Err(last_err(
                "StartServiceCtrlDispatcherW (nur als Dienst startbar)",
            ));
        }
        Ok(())
    }
}
