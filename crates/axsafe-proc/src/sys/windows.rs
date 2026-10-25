//! Windows: angehalten starten, Job Object zuweisen, dann fortsetzen.
//!
//! Job-Grenzen: `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION`, optional
//! Speicher je Prozess und Höchstzahl aktiver Prozesse. Breakaway ist nicht
//! erlaubt, Nachkommen bleiben im Job.

#![allow(unsafe_code)]

use crate::{Limits, Sandbox};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::os::windows::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    FreeSid, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateMutexW, CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenThread, ReleaseMutex, ResumeThread,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, THREAD_SUSPEND_RESUME,
};

pub(crate) type Stdio3 = (
    Option<Box<dyn Write + Send>>,
    Option<Box<dyn Read + Send>>,
    Option<Box<dyn Read + Send>>,
);

enum Proc {
    Std(Child),
    /// Selbst per CreateProcessW gestartet (AppContainer).
    Raw {
        process: HANDLE,
        pid: u32,
        stdio: Option<(File, File, File)>,
    },
}

pub(crate) struct Contained {
    proc: Proc,
    job: HANDLE,
    status: Option<ExitStatus>,
}

// SAFETY: Job- und Prozess-Handle werden nur von diesem Besitzer verwendet.
unsafe impl Send for Contained {}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: gültiges, uns gehörendes Handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn last_err(what: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

fn create_job(limits: &Limits) -> io::Result<HANDLE> {
    // SAFETY: dokumentierte Win32-Funktionen mit lokal initialisierten Strukturen.
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(last_err("CreateJobObjectW"));
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        let mut flags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        if let Some(mem) = limits.max_memory_bytes {
            flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            info.ProcessMemoryLimit = usize::try_from(mem).unwrap_or(usize::MAX);
        }
        if let Some(n) = limits.max_processes {
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            info.BasicLimitInformation.ActiveProcessLimit = n.max(1);
        }
        info.BasicLimitInformation.LimitFlags = flags;
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) == 0
        {
            let e = last_err("SetInformationJobObject");
            CloseHandle(job);
            return Err(e);
        }
        Ok(job)
    }
}

impl Contained {
    pub(crate) fn spawn(cmd: &mut Command, limits: &Limits) -> io::Result<Self> {
        let job = create_job(limits)?;
        // SAFETY: gültiges Job-Handle; Kindprozess-Handle aus std.
        unsafe {
            // DETACHED_PROCESS statt CREATE_NO_WINDOW: ohne Konsole entsteht
            // kein conhost.exe, das sonst im Job mitgezählt würde und als
            // „verbliebener Nachkomme“ erschiene (auf dem Windows-Runner
            // beobachtet). Ein-/Ausgabe läuft ohnehin über Pipes.
            cmd.creation_flags(CREATE_SUSPENDED | DETACHED_PROCESS);
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    CloseHandle(job);
                    return Err(e);
                }
            };
            if AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) == 0 {
                let e = last_err("AssignProcessToJobObject");
                let _ = child.kill();
                let _ = child.wait();
                CloseHandle(job);
                return Err(e);
            }
            match resume_process_threads(child.id()) {
                Ok(n) if n > 0 => {}
                Ok(_) => {
                    TerminateJobObject(job, 1);
                    let _ = child.wait();
                    CloseHandle(job);
                    return Err(io::Error::other("kein Thread zum Fortsetzen gefunden"));
                }
                Err(e) => {
                    TerminateJobObject(job, 1);
                    let _ = child.wait();
                    CloseHandle(job);
                    return Err(e);
                }
            }
            Ok(Contained {
                proc: Proc::Std(child),
                job,
                status: None,
            })
        }
    }

    /// Startet mit Rechtebeschränkung. Unter Windows: AppContainer ohne
    /// Fähigkeiten (kein Netz, kein Zugriff auf Benutzerdateien), zusätzlich
    /// im Job Object. Umgebung wird geerbt; Arbeitsordner ist System32.
    pub(crate) fn spawn_sandboxed(
        cmd: &mut Command,
        limits: &Limits,
        sandbox: &Sandbox,
    ) -> io::Result<Self> {
        match sandbox {
            Sandbox::None => Self::spawn(cmd, limits),
            Sandbox::AppContainer { profile } => spawn_appcontainer(cmd, limits, profile),
            Sandbox::Restricted => {
                let token = restricted_low_token()?;
                spawn_isolated(cmd, limits, Isolation::Restricted(token))
            }
        }
    }

    pub(crate) fn take_stdio(&mut self) -> Stdio3 {
        match &mut self.proc {
            Proc::Std(c) => (
                c.stdin.take().map(|x| Box::new(x) as Box<dyn Write + Send>),
                c.stdout.take().map(|x| Box::new(x) as Box<dyn Read + Send>),
                c.stderr.take().map(|x| Box::new(x) as Box<dyn Read + Send>),
            ),
            Proc::Raw { stdio, .. } => match stdio.take() {
                Some((i, o, e)) => (Some(Box::new(i)), Some(Box::new(o)), Some(Box::new(e))),
                None => (None, None, None),
            },
        }
    }

    pub(crate) fn pid(&self) -> u32 {
        match &self.proc {
            Proc::Std(c) => c.id(),
            Proc::Raw { pid, .. } => *pid,
        }
    }

    pub(crate) fn has_exited(&mut self) -> io::Result<bool> {
        if self.status.is_some() {
            return Ok(true);
        }
        match &mut self.proc {
            Proc::Std(c) => self.status = c.try_wait()?,
            Proc::Raw { process, .. } => {
                // SAFETY: gültiges Prozess-Handle.
                unsafe {
                    if WaitForSingleObject(*process, 0) == WAIT_OBJECT_0 {
                        let mut code = 0u32;
                        if GetExitCodeProcess(*process, &mut code) == 0 {
                            return Err(last_err("GetExitCodeProcess"));
                        }
                        self.status = Some(ExitStatus::from_raw(code));
                    }
                }
            }
        }
        Ok(self.status.is_some())
    }

    /// Nach dem Ende des Hauptprozesses: noch aktive Prozesse im Job beenden.
    pub(crate) fn terminate_descendants(&mut self) -> bool {
        // Die Job-Buchhaltung kann dem Prozessende kurz nachlaufen: bis zu
        // 100 ms auf 0 aktive Prozesse warten, bevor Nachkommen angenommen werden.
        let mut active = self.active_processes();
        let until = std::time::Instant::now() + std::time::Duration::from_millis(100);
        while active > 0 && std::time::Instant::now() < until {
            std::thread::sleep(std::time::Duration::from_millis(5));
            active = self.active_processes();
        }
        if active > 0 {
            self.terminate_tree();
            true
        } else {
            false
        }
    }

    pub(crate) fn terminate_tree(&mut self) {
        // SAFETY: gültiges Job-Handle.
        unsafe {
            TerminateJobObject(self.job, 1);
        }
    }

    fn active_processes(&self) -> u32 {
        // SAFETY: Struktur wird lokal bereitgestellt, Größe stimmt.
        unsafe {
            let mut acc: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
            let ok = QueryInformationJobObject(
                self.job,
                JobObjectBasicAccountingInformation,
                &mut acc as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            if ok == 0 {
                // Unbekannt: vorsichtshalber als „Nachkommen vorhanden“ werten.
                return 1;
            }
            acc.ActiveProcesses
        }
    }

    pub(crate) fn reap(&mut self) -> Option<ExitStatus> {
        if self.status.is_none() {
            match &mut self.proc {
                Proc::Std(c) => self.status = c.wait().ok(),
                Proc::Raw { process, .. } => {
                    // SAFETY: gültiges Prozess-Handle; der Baum wurde vorher beendet.
                    unsafe {
                        WaitForSingleObject(*process, INFINITE);
                        let mut code = 0u32;
                        if GetExitCodeProcess(*process, &mut code) != 0 {
                            self.status = Some(ExitStatus::from_raw(code));
                        }
                    }
                }
            }
        }
        self.status
    }

    pub(crate) fn peak_memory(&self) -> Option<u64> {
        // SAFETY: Struktur wird lokal bereitgestellt, Größe stimmt.
        unsafe {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            let ok = QueryInformationJobObject(
                self.job,
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            (ok != 0).then_some(info.PeakJobMemoryUsed as u64)
        }
    }
}

impl Drop for Contained {
    fn drop(&mut self) {
        // SAFETY: gültiges Job-Handle; KILL_ON_JOB_CLOSE beendet Reste.
        unsafe {
            TerminateJobObject(self.job, 1);
            CloseHandle(self.job);
            if let Proc::Raw { process, .. } = &self.proc {
                CloseHandle(*process);
            }
        }
    }
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Quotet ein Argument nach den Regeln von CommandLineToArgvW.
fn quote_arg(arg: &OsStr, out: &mut Vec<u16>) {
    let a: Vec<u16> = arg.encode_wide().collect();
    let needs = a.is_empty()
        || a.iter()
            .any(|&c| c == b' ' as u16 || c == b'\t' as u16 || c == b'"' as u16);
    if !needs {
        out.extend_from_slice(&a);
        return;
    }
    out.push(b'"' as u16);
    let mut backslashes = 0usize;
    for &c in &a {
        if c == b'\\' as u16 {
            backslashes += 1;
        } else {
            if c == b'"' as u16 {
                out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            } else {
                out.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            }
            backslashes = 0;
            out.push(c);
        }
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    out.push(b'"' as u16);
}

struct Sid(PSID);
impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: von CreateAppContainerProfile/Derive... geliefert.
        unsafe {
            FreeSid(self.0);
        }
    }
}

/// HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
const HR_ALREADY_EXISTS: i32 = 0x800700B7_u32 as i32;

fn appcontainer_sid(profile: &str) -> io::Result<Sid> {
    let name = wide(OsStr::new(profile));
    let display = wide(OsStr::new("AXSafe Scanworker"));
    let desc = wide(OsStr::new("AXSafe: isolierter Scanworker ohne Fähigkeiten"));
    let mut sid: PSID = std::ptr::null_mut();
    // Mehrere AXSafe-Prozesse dürfen das Profil nicht gleichzeitig anlegen:
    // Auf dem Windows-Runner schlug CreateProcess sonst mit „Datei nicht
    // gefunden“ fehl, solange ein anderer Prozess das Profil noch anlegte.
    let mutex_name = wide(OsStr::new("Local\\AXSafe.AppContainerProfile.v1"));
    // SAFETY: benanntes Mutex; Handle wird unten freigegeben.
    let mutex = unsafe { CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr()) };
    if !mutex.is_null() {
        // SAFETY: gültiges Mutex-Handle; höchstens 30 s warten.
        unsafe {
            WaitForSingleObject(mutex, 30_000);
        }
    }
    struct Unlock(HANDLE);
    impl Drop for Unlock {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: eigenes Mutex-Handle.
                unsafe {
                    ReleaseMutex(self.0);
                    CloseHandle(self.0);
                }
            }
        }
    }
    let _unlock = Unlock(mutex);
    // SAFETY: gültige, nullterminierte Zeichenketten; sid wird von der API gesetzt.
    unsafe {
        let hr = CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            desc.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        );
        // Profil existiert schon oder wird gerade parallel angelegt: Die SID
        // ist aus dem Namen ableitbar, ein Profil ist dafür nicht nötig.
        if hr == HR_ALREADY_EXISTS || hr < 0 {
            let first = hr;
            sid = std::ptr::null_mut();
            let hr2 = DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid);
            if hr2 < 0 && first != HR_ALREADY_EXISTS {
                return Err(io::Error::other(format!(
                    "CreateAppContainerProfile: HRESULT 0x{:08X}, Derive...: 0x{:08X}",
                    first as u32, hr2 as u32
                )));
            }
            if hr2 < 0 {
                return Err(io::Error::other(format!(
                    "DeriveAppContainerSidFromAppContainerName: HRESULT 0x{:08X}",
                    hr2 as u32
                )));
            }
        }
    }
    Ok(Sid(sid))
}

/// Gibt dem AppContainer Lese-/Ausführrecht auf die Programmdatei (nötig,
/// wenn das Programm nicht unter Program Files liegt). Fehler werden
/// zurückgegeben; CreateProcess entscheidet danach endgültig.
fn grant_read_execute(path: &OsStr, sid: &Sid) -> io::Result<()> {
    grant_access(
        path,
        sid,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        NO_INHERITANCE,
    )
}

/// Fügt der DACL von `path` einen Erlaubt-Eintrag für die AppContainer-SID
/// hinzu (vorhandene Einträge bleiben).
fn grant_access(path: &OsStr, sid: &Sid, mask: u32, inherit: u32) -> io::Result<()> {
    grant_access_psid(path, sid.0, mask, inherit)
}

fn grant_access_psid(path: &OsStr, sid: PSID, mask: u32, inherit: u32) -> io::Result<()> {
    let p = wide(path);
    // SAFETY: dokumentierte Sicherheits-APIs; alle Zeiger lokal und gültig,
    // zurückgegebene Puffer werden mit LocalFree freigegeben.
    unsafe {
        let mut old: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let rc = GetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old,
            std::ptr::null_mut(),
            &mut sd,
        );
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inherit,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: sid as *mut u16,
            },
        };
        let mut new: *mut ACL = std::ptr::null_mut();
        let rc = SetEntriesInAclW(1, &ea, old, &mut new);
        if rc != 0 {
            LocalFree(sd as _);
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let rc = SetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new,
            std::ptr::null(),
        );
        LocalFree(new as _);
        LocalFree(sd as _);
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
    }
    Ok(())
}

/// Gibt dem AppContainer `profile` Lesezugriff (bzw. Ändern bei
/// `write`) auf einen Ordner samt Inhalt. Gelingt nur, wenn der Aufrufer
/// die Rechte des Ordners ändern darf (z. B. eigener Ordner).
pub fn appcontainer_grant(profile: &str, dir: &std::path::Path, write: bool) -> io::Result<()> {
    use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
    let sid = appcontainer_sid(profile)?;
    let mut mask = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    if write {
        mask |= FILE_GENERIC_WRITE | 0x0001_0000 /* DELETE */;
    }
    grant_access(
        dir.as_os_str(),
        &sid,
        mask,
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
    )
}

/// Eigener, für den AppContainer beschreibbarer Ordner (…\Packages\<Profil>\AC).
pub fn appcontainer_folder(profile: &str) -> io::Result<std::path::PathBuf> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::Isolation::GetAppContainerFolderPath;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    let sid = appcontainer_sid(profile)?;
    // SAFETY: SID gültig; zurückgegebene Zeichenketten werden freigegeben.
    unsafe {
        let mut ssid: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid.0, &mut ssid) == 0 {
            return Err(last_err("ConvertSidToStringSidW"));
        }
        let mut path: *mut u16 = std::ptr::null_mut();
        let hr = GetAppContainerFolderPath(ssid, &mut path);
        LocalFree(ssid as _);
        if hr < 0 || path.is_null() {
            return Err(io::Error::other(format!(
                "GetAppContainerFolderPath: HRESULT 0x{:08X}",
                hr as u32
            )));
        }
        let mut n = 0;
        while *path.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(path, n));
        CoTaskMemFree(path as _);
        Ok(std::path::PathBuf::from(s))
    }
}

/// Prüft vor dem Fortsetzen, dass der Prozess wirklich ein AppContainer-
/// Token ohne Fähigkeiten hat.
fn verify_appcontainer_token(process: HANDLE) -> io::Result<()> {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenCapabilities, TokenIsAppContainer, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    // SAFETY: gültiges Prozess-Handle; Puffer lokal.
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut tok) == 0 {
            return Err(last_err("OpenProcessToken"));
        }
        let _g = Handle(tok);
        let mut is_ac = 0u32;
        let mut len = 0u32;
        if GetTokenInformation(
            tok,
            TokenIsAppContainer,
            &mut is_ac as *mut u32 as _,
            4,
            &mut len,
        ) == 0
            || is_ac == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "gestarteter Prozess hat KEIN AppContainer-Token",
            ));
        }
        let mut buf = vec![0u8; 4096];
        if GetTokenInformation(
            tok,
            TokenCapabilities,
            buf.as_mut_ptr() as _,
            buf.len() as u32,
            &mut len,
        ) == 0
        {
            return Err(last_err("GetTokenInformation(TokenCapabilities)"));
        }
        let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if count != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("AppContainer-Token hat {count} Fähigkeit(en); erwartet keine"),
            ));
        }
        Ok(())
    }
}

/// Anonyme Pipe; `child_end_is_read` bestimmt, welches Ende vererbt wird.
fn pipe(child_end_is_read: bool) -> io::Result<(HANDLE, HANDLE)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: gültige Ausgabezeiger; Handles werden vom Aufrufer verwaltet.
    unsafe {
        if CreatePipe(&mut r, &mut w, &sa, 0) == 0 {
            return Err(last_err("CreatePipe"));
        }
        let (child, parent) = if child_end_is_read { (r, w) } else { (w, r) };
        // Elternende nicht vererben.
        if SetHandleInformation(parent, HANDLE_FLAG_INHERIT, 0) == 0 {
            let e = last_err("SetHandleInformation");
            CloseHandle(r);
            CloseHandle(w);
            return Err(e);
        }
        Ok((child, parent))
    }
}

/// Art der Rechtebeschränkung eines selbst gestarteten Prozesses.
enum Isolation {
    AppContainer(Sid),
    /// Eingeschränktes Primärtoken (wird nach dem Start geschlossen).
    Restricted(Handle),
}

fn spawn_appcontainer(cmd: &Command, limits: &Limits, profile: &str) -> io::Result<Contained> {
    let sid = appcontainer_sid(profile)?;
    spawn_isolated(cmd, limits, Isolation::AppContainer(sid))
}

/// Well-known SID als eigener Puffer.
fn well_known_sid(kind: i32) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::CreateWellKnownSid;
    let mut buf = vec![0u8; 68];
    let mut len = buf.len() as u32;
    // SAFETY: Puffer groß genug für jede SID (SECURITY_MAX_SID_SIZE = 68).
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as PSID,
            &mut len,
        )
    } == 0
    {
        return Err(last_err("CreateWellKnownSid"));
    }
    buf.truncate(len as usize);
    Ok(buf)
}

/// Eingeschränktes Primärtoken: keine Privilegien (außer SeChangeNotify),
/// Einschränkungs-SIDs RESTRICTED, Jeder, Benutzer, Anmelde-SID;
/// Integritätsstufe Niedrig.
fn restricted_low_token() -> io::Result<Handle> {
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, GetLengthSid, GetTokenInformation, SetTokenInformation, TokenGroups,
        TokenIntegrityLevel, WinBuiltinUsersSid, WinLowLabelSid, WinRestrictedCodeSid, WinWorldSid,
        DISABLE_MAX_PRIVILEGE, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
        TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // winnt.h; in windows-sys unter SystemServices (Feature nicht aktiviert).
    const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;
    const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
    // SAFETY: dokumentierte Token-APIs; alle Puffer leben bis nach den Aufrufen.
    unsafe {
        let mut own: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut own,
        ) == 0
        {
            return Err(last_err("OpenProcessToken"));
        }
        let own = Handle(own);
        let restricted = well_known_sid(WinRestrictedCodeSid)?;
        let world = well_known_sid(WinWorldSid)?;
        let users = well_known_sid(WinBuiltinUsersSid)?;
        let mut sids = vec![
            SID_AND_ATTRIBUTES {
                Sid: restricted.as_ptr() as PSID,
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: world.as_ptr() as PSID,
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: users.as_ptr() as PSID,
                Attributes: 0,
            },
        ];
        // Anmelde-SID (Fensterstation/Desktop), falls vorhanden.
        let mut len = 0u32;
        GetTokenInformation(own.0, TokenGroups, std::ptr::null_mut(), 0, &mut len);
        let mut gbuf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        if GetTokenInformation(own.0, TokenGroups, gbuf.as_mut_ptr() as _, len, &mut len) != 0 {
            let groups = &*(gbuf.as_ptr() as *const TOKEN_GROUPS);
            let list =
                std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);
            if let Some(g) = list
                .iter()
                .find(|g| g.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
            {
                sids.push(SID_AND_ATTRIBUTES {
                    Sid: g.Sid,
                    Attributes: 0,
                });
            }
        }
        // Dienstkontext (LocalService/NetworkService): Die Fensterstation des
        // Dienstes ist nur für das Dienstkonto freigegeben; ohne dessen SID in
        // der Einschränkungsliste scheitert der Prozessstart mit
        // STATUS_DLL_INIT_FAILED (in CI gemessen). Dateien eines Benutzers
        // bleiben trotzdem unerreichbar – sie sind nicht für das Dienstkonto
        // freigegeben. Für normale Benutzer wird die eigene SID NICHT
        // aufgenommen (sonst wären deren Dateien lesbar).
        let user_buf = token_user_sid(own.0)?;
        let user_sid = user_buf.as_ptr() as PSID;
        if is_service_account(user_sid) {
            sids.push(SID_AND_ATTRIBUTES {
                Sid: user_sid,
                Attributes: 0,
            });
        }
        let mut tok: HANDLE = std::ptr::null_mut();
        if CreateRestrictedToken(
            own.0,
            DISABLE_MAX_PRIVILEGE,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            sids.len() as u32,
            sids.as_ptr(),
            &mut tok,
        ) == 0
        {
            return Err(last_err("CreateRestrictedToken"));
        }
        let tok = Handle(tok);
        let low = well_known_sid(WinLowLabelSid)?;
        let tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: low.as_ptr() as PSID,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        if SetTokenInformation(
            tok.0,
            TokenIntegrityLevel,
            &tml as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32
                + GetLengthSid(low.as_ptr() as PSID),
        ) == 0
        {
            return Err(last_err("SetTokenInformation(TokenIntegrityLevel)"));
        }
        Ok(tok)
    }
}

/// Benutzer-SID eines Tokens als eigener Puffer (TOKEN_USER-Struktur).
fn token_user_sid(tok: HANDLE) -> io::Result<Vec<u64>> {
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser};
    let mut len = 0u32;
    // SAFETY: Größenabfrage, dann Abfrage in ausreichend großen Puffer.
    unsafe {
        GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        if GetTokenInformation(tok, TokenUser, buf.as_mut_ptr() as _, len, &mut len) == 0 {
            return Err(last_err("GetTokenInformation(TokenUser)"));
        }
        // TOKEN_USER beginnt mit SID_AND_ATTRIBUTES; den SID-Zeiger als
        // eigenen Puffer kopieren, damit er unabhängig weiterlebt.
        let sa = &*(buf.as_ptr() as *const windows_sys::Win32::Security::SID_AND_ATTRIBUTES);
        let n = windows_sys::Win32::Security::GetLengthSid(sa.Sid) as usize;
        let mut out = vec![0u64; n.div_ceil(8)];
        std::ptr::copy_nonoverlapping(sa.Sid as *const u8, out.as_mut_ptr() as *mut u8, n);
        Ok(out)
    }
}

/// LocalService (S-1-5-19) oder NetworkService (S-1-5-20); SYSTEM bewusst nicht.
fn is_service_account(sid: PSID) -> bool {
    use windows_sys::Win32::Security::{EqualSid, WinLocalServiceSid, WinNetworkServiceSid};
    [WinLocalServiceSid, WinNetworkServiceSid].iter().any(|k| {
        well_known_sid(*k)
            // SAFETY: beide SIDs gültig.
            .map(|w| unsafe { EqualSid(sid, w.as_ptr() as PSID) } != 0)
            .unwrap_or(false)
    })
}

/// Prüft vor dem Fortsetzen: eingeschränktes Token mit Integritätsstufe Niedrig.
fn verify_restricted_token(process: HANDLE) -> io::Result<()> {
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsTokenRestricted,
        TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    // SAFETY: gültiges Prozess-Handle; Puffer lokal.
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut tok) == 0 {
            return Err(last_err("OpenProcessToken"));
        }
        let _g = Handle(tok);
        if IsTokenRestricted(tok) == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "gestarteter Prozess hat KEIN eingeschränktes Token",
            ));
        }
        let mut buf = vec![0u64; 16];
        let mut len = 0u32;
        if GetTokenInformation(
            tok,
            TokenIntegrityLevel,
            buf.as_mut_ptr() as _,
            (buf.len() * 8) as u32,
            &mut len,
        ) == 0
        {
            return Err(last_err("GetTokenInformation(TokenIntegrityLevel)"));
        }
        let tml = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let n = *GetSidSubAuthorityCount(tml.Label.Sid);
        let rid = *GetSidSubAuthority(tml.Label.Sid, u32::from(n) - 1);
        if rid > 0x1000 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Integritätsstufe 0x{rid:X} statt Niedrig (0x1000)"),
            ));
        }
        Ok(())
    }
}

fn spawn_isolated(cmd: &Command, limits: &Limits, iso: Isolation) -> io::Result<Contained> {
    let program = cmd.get_program().to_os_string();
    let grant = match &iso {
        Isolation::AppContainer(sid) => grant_read_execute(&program, sid),
        Isolation::Restricted(_) => Ok(()),
    };

    let mut cmdline: Vec<u16> = Vec::new();
    quote_arg(&program, &mut cmdline);
    for a in cmd.get_args() {
        cmdline.push(b' ' as u16);
        quote_arg(a, &mut cmdline);
    }
    cmdline.push(0);
    let app = wide(&program);
    let sysdir = std::env::var_os("SystemRoot")
        .map(|r| {
            let mut p = std::path::PathBuf::from(r);
            p.push("System32");
            p.into_os_string()
        })
        .unwrap_or_else(|| "C:\\Windows\\System32".into());
    let cwd = wide(&sysdir);
    // Umgebung: NUR die am Command ausdrücklich gesetzten Variablen, nichts
    // vom Aufrufer erben (keine Zugangsdaten o. Ä. im Worker).
    let mut vars: Vec<(std::ffi::OsString, std::ffi::OsString)> = cmd
        .get_envs()
        .filter_map(|(k, v)| v.map(|v| (k.to_os_string(), v.to_os_string())))
        .collect();
    vars.sort_by_key(|(k, _)| k.to_string_lossy().to_uppercase());
    let mut env_block: Vec<u16> = Vec::new();
    for (k, v) in &vars {
        env_block.extend(k.encode_wide());
        env_block.push(b'=' as u16);
        env_block.extend(v.encode_wide());
        env_block.push(0);
    }
    if env_block.is_empty() {
        env_block.push(0);
    }
    env_block.push(0);

    let job = create_job(limits)?;
    let mut owned: Vec<HANDLE> = Vec::new();
    let cleanup = |owned: &mut Vec<HANDLE>| {
        for h in owned.drain(..) {
            // SAFETY: eigene, noch offene Handles.
            unsafe {
                CloseHandle(h);
            }
        }
    };
    let result = (|| -> io::Result<Contained> {
        let (in_child, in_parent) = pipe(true)?;
        owned.push(in_child);
        owned.push(in_parent);
        let (out_child, out_parent) = pipe(false)?;
        owned.push(out_child);
        owned.push(out_parent);
        let (err_child, err_parent) = pipe(false)?;
        owned.push(err_child);
        owned.push(err_parent);

        // SAFETY: dokumentierter Ablauf für STARTUPINFOEX mit Attributliste;
        // Puffer und Strukturen leben bis nach CreateProcessW.
        unsafe {
            let mut size = 0usize;
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size);
            let mut buf = vec![0u8; size];
            let list = buf.as_mut_ptr() as *mut core::ffi::c_void;
            if InitializeProcThreadAttributeList(list, 2, 0, &mut size) == 0 {
                return Err(last_err("InitializeProcThreadAttributeList"));
            }
            struct List(*mut core::ffi::c_void);
            impl Drop for List {
                fn drop(&mut self) {
                    // SAFETY: initialisierte Attributliste.
                    unsafe { DeleteProcThreadAttributeList(self.0) }
                }
            }
            let _list_guard = List(list);
            // UpdateProcThreadAttribute speichert nur den ZEIGER auf `caps`:
            // Die Struktur muss bis nach CreateProcess leben (deshalb hier
            // außerhalb des if – ein Block-lokaler Wert war im Release-Build
            // bereits überschrieben, als CreateProcessW ihn las).
            let caps = SECURITY_CAPABILITIES {
                AppContainerSid: match &iso {
                    Isolation::AppContainer(sid) => sid.0,
                    Isolation::Restricted(_) => std::ptr::null_mut(),
                },
                Capabilities: std::ptr::null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            };
            if let Isolation::AppContainer(_) = &iso {
                if UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    &caps as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<SECURITY_CAPABILITIES>(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                ) == 0
                {
                    return Err(last_err("UpdateProcThreadAttribute(SECURITY_CAPABILITIES)"));
                }
            }
            // Nur genau die drei Pipe-Enden vererben.
            let inherit = [in_child, out_child, err_child];
            if UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherit.as_ptr() as *const core::ffi::c_void,
                std::mem::size_of_val(&inherit),
                std::ptr::null_mut(),
                std::ptr::null(),
            ) == 0
            {
                return Err(last_err("UpdateProcThreadAttribute(HANDLE_LIST)"));
            }
            let mut si: STARTUPINFOEXW = std::mem::zeroed();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = in_child;
            si.StartupInfo.hStdOutput = out_child;
            si.StartupInfo.hStdError = err_child;
            si.lpAttributeList = list;
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let mut created = false;
            let mut last = io::Error::other("CreateProcessW nicht aufgerufen");
            // Kurzer Wiederholversuch, falls das AppContainer-Profil gerade
            // erst sichtbar wird (ERROR_FILE_NOT_FOUND/PATH_NOT_FOUND).
            let flags = EXTENDED_STARTUPINFO_PRESENT
                | CREATE_SUSPENDED
                | DETACHED_PROCESS
                | CREATE_UNICODE_ENVIRONMENT;
            for attempt in 0..5 {
                let ok = match &iso {
                    Isolation::AppContainer(_) => CreateProcessW(
                        app.as_ptr(),
                        cmdline.as_mut_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        1,
                        flags,
                        env_block.as_ptr() as *const core::ffi::c_void,
                        cwd.as_ptr(),
                        &si.StartupInfo,
                        &mut pi,
                    ),
                    // Eingeschränkte Version des eigenen Tokens: dafür ist
                    // kein SeAssignPrimaryTokenPrivilege nötig.
                    Isolation::Restricted(tok) => {
                        windows_sys::Win32::System::Threading::CreateProcessAsUserW(
                            tok.0,
                            app.as_ptr(),
                            cmdline.as_mut_ptr(),
                            std::ptr::null(),
                            std::ptr::null(),
                            1,
                            flags,
                            env_block.as_ptr() as *const core::ffi::c_void,
                            cwd.as_ptr(),
                            &si.StartupInfo,
                            &mut pi,
                        )
                    }
                };
                if ok != 0 {
                    created = true;
                    break;
                }
                last = last_err(match &iso {
                    Isolation::AppContainer(_) => "CreateProcessW (AppContainer)",
                    Isolation::Restricted(_) => "CreateProcessAsUserW (eingeschränktes Token)",
                });
                if !matches!(last.raw_os_error(), Some(2) | Some(3)) || attempt == 4 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            if !created {
                let e = last;
                return Err(match &grant {
                    Err(g) => io::Error::new(
                        e.kind(),
                        format!("{e}; Rechtevergabe an den AppContainer scheiterte vorher: {g}"),
                    ),
                    Ok(()) => e,
                });
            }
            if AssignProcessToJobObject(job, pi.hProcess) == 0 {
                let e = last_err("AssignProcessToJobObject");
                TerminateJobObject(job, 1);
                windows_sys::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return Err(e);
            }
            // Token VOR dem ersten Befehl des Prozesses prüfen.
            let verified = match &iso {
                Isolation::AppContainer(_) => verify_appcontainer_token(pi.hProcess),
                Isolation::Restricted(_) => verify_restricted_token(pi.hProcess),
            };
            if let Err(e) = verified {
                TerminateJobObject(job, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return Err(e);
            }
            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            // Kindenden schließen; Elternenden an File übergeben.
            CloseHandle(in_child);
            CloseHandle(out_child);
            CloseHandle(err_child);
            owned.clear();
            let stdio = (
                File::from_raw_handle(in_parent as _),
                File::from_raw_handle(out_parent as _),
                File::from_raw_handle(err_parent as _),
            );
            Ok(Contained {
                proc: Proc::Raw {
                    process: pi.hProcess,
                    pid: pi.dwProcessId,
                    stdio: Some(stdio),
                },
                job,
                status: None,
            })
        }
    })();
    if result.is_err() {
        cleanup(&mut owned);
        // SAFETY: eigenes Job-Handle.
        unsafe {
            CloseHandle(job);
        }
    }
    result
}

/// Setzt alle Threads des angehaltenen Prozesses fort (dokumentierte
/// Toolhelp-API; kein undokumentiertes NtResumeProcess).
fn resume_process_threads(pid: u32) -> io::Result<usize> {
    // SAFETY: dokumentierte Toolhelp-/Thread-APIs mit gültigen Strukturen.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Err(last_err("CreateToolhelp32Snapshot"));
        }
        let _guard = Handle(snap);
        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut resumed = 0usize;
        let mut ok = Thread32First(snap, &mut te);
        while ok != 0 {
            if te.th32OwnerProcessID == pid {
                let th = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
                if !th.is_null() {
                    let _g = Handle(th);
                    if ResumeThread(th) != u32::MAX {
                        resumed += 1;
                    }
                }
            }
            ok = Thread32Next(snap, &mut te);
        }
        Ok(resumed)
    }
}

/// Arbeitsordner für einen Prozess mit [`Sandbox::Restricted`]: Der Ordner
/// wird angelegt, bekommt Ändern-Rechte für die SID RESTRICTED (nur dieser
/// Ordner, vererbt an seinen Inhalt) und die Integritätsstufe Niedrig. Alle
/// anderen Orte bleiben für den eingeschränkten Prozess schreibgeschützt.
pub fn restricted_work_dir(dir: &std::path::Path) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW as SetSec;
    use windows_sys::Win32::Security::{
        AddMandatoryAce, InitializeAcl, WinLowLabelSid, WinRestrictedCodeSid, ACL_REVISION,
        CONTAINER_INHERIT_ACE, LABEL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    };
    use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_GENERIC_WRITE};
    const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x1;
    std::fs::create_dir_all(dir)?;
    let restricted = well_known_sid(WinRestrictedCodeSid)?;
    grant_access_psid(
        dir.as_os_str(),
        restricted.as_ptr() as PSID,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | FILE_GENERIC_WRITE | DELETE,
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
    )
    .map_err(|e| io::Error::new(e.kind(), format!("Rechte für RESTRICTED: {e}")))?;
    let low = well_known_sid(WinLowLabelSid)?;
    let mut acl = vec![0u64; 32];
    let p = wide(dir.as_os_str());
    // SAFETY: ACL-Puffer (256 Bytes) reicht für einen Label-Eintrag.
    unsafe {
        let acl_ptr = acl.as_mut_ptr() as *mut ACL;
        if InitializeAcl(acl_ptr, (acl.len() * 8) as u32, ACL_REVISION) == 0 {
            return Err(last_err("InitializeAcl"));
        }
        if AddMandatoryAce(
            acl_ptr,
            ACL_REVISION,
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            low.as_ptr() as PSID,
        ) == 0
        {
            return Err(last_err("AddMandatoryAce"));
        }
        let rc = SetSec(
            p.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            acl_ptr,
        );
        if rc != 0 {
            return Err(io::Error::new(
                io::Error::from_raw_os_error(rc as i32).kind(),
                format!(
                    "Integritätsstufe Niedrig setzen: {}",
                    io::Error::from_raw_os_error(rc as i32)
                ),
            ));
        }
    }
    Ok(())
}

/// Gibt Prozessen mit [`Sandbox::Restricted`] Lesezugriff auf einen Ordner
/// samt Inhalt (Eintrag für die SID RESTRICTED). Gelingt nur, wenn der
/// Aufrufer die Rechte des Ordners ändern darf.
pub fn restricted_grant_read(dir: &std::path::Path) -> io::Result<()> {
    use windows_sys::Win32::Security::{
        WinRestrictedCodeSid, CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE,
    };
    let restricted = well_known_sid(WinRestrictedCodeSid)?;
    grant_access_psid(
        dir.as_os_str(),
        restricted.as_ptr() as PSID,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
    )
}

/// Gibt Prozessen mit [`Sandbox::Restricted`] Lesen/Ausführen auf GENAU eine
/// Programmdatei (z. B. die Zugriffsprobe, wenn sie im Benutzerprofil liegt).
pub fn restricted_grant_execute(file: &std::path::Path) -> io::Result<()> {
    use windows_sys::Win32::Security::WinRestrictedCodeSid;
    let restricted = well_known_sid(WinRestrictedCodeSid)?;
    grant_access_psid(
        file.as_os_str(),
        restricted.as_ptr() as PSID,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        NO_INHERITANCE,
    )
}
