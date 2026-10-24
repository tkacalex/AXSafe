//! Windows: angehalten starten, Job Object zuweisen, dann fortsetzen.
//!
//! Job-Grenzen: `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION`, optional
//! Speicher je Prozess und Höchstzahl aktiver Prozesse. Breakaway ist nicht
//! erlaubt, Nachkommen bleiben im Job.

#![allow(unsafe_code)]

use crate::Limits;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
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
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
};

pub(crate) struct Contained {
    pub(crate) child: Child,
    job: HANDLE,
    status: Option<ExitStatus>,
}

// SAFETY: Das Job-Handle wird nur von diesem Besitzer verwendet.
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

impl Contained {
    pub(crate) fn spawn(cmd: &mut Command, limits: &Limits) -> io::Result<Self> {
        // SAFETY: Alle Aufrufe sind dokumentierte Win32-Funktionen mit
        // gültigen Zeigern auf lokal initialisierte Strukturen.
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

            cmd.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
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
                child,
                job,
                status: None,
            })
        }
    }

    pub(crate) fn has_exited(&mut self) -> io::Result<bool> {
        if self.status.is_some() {
            return Ok(true);
        }
        self.status = self.child.try_wait()?;
        Ok(self.status.is_some())
    }

    /// Nach dem Ende des Hauptprozesses: noch aktive Prozesse im Job beenden.
    pub(crate) fn terminate_descendants(&mut self) -> bool {
        let active = self.active_processes();
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
            self.status = self.child.wait().ok();
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
        }
    }
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
