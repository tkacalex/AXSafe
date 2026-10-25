//! Unix: eigene Prozessgruppe, `killpg`, `RLIMIT_AS`.
//!
//! Der Hauptprozess wird erst nach dem Beenden der Gruppe eingesammelt
//! (`waitid` mit `WNOWAIT`), damit seine Prozessgruppen-ID nicht
//! wiederverwendet werden kann, solange wir die Gruppe noch ansprechen.

#![allow(unsafe_code)]

use crate::{Limits, Sandbox};
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};

pub(crate) type Stdio3 = (
    Option<Box<dyn Write + Send>>,
    Option<Box<dyn Read + Send>>,
    Option<Box<dyn Read + Send>>,
);

pub(crate) struct Contained {
    child: Child,
    pgid: libc::pid_t,
    status: Option<ExitStatus>,
}

impl Contained {
    pub(crate) fn spawn(cmd: &mut Command, limits: &Limits) -> io::Result<Self> {
        cmd.process_group(0);
        if let Some(bytes) = limits.max_memory_bytes {
            let lim = libc::rlimit {
                rlim_cur: bytes as libc::rlim_t,
                rlim_max: bytes as libc::rlim_t,
            };
            // SAFETY: Läuft im Kind zwischen fork und exec. setrlimit ist
            // async-signal-sicher; es wird kein Speicher allokiert.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setrlimit(libc::RLIMIT_AS, &lim) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = cmd.spawn()?;
        let pgid = child.id() as libc::pid_t;
        Ok(Contained {
            child,
            pgid,
            status: None,
        })
    }

    /// Unix kennt keinen AppContainer; die Rechtebeschränkung übernimmt der
    /// Worker selbst (Landlock). `Sandbox::AppContainer` ist hier ein Fehler.
    pub(crate) fn spawn_sandboxed(
        cmd: &mut Command,
        limits: &Limits,
        sandbox: &Sandbox,
    ) -> io::Result<Self> {
        match sandbox {
            Sandbox::None => Self::spawn(cmd, limits),
            Sandbox::AppContainer { .. } | Sandbox::Restricted => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "AppContainer und eingeschränkte Tokens gibt es nur unter Windows",
            )),
        }
    }

    pub(crate) fn take_stdio(&mut self) -> Stdio3 {
        (
            self.child
                .stdin
                .take()
                .map(|x| Box::new(x) as Box<dyn Write + Send>),
            self.child
                .stdout
                .take()
                .map(|x| Box::new(x) as Box<dyn Read + Send>),
            self.child
                .stderr
                .take()
                .map(|x| Box::new(x) as Box<dyn Read + Send>),
        )
    }

    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Prüft ohne Einsammeln, ob der Hauptprozess beendet ist.
    pub(crate) fn has_exited(&mut self) -> io::Result<bool> {
        if self.status.is_some() {
            return Ok(true);
        }
        // SAFETY: siginfo_t ist ein POD-Typ; nullinitialisiert bedeutet
        // si_pid == 0 („noch kein Ereignis“). waitid schreibt nur hinein.
        unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let rc = libc::waitid(
                libc::P_PID,
                self.pgid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            );
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(info.si_pid() != 0)
        }
    }

    /// Beendet Nachkommen nach dem Ende des Hauptprozesses.
    /// Rückgabe: ob tatsächlich noch Nachkommen liefen.
    pub(crate) fn terminate_descendants(&mut self) -> bool {
        let others = group_members_except_leader(self.pgid);
        self.kill_group();
        others
    }

    pub(crate) fn terminate_tree(&mut self) {
        self.kill_group();
    }

    fn kill_group(&self) {
        // SAFETY: killpg sendet nur ein Signal an unsere eigene Prozessgruppe;
        // die Gruppen-ID ist durch den noch nicht eingesammelten Hauptprozess
        // reserviert.
        unsafe {
            libc::killpg(self.pgid, libc::SIGKILL);
        }
    }

    pub(crate) fn reap(&mut self) -> Option<ExitStatus> {
        if self.status.is_none() {
            self.status = self.child.wait().ok();
        }
        self.status
    }

    pub(crate) fn peak_memory(&self) -> Option<u64> {
        None
    }
}

/// Linux: zählt über /proc weitere Mitglieder der Prozessgruppe.
#[cfg(target_os = "linux")]
fn group_members_except_leader(pgid: libc::pid_t) -> bool {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return true; // unbekannt → vorsichtig annehmen
    };
    for e in dir.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<libc::pid_t>().ok()) else {
            continue;
        };
        if pid == pgid {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // Format: pid (comm) state ppid pgrp ...; comm kann Leerzeichen enthalten.
        let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) else {
            continue;
        };
        let mut it = rest.split_whitespace();
        let _state = it.next();
        let _ppid = it.next();
        if it.next().and_then(|g| g.parse::<libc::pid_t>().ok()) == Some(pgid) {
            return true;
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn group_members_except_leader(_pgid: libc::pid_t) -> bool {
    false
}

/// Größter residenter Speicher (Bytes) aller bisher beendeten und
/// abgewarteten Kindprozesse dieses Prozesses (`getrusage(RUSAGE_CHILDREN)`).
/// Nur für Messungen.
pub fn children_peak_rss() -> Option<u64> {
    // SAFETY: getrusage schreibt nur in die übergebene, vollständig
    // initialisierte Struktur.
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut u) };
    let kb = u64::try_from(u.ru_maxrss).ok()?;
    (r == 0 && kb > 0).then_some(kb * 1024)
}

/// Darf diese Datei bzw. dieser Ordner NUR von root verändert werden?
pub fn only_admins_can_modify(path: &std::path::Path) -> std::io::Result<Result<(), String>> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path)?;
    if m.uid() != 0 {
        return Ok(Err(format!("Besitzer uid {} ist nicht root", m.uid())));
    }
    if m.mode() & 0o022 != 0 {
        return Ok(Err(format!(
            "Gruppe oder andere dürfen schreiben (Modus {:o})",
            m.mode() & 0o777
        )));
    }
    Ok(Ok(()))
}
