//! Prozessidentität (AXS-016): PID **und** Startzeit. Eine PID allein ist
//! nach dem Ende eines Prozesses wiederverwendbar; erst zusammen mit der
//! Startzeit bezeichnet sie genau einen Prozess.

// Betriebssystemaufrufe (Prozesszeiten); jede Stelle trägt eine SAFETY-Begründung.
#![allow(unsafe_code)]

use std::io;

/// Ein bestimmter Prozess: PID, Startzeit (systemeigene Einheit für den
/// exakten Vergleich und Unix-Nanosekunden für die Anzeige) und Programmpfad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStart {
    pub pid: u32,
    /// Windows: FILETIME der Erstellung (100 ns seit 1601); Linux: Starttakte
    /// seit Systemstart (`/proc/<pid>/stat`, Feld 22).
    pub start_ticks: u64,
    /// Startzeit in Nanosekunden seit 1970 (UTC).
    pub start_unix_ns: i128,
    pub image: Option<String>,
}

impl ProcessStart {
    /// Läuft GENAU dieser Prozess noch? `false`, wenn die PID frei oder an
    /// einen anderen (später gestarteten) Prozess vergeben ist.
    pub fn still_running(&self) -> bool {
        match process_start(self.pid) {
            Ok(now) => now.start_ticks == self.start_ticks && alive(self.pid),
            Err(_) => false,
        }
    }
}

/// Läuft der Prozess noch (nicht beendet, kein Zombie)? Unter Windows
/// bleibt das Prozessobjekt nach dem Ende bestehen, solange jemand ein
/// Handle hält – deshalb zählt der Exitcode.
#[cfg(windows)]
fn alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: Handle wird geschlossen.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code);
        CloseHandle(h);
        ok != 0 && code == 259 // STILL_ACTIVE
    }
}

#[cfg(target_os = "linux")]
fn alive(pid: u32) -> bool {
    // Zustand nach dem Kommandonamen: "Z" (Zombie) oder "X" (tot) = beendet.
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            s.rfind(')')
                .and_then(|i| s[i + 1..].split_whitespace().next().map(String::from))
        })
        .is_some_and(|st| st != "Z" && st != "X")
}

#[cfg(all(unix, not(target_os = "linux")))]
fn alive(_pid: u32) -> bool {
    false
}

/// Identität des eigenen Prozesses.
pub fn current_process() -> io::Result<ProcessStart> {
    process_start(std::process::id())
}

/// Identität eines laufenden Prozesses.
#[cfg(target_os = "linux")]
pub fn process_start(pid: u32) -> io::Result<ProcessStart> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let rest = stat
        .rfind(')')
        .map(|i| &stat[i + 1..])
        .ok_or_else(|| io::Error::other("/proc/<pid>/stat unlesbar"))?;
    // Nach ")" beginnt Feld 3; starttime ist Feld 22 → Index 19.
    let ticks: u64 = rest
        .split_whitespace()
        .nth(19)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| io::Error::other("starttime fehlt"))?;
    let btime: i128 = std::fs::read_to_string("/proc/stat")?
        .lines()
        .find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse().ok()))
        .ok_or_else(|| io::Error::other("btime fehlt"))?;
    // SAFETY: sysconf ohne Zeiger.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as i128;
    let image = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.display().to_string());
    Ok(ProcessStart {
        pid,
        start_ticks: ticks,
        start_unix_ns: btime * 1_000_000_000 + i128::from(ticks) * 1_000_000_000 / hz,
        image,
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn process_start(_pid: u32) -> io::Result<ProcessStart> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Prozessstartzeit nur unter Linux und Windows",
    ))
}

#[cfg(windows)]
pub fn process_start(pid: u32) -> io::Result<ProcessStart> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: Handle wird geschlossen; Puffer lokal.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        let z = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        let ok = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u);
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let image = (QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0)
            .then(|| String::from_utf16_lossy(&buf[..len as usize]));
        CloseHandle(h);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let ticks = (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime);
        // 1601 → 1970: 11 644 473 600 s.
        let unix_ns = (i128::from(ticks) - 116_444_736_000_000_000) * 100;
        Ok(ProcessStart {
            pid,
            start_ticks: ticks,
            start_unix_ns: unix_ns,
            image,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_identity_is_stable_and_running() {
        let a = current_process().unwrap();
        let b = current_process().unwrap();
        assert_eq!(a, b);
        assert!(a.still_running());
        assert!(a.start_unix_ns > 1_600_000_000_000_000_000, "{a:?}");
    }

    /// T-016: gleiche PID, andere Startzeit = anderer Prozess.
    #[test]
    fn same_pid_other_start_is_another_process() {
        let mut fake = current_process().unwrap();
        fake.start_ticks += 1;
        assert!(!fake.still_running());
    }

    /// Ein beendeter Prozess gilt nie mehr als „derselbe“, auch wenn seine
    /// PID inzwischen neu vergeben wurde.
    #[test]
    fn exited_process_is_not_still_running() {
        let mut c = if cfg!(windows) {
            std::process::Command::new("cmd")
                .args(["/C", "ping -n 30 127.0.0.1 >NUL"])
                .spawn()
                .unwrap()
        } else {
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap()
        };
        let id = process_start(c.id()).unwrap();
        assert!(id.still_running());
        c.kill().unwrap();
        c.wait().unwrap();
        assert!(!id.still_running());
    }

    /// Unter Windows bleibt das Prozessobjekt bestehen, solange ein Handle
    /// offen ist; unter Linux bleibt bis zum Abwarten ein Zombie. Beides
    /// zählt nicht als laufend.
    #[test]
    fn exited_but_not_released_process_is_not_running() {
        let mut c = if cfg!(windows) {
            std::process::Command::new("cmd")
                .args(["/C", "ping -n 30 127.0.0.1 >NUL"])
                .spawn()
                .unwrap()
        } else {
            std::process::Command::new("sleep").arg("30").spawn().unwrap()
        };
        let id = process_start(c.id()).unwrap();
        c.kill().unwrap();
        let t = std::time::Instant::now();
        while id.still_running() && t.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!id.still_running());
        c.wait().unwrap();
    }
}
