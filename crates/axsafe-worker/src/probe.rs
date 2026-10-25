//! Zugriffsprobe für die ClamAV-Abschottung (Windows, `Sandbox::Restricted`).
//!
//! `axsafe-worker --zugriffsprobe <prüfung>...` wird vom Host mit GENAU dem
//! eingeschränkten Token gestartet, das auch `clamscan` bekommt, und meldet,
//! was dieser Prozess darf. Er liest dabei keine Nutzdaten aus und schreibt
//! nur eine leere Probedatei, die sofort wieder gelöscht wird.
//!
//! Prüfungen (je eine Zeile JSON auf stdout):
//! * `lesen:<pfad>`      Datei lesen bzw. Ordner auflisten und erste Datei öffnen
//! * `aufloesen:<pfad>`  `std::fs::canonicalize` (braucht ClamAV für `certs`)
//! * `anlegen:<ordner>`  Probedatei anlegen und löschen
//! * `tcp:<host:port>`   ausgehende TCP-Verbindung (3 s)

use std::io::Read;

fn result(kind: &str, target: &str, r: Result<String, std::io::Error>) {
    let (allowed, detail) = match r {
        Ok(d) => (true, d),
        Err(e) => (false, e.to_string()),
    };
    println!(
        "{}",
        serde_json::json!({ "check": kind, "target": target, "allowed": allowed, "detail": detail })
    );
}

fn read_target(p: &std::path::Path) -> std::io::Result<String> {
    if p.is_dir() {
        let mut n = 0usize;
        let mut first = None;
        for e in std::fs::read_dir(p)? {
            let e = e?;
            n += 1;
            if first.is_none() && e.file_type()?.is_file() {
                first = Some(e.path());
            }
        }
        if let Some(f) = first {
            let mut buf = [0u8; 16];
            let k = std::fs::File::open(&f)?.read(&mut buf)?;
            Ok(format!("{n} Einträge, {} gelesen ({k} Bytes)", f.display()))
        } else {
            Ok(format!("{n} Einträge"))
        }
    } else {
        let mut buf = [0u8; 16];
        let k = std::fs::File::open(p)?.read(&mut buf)?;
        Ok(format!("{k} Bytes gelesen"))
    }
}

/// Einstieg für `axsafe-worker --zugriffsprobe ...`.
pub fn access_probe_main(args: impl Iterator<Item = String>) -> i32 {
    for a in args {
        let Some((kind, target)) = a.split_once(':') else {
            result(
                "unbekannt",
                &a,
                Err(std::io::Error::other("Format kind:ziel")),
            );
            continue;
        };
        let p = std::path::Path::new(target);
        let r = match kind {
            "lesen" => read_target(p),
            "aufloesen" => std::fs::canonicalize(p).map(|c| c.display().to_string()),
            "anlegen" => {
                let f = p.join(format!("axsafe-probe-{}.tmp", std::process::id()));
                std::fs::write(&f, b"")
                    .and_then(|_| std::fs::remove_file(&f))
                    .map(|_| "angelegt und gelöscht".into())
            }
            "tcp" => {
                use std::net::ToSocketAddrs;
                target
                    .to_socket_addrs()
                    .and_then(|mut it| {
                        it.next()
                            .ok_or_else(|| std::io::Error::other("keine Adresse"))
                    })
                    .and_then(|addr| {
                        std::net::TcpStream::connect_timeout(
                            &addr,
                            std::time::Duration::from_secs(3),
                        )
                        .map(|_| format!("verbunden mit {addr}"))
                    })
            }
            _ => Err(std::io::Error::other("unbekannte Prüfung")),
        };
        result(kind, target, r);
    }
    0
}
