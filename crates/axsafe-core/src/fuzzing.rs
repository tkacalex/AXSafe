//! Fuzz-Einstiegspunkte (AXS-028).
//!
//! Dieselben Funktionen laufen
//! * mit libFuzzer im CI-Job „Fuzzing“ (`fuzz/`, Nightly, je Ziel feste Dauer),
//! * als deterministischer Mutationstest im normalen Testlauf (stabil, auch
//!   auf dem Zielrechner), siehe Tests unten.
//!
//! Jede Funktion verarbeitet beliebige, nicht vertrauenswürdige Bytes und
//! darf weder paniken noch unbegrenzt Zeit oder Speicher brauchen.

use crate::filetype;

/// Typerkennung, statische Merkmale, Containerstruktur und Heuristik.
pub fn typ_und_merkmale(data: &[u8]) {
    let kind = filetype::detect(data);
    let _ = filetype::content_format(&kind);
    let f = crate::features::analyze(data, &kind);
    let _ = crate::container::check(data, &kind);
    // Dateiname aus den ersten Bytes (auch ungültiges UTF-8, Steuerzeichen).
    let name = String::from_utf8_lossy(&data[..data.len().min(64)]).into_owned();
    let _ = crate::heuristics::evaluate(&name, &kind, Some(&f), None, None);
    let _ = crate::heuristics::outcome(Vec::new(), &[]);
}

/// Richtliniendatei (vom Administrator, trotzdem nie vertrauen).
pub fn richtlinie(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = crate::policy::parse_policy(&text, "fuzz", chrono::Utc::now());
}

/// Mark of the Web (`Zone.Identifier`) – schreibt jede Anwendung.
pub fn herkunft(data: &[u8]) {
    let _ = crate::heuristics::parse_zone_identifier(&String::from_utf8_lossy(data));
}

/// Nachrichten aus dem Worker (Ergebnis, Typ, Merkmale) – der Host vertraut
/// dem Worker nicht.
pub fn worker_antwort(data: &[u8]) {
    let _ = serde_json::from_slice::<crate::engine::EngineOutcome>(data);
    let _ = serde_json::from_slice::<crate::filetype::FileKind>(data);
    let _ = serde_json::from_slice::<crate::features::StaticFeatures>(data);
    let _ = serde_json::from_slice::<crate::report::FileResult>(data);
}

/// Fortsetzungs- und Cache-Dateien (begrenzt gelesen).
pub fn fortsetzung_und_cache(data: &[u8], dir: &std::path::Path) {
    let p = dir.join("eingabe.jsonl");
    if std::fs::write(&p, data).is_ok() {
        let _ = crate::resume::Resume::load(&p, "0");
        let c = crate::cache::ScanCache::persistent(p.clone(), 64);
        let _ = c.info();
    }
}

/// Saatdaten für den Fuzzer (harmlos, zur Laufzeit erzeugt).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut v = vec![
        ("text", b"Hallo Welt\r\n".to_vec()),
        ("ps1", b"Write-Host 'hallo'\r\n".to_vec()),
        ("pdf", b"%PDF-1.7\n1 0 obj<<>>endobj\n%%EOF\n".to_vec()),
        ("ole", {
            let mut d = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
            d.resize(1024, 0);
            d
        }),
        ("lnk", {
            let mut d = vec![0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0];
            d.resize(128, 0);
            d
        }),
        (
            "zone",
            b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.org/a\r\n".to_vec(),
        ),
        (
            "policy",
            br#"{"schema":"axsafe.policy/1","version":1,"exclusions":[]}"#.to_vec(),
        ),
    ];
    v.push(("pe", crate::features::pe_sample()));
    v.push(("zip", crate::container::zip_sample()));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Deterministische Mutation (xorshift): Bitkipper, Kürzen, Einfügen,
    /// Überschreiben mit Grenzwerten, Verdoppeln.
    fn mutate(seed: &[u8], r: &mut u64) -> Vec<u8> {
        let mut next = || {
            *r ^= *r << 13;
            *r ^= *r >> 7;
            *r ^= *r << 17;
            *r
        };
        let mut d = seed.to_vec();
        for _ in 0..(next() % 8 + 1) {
            let len = d.len().max(1);
            match next() % 6 {
                0 if !d.is_empty() => {
                    let i = (next() as usize) % d.len();
                    d[i] ^= 1 << (next() % 8);
                }
                1 => d.truncate((next() as usize) % len),
                2 => {
                    let i = (next() as usize) % len.min(d.len() + 1);
                    d.insert(i.min(d.len()), next() as u8);
                }
                3 if d.len() >= 4 => {
                    let i = (next() as usize) % (d.len() - 3);
                    let v = [0u32, 0xFFFF_FFFF, 0x7FFF_FFFF, 0x8000_0000][(next() % 4) as usize];
                    d[i..i + 4].copy_from_slice(&v.to_le_bytes());
                }
                4 if d.len() < 64 * 1024 => {
                    let copy = d.clone();
                    d.extend_from_slice(&copy);
                }
                _ => d.push(next() as u8),
            }
        }
        d
    }

    #[test]
    fn mutation_fuzzing_without_panic_or_hang() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = 0x1234_5678_9ABC_DEF1u64;
        let started = Instant::now();
        let mut slowest = Duration::ZERO;
        for (_, seed) in seeds() {
            for _ in 0..1500 {
                let m = mutate(&seed, &mut r);
                let t = Instant::now();
                typ_und_merkmale(&m);
                richtlinie(&m);
                herkunft(&m);
                worker_antwort(&m);
                slowest = slowest.max(t.elapsed());
            }
            for _ in 0..30 {
                fortsetzung_und_cache(&mutate(&seed, &mut r), dir.path());
            }
        }
        assert!(
            slowest < Duration::from_secs(2),
            "langsamste Eingabe {slowest:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(120));
    }

    /// Schreibt die Saatdaten für den libFuzzer-Lauf (CI-Job Fuzzing setzt
    /// `AXSAFE_FUZZ_SEEDS`); sonst in einen temporären Ordner und prüft, dass
    /// alle Saaten geschrieben und wieder lesbar sind.
    #[test]
    fn write_fuzz_seeds() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::env::var_os("AXSAFE_FUZZ_SEEDS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| tmp.path().to_path_buf());
        std::fs::create_dir_all(&dir).unwrap();
        let seeds = seeds();
        assert!(seeds.len() >= 9);
        for (name, data) in &seeds {
            std::fs::write(dir.join(name), data).unwrap();
            assert_eq!(&std::fs::read(dir.join(name)).unwrap(), data);
        }
    }
}
