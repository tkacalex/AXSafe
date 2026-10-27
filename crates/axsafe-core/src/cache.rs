//! Sicherer Ergebnis-Cache (AXS-027).
//!
//! **Gebunden an den Inhalt, nicht an Dateizustände:** Schlüssel ist der
//! SHA-256 der gerade gelesenen Bytes plus der Versionsschlüssel (Programm,
//! Engines mit Regel-/Signaturstand, Heuristik, Richtlinie, Grenzen). Die
//! Datei wird also immer gelesen und gehasht; gespart wird die Engine-Zeit.
//! Zeitstempel, Datei-IDs oder Volumes werden bewusst NICHT als Beleg für
//! „unverändert“ genutzt – sie lassen sich setzen bzw. ändern sich beim
//! erneuten Einbinden eines Datenträgers, ohne dass der Inhalt gleich bleibt.
//!
//! * Neuer Regel- oder Signaturstand ⇒ anderer Versionsschlüssel ⇒ kein
//!   Eintrag passt mehr (Schlüssel = Versionsschlüssel + SHA-256); alte
//!   Einträge altern über die Größengrenze heraus. Aufträge mit und ohne
//!   ClamAV haben verschiedene Schlüssel und verdrängen sich nicht.
//! * Gespeichert werden nur **vollständige** Ergebnisse (keine Lücke) und nur
//!   inhaltsabhängige Teile: Dateityp, statische Merkmale und Engine-Ergebnisse.
//!   Heuristik (hängt am Namen), Herkunft und Authenticode (hängen an Datenstrom
//!   und Vertrauensspeicher) werden bei jedem Scan neu bestimmt.
//! * Begrenzt (Einträge, Dateigröße); beschädigte Einträge werden verworfen.

use crate::engine::EngineOutcome;
use crate::features::StaticFeatures;
use crate::filetype::FileKind;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const CACHE_SCHEMA: &str = "axsafe.cache/1";
pub const DEFAULT_MAX_ENTRIES: usize = 20_000;
pub const MAX_CACHE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_LINE: u64 = 1024 * 1024;

/// Inhaltsabhängiger Teil eines Ergebnisses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedScan {
    pub kind: FileKind,
    #[serde(default)]
    pub features: Option<StaticFeatures>,
    pub engines: Vec<EngineOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheInfo {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
    pub note: String,
}

#[derive(Serialize, Deserialize)]
struct Header {
    schema: String,
}

#[derive(Serialize, Deserialize)]
struct Line {
    version_key: String,
    sha256: String,
    scan: CachedScan,
}

struct Inner {
    /// Schlüssel: "<Versionsschlüssel>:<SHA-256>".
    map: HashMap<String, CachedScan>,
    order: VecDeque<String>,
    hits: u64,
    misses: u64,
    dirty: bool,
}

pub struct ScanCache {
    inner: Mutex<Inner>,
    max_entries: usize,
    path: Option<PathBuf>,
}

fn key(version_key: &str, sha256: &str) -> String {
    format!("{version_key}:{sha256}")
}

fn valid_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl ScanCache {
    /// Nur im Speicher.
    pub fn in_memory(max_entries: usize) -> Self {
        ScanCache {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
                hits: 0,
                misses: 0,
                dirty: false,
            }),
            max_entries: max_entries.max(1),
            path: None,
        }
    }

    /// Mit Datei (Dienst: nur vom Dienst beschreibbarer Ordner). Fehlt die
    /// Datei oder ist sie unlesbar, beginnt der Cache leer.
    pub fn persistent(path: PathBuf, max_entries: usize) -> Self {
        let mut c = Self::in_memory(max_entries);
        if let Ok(entries) = Self::read_file(&path) {
            let g = c.inner.get_mut().unwrap_or_else(|e| e.into_inner());
            for (key, scan) in entries.into_iter().take(c.max_entries) {
                if g.map.insert(key.clone(), scan).is_none() {
                    g.order.push_back(key);
                }
            }
        }
        c.path = Some(path);
        c
    }

    fn read_file(path: &Path) -> std::io::Result<Vec<(String, CachedScan)>> {
        let f = std::fs::File::open(path)?;
        let mut r = BufReader::new(f.take(MAX_CACHE_FILE_BYTES));
        let mut first = String::new();
        r.read_line(&mut first)?;
        let h: Header = serde_json::from_str(first.trim_end()).map_err(std::io::Error::other)?;
        if h.schema != CACHE_SCHEMA {
            return Err(std::io::Error::other("anderes Cache-Schema"));
        }
        let mut out = Vec::new();
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n = (&mut r).take(MAX_LINE + 1).read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            if buf.last() != Some(&b'\n') || buf.len() as u64 > MAX_LINE {
                break; // abgeschnitten oder übergroß: Rest verwerfen
            }
            if let Ok(l) = serde_json::from_slice::<Line>(&buf) {
                if valid_sha(&l.sha256) && valid_sha(&l.version_key) {
                    out.push((key(&l.version_key, &l.sha256), l.scan));
                }
            }
        }
        Ok(out)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, version_key: &str, sha256: &str) -> Option<CachedScan> {
        let mut g = self.lock();
        match g.map.get(&key(version_key, sha256)).cloned() {
            Some(c) => {
                g.hits += 1;
                Some(c)
            }
            None => {
                g.misses += 1;
                None
            }
        }
    }

    pub fn put(&self, version_key: &str, sha256: &str, scan: CachedScan) {
        if !valid_sha(sha256) || !valid_sha(version_key) {
            return;
        }
        let k = key(version_key, sha256);
        let mut g = self.lock();
        if g.map.insert(k.clone(), scan).is_none() {
            g.order.push_back(k);
        }
        while g.order.len() > self.max_entries {
            if let Some(old) = g.order.pop_front() {
                g.map.remove(&old);
            }
        }
        g.dirty = true;
    }

    /// Alles verwerfen (z. B. auf Anforderung).
    pub fn clear(&self) {
        let mut g = self.lock();
        g.map.clear();
        g.order.clear();
        g.dirty = true;
    }

    pub fn info(&self) -> CacheInfo {
        let g = self.lock();
        CacheInfo {
            hits: g.hits,
            misses: g.misses,
            entries: g.map.len() as u64,
            note: "Cache an Inhalt (SHA-256) und Engine-/Regel-/Richtlinienstand gebunden; \
                   Dateien werden immer gelesen, Heuristik, Herkunft und Signatur neu bestimmt"
                .into(),
        }
    }

    /// Schreibt den Cache atomar (temporäre Datei + Umbenennen).
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let (header, lines) = {
            let mut g = self.lock();
            if !g.dirty {
                return Ok(());
            }
            g.dirty = false;
            let h = Header {
                schema: CACHE_SCHEMA.into(),
            };
            let lines: Vec<Line> = g
                .order
                .iter()
                .filter_map(|k| {
                    let (vk, sha) = k.split_once(':')?;
                    g.map.get(k).map(|s| Line {
                        version_key: vk.to_string(),
                        sha256: sha.to_string(),
                        scan: s.clone(),
                    })
                })
                .collect();
            (h, lines)
        };
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
            serde_json::to_writer(&mut f, &header).map_err(std::io::Error::other)?;
            f.write_all(b"\n")?;
            let mut written = 0u64;
            for l in &lines {
                let b = serde_json::to_vec(l).map_err(std::io::Error::other)?;
                written += b.len() as u64 + 1;
                if written > MAX_CACHE_FILE_BYTES {
                    break;
                }
                f.write_all(&b)?;
                f.write_all(b"\n")?;
            }
            f.flush()?;
            f.get_ref().sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::Verdict;

    fn scan(v: Verdict) -> CachedScan {
        CachedScan {
            kind: FileKind::Text,
            features: None,
            engines: vec![EngineOutcome {
                engine: "e".into(),
                engine_version: "1".into(),
                content_version: "1".into(),
                verdict: v,
                detections: vec![],
                gaps: vec![],
                note: None,
                duration_ms: 0,
            }],
        }
    }

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const V1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const V2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn other_version_key_never_matches() {
        let c = ScanCache::in_memory(10);
        c.put(V1, A, scan(Verdict::NoDetection));
        assert!(c.get(V1, A).is_some());
        assert!(
            c.get(V2, A).is_none(),
            "neuer Regelstand darf keine alte Freigabe liefern"
        );
        assert!(c.get(V1, B).is_none());
        let i = c.info();
        assert_eq!((i.hits, i.misses), (1, 2));
    }

    #[test]
    fn bounded_and_rejects_bad_keys() {
        let c = ScanCache::in_memory(1);
        c.put(V1, A, scan(Verdict::NoDetection));
        c.put(V1, B, scan(Verdict::NoDetection));
        assert!(c.get(V1, A).is_none());
        assert!(c.get(V1, B).is_some());
        c.put(V1, "kurz", scan(Verdict::NoDetection));
        c.put("kein-schluessel", A, scan(Verdict::NoDetection));
        assert_eq!(c.info().entries, 1);
    }

    #[test]
    fn persists_atomically_and_survives_damage() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.jsonl");
        {
            let c = ScanCache::persistent(p.clone(), 10);
            c.put(V1, A, scan(Verdict::NoDetection));
            c.put(V1, B, scan(Verdict::Malicious));
            c.save().unwrap();
        }
        assert!(!p.with_extension("tmp").exists());
        let c = ScanCache::persistent(p.clone(), 10);
        assert_eq!(c.get(V1, B).unwrap().engines[0].verdict, Verdict::Malicious);
        assert!(c.get(V2, A).is_none());
        // Abgeschnittene letzte Zeile: verworfen, der Rest bleibt.
        let mut t = std::fs::read_to_string(&p).unwrap();
        t.truncate(t.len() - 10);
        std::fs::write(&p, t).unwrap();
        let c = ScanCache::persistent(p.clone(), 10);
        assert_eq!(c.info().entries, 1);
        std::fs::write(&p, b"kein json\n").unwrap();
        let c = ScanCache::persistent(p, 10);
        assert_eq!(c.info().entries, 0);
    }
}
