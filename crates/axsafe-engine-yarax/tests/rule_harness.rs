//! AXS-022: Regeltests. Jede Regel unter `rules/` braucht in `rule-tests/`
//! Positiv- und gutartige Gegenbeispiele; Laufzeitgrenze je Regelsatz.
//! Beispiele entstehen zur Laufzeit (EICAR über einen Generator).

use axsafe_core::engine::{Engine, EngineHealth, ScanInput};
use axsafe_core::filetype::FileKind;
use axsafe_core::verdict::Verdict;
use axsafe_engine_yarax::YaraXEngine;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_SAMPLE: usize = 1024 * 1024;
const RUNTIME_LIMIT: Duration = Duration::from_secs(2);

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn eicar() -> Vec<u8> {
    let a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
    let b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    format!("{a}{b}").into_bytes()
}

/// Setzt ein Beispiel zusammen; unbekannte Felder sind ein Fehler.
fn build(sample: &Value) -> Result<Vec<u8>, String> {
    let obj = sample.as_object().ok_or("sample muss ein Objekt sein")?;
    const KNOWN: [&str; 8] = [
        "prefix_text",
        "prefix_hex",
        "generator",
        "text",
        "hex",
        "suffix_text",
        "suffix_hex",
        "repeat_suffix",
    ];
    if let Some(k) = obj.keys().find(|k| !KNOWN.contains(&k.as_str())) {
        return Err(format!("unbekanntes Feld {k}"));
    }
    let s = |k: &str| obj.get(k).and_then(Value::as_str);
    let hx = |k: &str| -> Result<Vec<u8>, String> {
        match s(k) {
            Some(h) => hex::decode(h).map_err(|e| format!("{k}: {e}")),
            None => Ok(Vec::new()),
        }
    };
    let mut out = Vec::new();
    out.extend_from_slice(s("prefix_text").unwrap_or("").as_bytes());
    out.extend(hx("prefix_hex")?);
    match s("generator") {
        None => {}
        Some("eicar") => out.extend(eicar()),
        Some(g) => return Err(format!("unbekannter Generator {g}")),
    }
    out.extend_from_slice(s("text").unwrap_or("").as_bytes());
    out.extend(hx("hex")?);
    let mut suffix = s("suffix_text").unwrap_or("").as_bytes().to_vec();
    suffix.extend(hx("suffix_hex")?);
    let n = obj
        .get("repeat_suffix")
        .and_then(Value::as_u64)
        .unwrap_or(1) as usize;
    if suffix.len().saturating_mul(n).saturating_add(out.len()) > MAX_SAMPLE {
        return Err("Beispiel größer als 1 MiB".into());
    }
    for _ in 0..n {
        out.extend_from_slice(&suffix);
    }
    Ok(out)
}

fn scan(e: &YaraXEngine, data: &[u8]) -> axsafe_core::engine::EngineOutcome {
    e.scan(&ScanInput {
        data,
        kind: &FileKind::Unknown,
        sha256: "",
        timeout: Duration::from_secs(10),
    })
}

fn specs() -> BTreeMap<String, (PathBuf, Value)> {
    let mut m = BTreeMap::new();
    for entry in std::fs::read_dir(root().join("rule-tests")).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        assert_eq!(v["schema"], "axsafe.rule-tests/1", "{}", p.display());
        let id = v["rule_id"].as_str().expect("rule_id").to_string();
        assert_eq!(
            p.file_stem().unwrap().to_str().unwrap(),
            id,
            "Dateiname muss der Regel-ID entsprechen"
        );
        assert!(m.insert(id.clone(), (p, v)).is_none(), "doppelt: {id}");
    }
    m
}

#[test]
fn every_rule_has_tests_and_every_test_has_a_rule() {
    let e = YaraXEngine::from_dir(root().join("rules"));
    assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
    let rules = e.rule_catalog();
    assert!(!rules.is_empty());
    let specs = specs();
    for r in &rules {
        let (p, v) = specs
            .get(&r.id)
            .unwrap_or_else(|| panic!("Regel {} hat keine rule-tests/{}.json", r.id, r.id));
        assert_eq!(
            v["rule_version"].as_str(),
            Some(r.version.as_str()),
            "{}: Regelversion geändert – Tests prüfen und Version eintragen",
            p.display()
        );
        assert!(!r.license.is_empty() && !r.source.is_empty(), "{r:?}");
    }
    for id in specs.keys() {
        assert!(
            rules.iter().any(|r| &r.id == id),
            "Testdatei ohne Regel: {id}"
        );
    }
}

#[test]
fn positives_hit_exactly_their_rule_and_benign_cases_do_not() {
    let e = YaraXEngine::from_dir(root().join("rules"));
    for (id, (p, v)) in specs() {
        let pos = v["positive"].as_array().expect("positive");
        let ben = v["benign"].as_array().expect("benign");
        assert!(!pos.is_empty(), "{}: kein Positivbeispiel", p.display());
        assert!(!ben.is_empty(), "{}: kein Gegenbeispiel", p.display());
        for (list, expect) in [(pos, true), (ben, false)] {
            for case in list {
                let name = case["name"].as_str().unwrap_or("?");
                let data = build(&case["sample"]).unwrap_or_else(|e| panic!("{id}/{name}: {e}"));
                let o = scan(&e, &data);
                assert!(
                    !matches!(o.verdict, Verdict::Error | Verdict::Timeout),
                    "{id}/{name}: {o:?}"
                );
                let hit = o
                    .detections
                    .iter()
                    .any(|d| d.rule_id.as_deref() == Some(id.as_str()));
                assert_eq!(hit, expect, "{id}/{name}: {:?}", o.detections);
            }
        }
    }
}

#[test]
fn every_rule_stays_within_runtime_limit() {
    let e = YaraXEngine::from_dir(root().join("rules"));
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let random: Vec<u8> = (0..8 * 1024 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    let repeated = vec![b'A'; 8 * 1024 * 1024];
    for data in [&random, &repeated] {
        let t = Instant::now();
        let o = scan(&e, data);
        let took = t.elapsed();
        assert_ne!(o.verdict, Verdict::Timeout);
        assert!(took < RUNTIME_LIMIT, "Regelsatz braucht {took:?} für 8 MiB");
    }
}

#[test]
fn sample_builder_rejects_unknown_fields_and_oversize() {
    assert!(build(&serde_json::json!({"text": "x"})).is_ok());
    assert!(build(&serde_json::json!({"unbekannt": 1})).is_err());
    assert!(build(&serde_json::json!({"generator": "malware"})).is_err());
    assert!(
        build(&serde_json::json!({"suffix_text": "AAAA", "repeat_suffix": 1_000_000})).is_err()
    );
}
