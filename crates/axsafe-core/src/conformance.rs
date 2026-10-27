//! Vertragstests für Engineadapter (AXS-021).
//!
//! Jede Engine wird mit derselben Prüfreihe geprüft (siehe
//! `docs/ENGINE-CONTRACT.md`). Ein Verstoß ist ein Fehler im Adapter, nie in
//! den Daten. Die Prüfreihe ist bewusst ohne Schadsoftware: Für den
//! Positivfall übergibt der Adapter-Test eine Probe, die sein **eigener**
//! Test-Erkennungsinhalt erkennt (z. B. EICAR, zur Laufzeit erzeugt).

use crate::engine::{Engine, EngineHealth, EngineOutcome, ScanInput};
use crate::filetype;
use crate::verdict::Verdict;
use std::time::Duration;

/// Ergebnis der Prüfreihe: Liste der Verstöße (leer = konform).
#[derive(Debug, Default)]
pub struct Report {
    pub violations: Vec<String>,
    pub checked: Vec<String>,
}

impl Report {
    fn check(&mut self, name: &str, ok: bool, detail: impl FnOnce() -> String) {
        self.checked.push(name.to_string());
        if !ok {
            self.violations.push(format!("{name}: {}", detail()));
        }
    }
}

fn run(e: &dyn Engine, data: &[u8], timeout: Duration) -> EngineOutcome {
    let kind = filetype::detect(data);
    e.scan(&ScanInput {
        data,
        kind: &kind,
        sha256: "",
        timeout,
    })
}

/// Allgemeine Regeln für JEDES Ergebnis.
fn outcome_rules(r: &mut Report, label: &str, e: &dyn Engine, o: &EngineOutcome) {
    let info = e.info();
    r.check(
        &format!("{label}: Engine-Name"),
        o.engine == info.name,
        || format!("Ergebnis nennt {:?}, info {:?}", o.engine, info.name),
    );
    r.check(
        &format!("{label}: Engine- und Inhaltsversion angegeben"),
        !o.engine_version.is_empty() && !o.content_version.is_empty(),
        || format!("{o:?}"),
    );
    r.check(
        &format!("{label}: Funde nur mit Fundzustand"),
        o.detections.is_empty() || o.verdict.is_detection(),
        || format!("{:?} mit {} Funden", o.verdict, o.detections.len()),
    );
    r.check(
        &format!("{label}: Fundzustand nur mit Fund"),
        !o.verdict.is_detection() || !o.detections.is_empty(),
        || format!("{:?} ohne Fundliste", o.verdict),
    );
    for d in &o.detections {
        r.check(
            &format!("{label}: Fund mit Belegen und Kennung"),
            !d.evidence.is_empty() && !d.name.is_empty() && d.verdict.is_detection(),
            || format!("{d:?}"),
        );
    }
    r.check(
        &format!("{label}: „ohne Fund“ nie mit Lücke"),
        o.verdict != Verdict::NoDetection || o.gaps.is_empty(),
        || format!("{:?}", o.gaps),
    );
    for g in &o.gaps {
        r.check(
            &format!("{label}: Lücke mit Lückenzustand und Erklärung"),
            g.state.is_incomplete() && !g.detail.is_empty(),
            || format!("{g:?}"),
        );
    }
}

/// Prüfreihe für eine BEREITE Engine. `positive` muss vom geladenen
/// Testinhalt der Engine erkannt werden; `benign` darf nicht erkannt werden.
pub fn check_ready(e: &dyn Engine, positive: &[u8], benign: &[u8]) -> Report {
    let mut r = Report::default();
    let info = e.info();
    r.check("bereit", info.health == EngineHealth::Ready, || {
        format!("{:?}", info.health)
    });
    r.check(
        "Name stabil",
        !info.name.is_empty() && e.name() == info.name,
        || format!("{} / {}", e.name(), info.name),
    );
    r.check(
        "Versionen und Lizenz angegeben",
        !info.engine_version.is_empty()
            && !info.content_version.is_empty()
            && !info.license.is_empty(),
        || format!("{info:?}"),
    );
    r.check(
        "Isolation beschrieben",
        !info.isolation.detail.is_empty() || !info.isolation.enforced,
        || format!("{:?}", info.isolation),
    );

    let t = Duration::from_secs(60);
    let p = run(e, positive, t);
    outcome_rules(&mut r, "Positivfall", e, &p);
    r.check("Positivfall erkannt", p.verdict.is_detection(), || {
        format!("{p:?}")
    });

    let b = run(e, benign, t);
    outcome_rules(&mut r, "Gegenfall", e, &b);
    r.check(
        "Gegenfall ohne Fund und vollständig",
        b.verdict == Verdict::NoDetection && b.gaps.is_empty(),
        || format!("{b:?}"),
    );

    let empty = run(e, b"", t);
    outcome_rules(&mut r, "leere Eingabe", e, &empty);
    r.check(
        "leere Eingabe ohne Fund",
        !empty.verdict.is_detection(),
        || format!("{empty:?}"),
    );

    let again = run(e, positive, t);
    r.check(
        "wiederholbar",
        again.verdict == p.verdict
            && again.detections.iter().map(|d| &d.name).collect::<Vec<_>>()
                == p.detections.iter().map(|d| &d.name).collect::<Vec<_>>(),
        || format!("{:?} vs {:?}", p.verdict, again.verdict),
    );

    // Zufällige und präparierte Eingaben: nie eine Panik, Regeln eingehalten.
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let random: Vec<u8> = (0..256 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let mut fake_pe = b"MZ".to_vec();
    fake_pe.extend_from_slice(&[0xFF; 4096]);
    for (label, data) in [("Zufallsdaten", &random[..]), ("kaputtes PE", &fake_pe[..])] {
        let o = run(e, data, t);
        outcome_rules(&mut r, label, e, &o);
    }
    r
}

/// Prüfreihe für eine NICHT bereite Engine (z. B. fehlende Datenbank):
/// Sie darf nie „ohne Fund“ melden.
pub fn check_unavailable(e: &dyn Engine) -> Report {
    let mut r = Report::default();
    let info = e.info();
    r.check(
        "als nicht verfügbar gemeldet",
        matches!(info.health, EngineHealth::Unavailable { ref reason } if !reason.is_empty()),
        || format!("{:?}", info.health),
    );
    let o = run(e, b"beliebiger Inhalt", Duration::from_secs(10));
    r.check(
        "nicht bereite Engine meldet nie „ohne Fund“",
        o.verdict != Verdict::NoDetection && !o.verdict.is_detection(),
        || format!("{o:?}"),
    );
    r
}

/// Für Tests: Verstöße als Panik mit allen Angaben.
pub fn assert_conforms(r: &Report) {
    assert!(
        r.violations.is_empty(),
        "Engine verletzt den Vertrag:\n  {}",
        r.violations.join("\n  ")
    );
    assert!(!r.checked.is_empty());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{ContentKind, Detection, EngineInfo, Isolation};
    use crate::verdict::{Confidence, Severity};

    /// Absichtlich fehlerhafte Engine: meldet „ohne Fund“ trotz Lücke und
    /// Funde ohne Belege – die Prüfreihe muss das finden.
    struct Broken;
    impl Engine for Broken {
        fn name(&self) -> &str {
            "kaputt"
        }
        fn info(&self) -> EngineInfo {
            EngineInfo {
                name: "kaputt".into(),
                engine_version: "1".into(),
                content_version: "1".into(),
                health: EngineHealth::Ready,
                license: "x".into(),
                content_kind: ContentKind::TestOnly,
                content_note: String::new(),
                inspects_contents_of: vec![],
                isolation: Isolation::in_process(),
                content_time_utc: None,
            }
        }
        fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
            let hit = input.data.starts_with(b"BAD");
            EngineOutcome {
                engine: "kaputt".into(),
                engine_version: "1".into(),
                content_version: "1".into(),
                verdict: if hit {
                    Verdict::Malicious
                } else {
                    Verdict::NoDetection
                },
                detections: if hit {
                    vec![Detection {
                        name: "X".into(),
                        verdict: Verdict::Malicious,
                        severity: Severity::High,
                        confidence: Confidence::High,
                        rule_id: None,
                        rule_version: None,
                        evidence: vec![],
                        test_signature: true,
                    }]
                } else {
                    vec![]
                },
                gaps: if input.data.is_empty() {
                    vec![crate::engine::Gap::new(
                        Verdict::Error,
                        crate::engine::GapReason::EngineError,
                        "kaputt",
                        "x",
                    )]
                } else {
                    vec![]
                },
                note: None,
                duration_ms: 0,
            }
        }
    }

    #[test]
    fn broken_engine_is_caught() {
        let r = check_ready(&Broken, b"BAD", b"gut");
        assert!(r.violations.iter().any(|v| v.contains("Belegen")), "{r:?}");
        assert!(
            r.violations.iter().any(|v| v.contains("nie mit Lücke")),
            "{r:?}"
        );
    }
}
