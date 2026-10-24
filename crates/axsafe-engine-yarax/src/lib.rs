//! YARA-X Engineadapter (AXS-022, T-022).
//!
//! * Regeln werden aus einem Verzeichnis (`*.yar`, rekursiv, sortiert) geladen.
//! * Jede Regel **muss** die AXSafe-Pflichtmetadaten tragen, sonst wird der
//!   gesamte Regelsatz abgelehnt (fail closed, Zustand `Unavailable`).
//! * Laufzeit je Objekt ist über das Zeitbudget begrenzt; eine
//!   Zeitüberschreitung ergibt [`Verdict::Timeout`], nie „sauber“.
//! * Ein Fund entsteht nur durch Inhalt: YARA-X sieht den Dateinamen nicht.
//!
//! Noch offen (siehe `docs/BLOCKERS.md`): Signatur der Regelpakete (P04),
//! Ausführung in einem isolierten Worker-Prozess (P02), Speicherlimit.

#![forbid(unsafe_code)]

use axsafe_core::engine::{
    ContentKind, Detection, Engine, EngineHealth, EngineInfo, EngineOutcome, Gap, GapReason,
    ScanInput,
};
use axsafe_core::verdict::{Confidence, Severity, Verdict};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Gepinnte YARA-X-Version. Ein Test prüft die Übereinstimmung mit Cargo.lock.
pub const YARAX_VERSION: &str = "1.22.0";

/// Pflichtfelder in `meta:` jeder AXSafe-Regel.
pub const REQUIRED_META: [&str; 8] = [
    "id",
    "verdict",
    "severity",
    "confidence",
    "author",
    "license",
    "source",
    "min_engine",
];

struct Loaded {
    rules: yara_x::Rules,
    content_version: String,
    rule_count: usize,
    /// Regeln mit `meta: test = true` (Funktionstest, z. B. EICAR).
    test_rule_count: usize,
}

/// YARA-X Engine mit geladenem Regelsatz.
pub struct YaraXEngine {
    loaded: Result<Loaded, String>,
    rules_dir: PathBuf,
}

/// Kennzahlen eines geladenen Regelsatzes (für den Worker-Handshake).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuleStats {
    pub content_version: String,
    pub rule_count: usize,
    pub test_rule_count: usize,
}

fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.path());
    for e in entries {
        let ft = e.file_type()?;
        let p = e.path();
        if ft.is_dir() {
            collect_rule_files(&p, out)?;
        } else if ft.is_file() && p.extension().and_then(|x| x.to_str()) == Some("yar") {
            out.push(p);
        }
    }
    Ok(())
}

fn meta_str(rule: &yara_x::Rule<'_, '_>, key: &str) -> Option<String> {
    rule.metadata()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| match v {
            yara_x::MetaValue::String(s) => s.to_string(),
            yara_x::MetaValue::Integer(i) => i.to_string(),
            yara_x::MetaValue::Float(f) => f.to_string(),
            yara_x::MetaValue::Bool(b) => b.to_string(),
            yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        })
}

fn parse_verdict(s: &str) -> Option<Verdict> {
    match s {
        "malicious" => Some(Verdict::Malicious),
        "suspicious" => Some(Verdict::Suspicious),
        "pua" => Some(Verdict::Pua),
        _ => None,
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn parse_confidence(s: &str) -> Option<Confidence> {
    match s {
        "low" => Some(Confidence::Low),
        "medium" => Some(Confidence::Medium),
        "high" => Some(Confidence::High),
        _ => None,
    }
}

fn version_tuple(v: &str) -> Option<(u32, u32, u32)> {
    let mut it = v.split('.').map(|p| p.parse::<u32>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

/// Regelbestand verständlich beschreiben (Befund 7): nur Testregeln werden
/// unübersehbar als solche ausgewiesen.
pub fn describe_content(st: &RuleStats) -> (ContentKind, String) {
    if st.test_rule_count == st.rule_count {
        (
            ContentKind::TestOnly,
            format!(
                "nur Funktionstest-Regeln ({} von {}), z. B. EICAR – damit wird keine echte \
                 Schadsoftware erkannt",
                st.test_rule_count, st.rule_count
            ),
        )
    } else {
        (
            ContentKind::Production,
            format!(
                "{} Regeln, davon {} produktiv und {} Funktionstest",
                st.rule_count,
                st.rule_count - st.test_rule_count,
                st.test_rule_count
            ),
        )
    }
}

/// Eine Regeldatei als Text (für den isolierten Worker, der selbst keine
/// Dateien lesen darf).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuleSource {
    /// Relativer Pfad mit `/` (geht in die Inhaltsversion ein).
    pub path: String,
    pub text: String,
}

/// Liest alle `*.yar` rekursiv und sortiert. Fehler sind beschreibend.
pub fn read_rule_sources(dir: &Path) -> Result<Vec<RuleSource>, String> {
    let mut files = Vec::new();
    collect_rule_files(dir, &mut files)
        .map_err(|e| format!("Regelverzeichnis {} nicht lesbar: {e}", dir.display()))?;
    if files.is_empty() {
        return Err(format!(
            "Keine Regeln (*.yar) in {} gefunden",
            dir.display()
        ));
    }
    let mut out = Vec::with_capacity(files.len());
    for f in &files {
        let src = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
        let rel = f
            .strip_prefix(dir)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        let text = String::from_utf8(src).map_err(|_| format!("{}: kein UTF-8", f.display()))?;
        out.push(RuleSource { path: rel, text });
    }
    Ok(out)
}

fn load(dir: &Path) -> Result<Loaded, String> {
    compile(&read_rule_sources(dir)?)
}

/// Kompiliert und validiert einen Regelsatz (fail closed).
fn compile(sources: &[RuleSource]) -> Result<Loaded, String> {
    if sources.is_empty() {
        return Err("Regelsatz enthält keine Regeldateien".into());
    }
    let mut hasher = Sha256::new();
    let mut compiler = yara_x::Compiler::new();
    for src in sources {
        hasher.update(src.path.as_bytes());
        hasher.update([0]);
        hasher.update(src.text.as_bytes());
        hasher.update([0]);
        compiler
            .add_source(src.text.as_str())
            .map_err(|e| format!("{}: Kompilierfehler: {e}", src.path))?;
    }
    let rules = compiler.build();
    let engine = version_tuple(YARAX_VERSION).expect("gültige Konstante");
    let mut count = 0usize;
    let mut test_count = 0usize;
    for rule in rules.iter() {
        count += 1;
        if meta_str(&rule, "test").as_deref() == Some("true") {
            test_count += 1;
        }
        let ident = rule.identifier().to_string();
        for key in REQUIRED_META {
            if meta_str(&rule, key).is_none() {
                return Err(format!("Regel {ident}: Pflichtmetadatum '{key}' fehlt"));
            }
        }
        let v = meta_str(&rule, "verdict").unwrap_or_default();
        parse_verdict(&v).ok_or(format!("Regel {ident}: ungültiges verdict '{v}'"))?;
        let s = meta_str(&rule, "severity").unwrap_or_default();
        parse_severity(&s).ok_or(format!("Regel {ident}: ungültige severity '{s}'"))?;
        let c = meta_str(&rule, "confidence").unwrap_or_default();
        parse_confidence(&c).ok_or(format!("Regel {ident}: ungültige confidence '{c}'"))?;
        let min = meta_str(&rule, "min_engine").unwrap_or_default();
        let min_t =
            version_tuple(&min).ok_or(format!("Regel {ident}: ungültige min_engine '{min}'"))?;
        if min_t > engine {
            return Err(format!(
                "Regel {ident}: benötigt YARA-X {min}, vorhanden {YARAX_VERSION}"
            ));
        }
    }
    if count == 0 {
        return Err("Regelsatz enthält keine Regeln".into());
    }
    let digest = hex::encode(hasher.finalize());
    Ok(Loaded {
        rules,
        content_version: format!("rules-sha256:{}", &digest[..16]),
        rule_count: count,
        test_rule_count: test_count,
    })
}

impl YaraXEngine {
    /// Lädt Regeln. Fehler werden nicht verschluckt, sondern als
    /// `Unavailable` mit Grund gemeldet.
    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        let rules_dir = dir.into();
        YaraXEngine {
            loaded: load(&rules_dir),
            rules_dir,
        }
    }

    /// Kompiliert Regeln aus übergebenen Texten (Worker ohne Dateizugriff).
    pub fn from_sources(sources: &[RuleSource]) -> Self {
        YaraXEngine {
            loaded: compile(sources),
            rules_dir: PathBuf::new(),
        }
    }

    /// Kennzahlen oder Ladefehler.
    pub fn stats(&self) -> Result<RuleStats, String> {
        self.loaded
            .as_ref()
            .map(|l| RuleStats {
                content_version: l.content_version.clone(),
                rule_count: l.rule_count,
                test_rule_count: l.test_rule_count,
            })
            .map_err(|e| e.clone())
    }

    /// Anzahl geladener Regeln (0 bei Ladefehler).
    pub fn rule_count(&self) -> usize {
        self.loaded.as_ref().map(|l| l.rule_count).unwrap_or(0)
    }

    pub fn rules_dir(&self) -> &Path {
        &self.rules_dir
    }

    fn outcome(&self, verdict: Verdict, note: Option<String>, start: Instant) -> EngineOutcome {
        EngineOutcome {
            engine: "yara-x".into(),
            engine_version: YARAX_VERSION.into(),
            content_version: self
                .loaded
                .as_ref()
                .map(|l| l.content_version.clone())
                .unwrap_or_else(|_| "nicht geladen".into()),
            verdict,
            detections: Vec::new(),
            gaps: match verdict {
                Verdict::Timeout => vec![Gap::new(
                    Verdict::Timeout,
                    GapReason::EngineTimeout,
                    "yara-x",
                    note.clone().unwrap_or_default(),
                )],
                Verdict::Error => vec![Gap::new(
                    Verdict::Error,
                    GapReason::EngineError,
                    "yara-x",
                    note.clone().unwrap_or_default(),
                )],
                _ => Vec::new(),
            },
            note,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Anzahl geladener Funktions-Testregeln.
    pub fn test_rule_count(&self) -> usize {
        self.loaded.as_ref().map(|l| l.test_rule_count).unwrap_or(0)
    }
}

impl Engine for YaraXEngine {
    fn name(&self) -> &str {
        "yara-x"
    }

    fn info(&self) -> EngineInfo {
        let (content_version, health) = match &self.loaded {
            Ok(l) => (l.content_version.clone(), EngineHealth::Ready),
            Err(e) => (
                "nicht geladen".into(),
                EngineHealth::Unavailable { reason: e.clone() },
            ),
        };
        let (content_kind, content_note) = match self.stats() {
            Ok(st) => describe_content(&st),
            Err(_) => (ContentKind::Unknown, "Regelsatz nicht geladen".into()),
        };
        EngineInfo {
            name: "yara-x".into(),
            engine_version: YARAX_VERSION.into(),
            content_version,
            health,
            license: "BSD-3-Clause (Engine; Regellizenzen je Regel in meta.license)".into(),
            content_kind,
            content_note,
            // YARA-X prüft die übergebenen Rohbytes; Containerinhalte werden
            // nicht entpackt (Befund 3).
            inspects_contents_of: Vec::new(),
            isolation: axsafe_core::engine::Isolation::in_process(),
        }
    }

    fn scan(&self, input: &ScanInput<'_>) -> EngineOutcome {
        let start = Instant::now();
        let loaded = match &self.loaded {
            Ok(l) => l,
            Err(e) => return self.outcome(Verdict::Error, Some(e.clone()), start),
        };
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut scanner = yara_x::Scanner::new(&loaded.rules);
            scanner.set_timeout(input.timeout);
            match scanner.scan(input.data) {
                Ok(results) => {
                    let mut dets = Vec::new();
                    for rule in results.matching_rules() {
                        let get = |k: &str| meta_str(&rule, k).unwrap_or_default();
                        let mut evidence = Vec::new();
                        for pat in rule.patterns() {
                            for m in pat.matches().take(3) {
                                let r = m.range();
                                evidence.push(format!(
                                    "Muster {} bei Offset {}..{}",
                                    pat.identifier(),
                                    r.start,
                                    r.end
                                ));
                            }
                        }
                        if evidence.is_empty() {
                            evidence
                                .push(format!("Bedingung der Regel {} erfüllt", rule.identifier()));
                        }
                        dets.push(Detection {
                            name: meta_str(&rule, "name")
                                .unwrap_or_else(|| rule.identifier().to_string()),
                            verdict: parse_verdict(&get("verdict")).unwrap_or(Verdict::Suspicious),
                            severity: parse_severity(&get("severity")).unwrap_or(Severity::Medium),
                            confidence: parse_confidence(&get("confidence"))
                                .unwrap_or(Confidence::Low),
                            rule_id: Some(get("id")),
                            evidence,
                            test_signature: get("test") == "true",
                        });
                    }
                    Ok(dets)
                }
                Err(yara_x::ScanError::Timeout) => {
                    Err((Verdict::Timeout, "Zeitbudget überschritten".to_string()))
                }
                Err(e) => Err((Verdict::Error, format!("Scanfehler: {e}"))),
            }
        }));
        match run {
            Ok(Ok(dets)) => {
                let verdict = axsafe_core::verdict::aggregate(
                    std::iter::once(Verdict::NoDetection).chain(dets.iter().map(|d| d.verdict)),
                );
                let mut o = self.outcome(verdict, None, start);
                o.detections = dets;
                o
            }
            Ok(Err((v, note))) => self.outcome(v, Some(note), start),
            Err(_) => self.outcome(
                Verdict::Error,
                Some("Interner Fehler (Panic) in der Engine abgefangen".into()),
                start,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axsafe_core::filetype::FileKind;
    use std::time::Duration;

    /// EICAR wird zur Laufzeit zusammengesetzt, damit die Quelltextdatei
    /// selbst keinen zusammenhängenden Teststring enthält.
    pub(crate) fn eicar() -> Vec<u8> {
        let a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
        let b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        format!("{a}{b}").into_bytes()
    }

    fn repo_rules() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules")
    }

    fn scan(engine: &YaraXEngine, data: &[u8]) -> EngineOutcome {
        engine.scan(&ScanInput {
            data,
            kind: &FileKind::Unknown,
            sha256: "",
            timeout: Duration::from_secs(10),
        })
    }

    #[test]
    fn repo_rules_load_with_required_meta() {
        let e = YaraXEngine::from_dir(repo_rules());
        assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
        assert!(e.rule_count() >= 1);
        assert!(e.info().content_version.starts_with("rules-sha256:"));
    }

    #[test]
    fn repo_rules_are_marked_test_only() {
        // Befund 7: Der mitgelieferte Regelbestand ist ausschließlich EICAR.
        let i = YaraXEngine::from_dir(repo_rules()).info();
        assert_eq!(i.content_kind, ContentKind::TestOnly, "{i:?}");
        assert!(i.content_note.contains("keine echte"));
        assert!(
            i.inspects_contents_of.is_empty(),
            "YARA-X entpackt keine Container"
        );
    }

    #[test]
    fn mixed_rules_are_production() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            repo_rules().join("test/eicar.yar"),
            dir.path().join("eicar.yar"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("prod.yar"),
            r#"rule Prod { meta: id = "P1" verdict = "suspicious" severity = "low" confidence = "low"
               author = "t" license = "CC0-1.0" source = "t" min_engine = "1.0.0"
               strings: $a = "nie-vorkommender-teststring-axsafe" condition: $a }"#,
        )
        .unwrap();
        let e = YaraXEngine::from_dir(dir.path());
        assert_eq!(e.info().content_kind, ContentKind::Production);
        assert_eq!(e.test_rule_count(), 1);
    }

    #[test]
    fn eicar_positive() {
        let e = YaraXEngine::from_dir(repo_rules());
        let o = scan(&e, &eicar());
        assert_eq!(o.verdict, Verdict::Malicious);
        assert_eq!(o.detections[0].name, "AXSafe.Test.EICAR");
        assert!(o.detections[0].test_signature);
        assert!(o.detections[0].evidence[0].contains("Offset 0..68"));
    }

    #[test]
    fn eicar_with_trailing_whitespace_positive() {
        let e = YaraXEngine::from_dir(repo_rules());
        let mut d = eicar();
        d.extend_from_slice(b"\r\n");
        assert_eq!(scan(&e, &d).verdict, Verdict::Malicious);
    }

    #[test]
    fn benign_counterexamples() {
        let e = YaraXEngine::from_dir(repo_rules());
        // Teststring nicht am Anfang (z. B. in Dokumentation zitiert).
        let mut quoted = b"Der EICAR-Teststring lautet: ".to_vec();
        quoted.extend(eicar());
        assert_eq!(scan(&e, &quoted).verdict, Verdict::NoDetection);
        // Teststring am Anfang, aber in einer großen Datei.
        let mut big = eicar();
        big.extend(vec![b'A'; 200]);
        assert_eq!(scan(&e, &big).verdict, Verdict::NoDetection);
        // Gewöhnlicher Inhalt; der Name „eicar.com“ spielt keine Rolle,
        // weil der Adapter den Namen gar nicht kennt.
        assert_eq!(scan(&e, b"Hallo Welt").verdict, Verdict::NoDetection);
        assert_eq!(scan(&e, b"").verdict, Verdict::NoDetection);
    }

    #[test]
    fn rule_without_required_meta_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("bad.yar"),
            "rule NoMeta { strings: $a = \"abc\" condition: $a }",
        )
        .unwrap();
        let e = YaraXEngine::from_dir(dir.path());
        match e.info().health {
            EngineHealth::Unavailable { reason } => assert!(reason.contains("Pflichtmetadatum")),
            h => panic!("{h:?}"),
        }
        // Und ein Scan mit abgelehntem Regelsatz ist ein Fehler, nie sauber.
        assert_eq!(scan(&e, b"abc").verdict, Verdict::Error);
    }

    #[test]
    fn syntax_error_and_empty_dir_are_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            YaraXEngine::from_dir(dir.path()).info().health,
            EngineHealth::Unavailable { .. }
        ));
        std::fs::write(dir.path().join("x.yar"), "rule {").unwrap();
        assert!(matches!(
            YaraXEngine::from_dir(dir.path()).info().health,
            EngineHealth::Unavailable { .. }
        ));
    }

    #[test]
    fn too_new_min_engine_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("new.yar"),
            r#"rule Future { meta: id = "T" verdict = "suspicious" severity = "low" confidence = "low"
               author = "t" license = "CC0-1.0" source = "t" min_engine = "99.0.0"
               condition: false }"#,
        )
        .unwrap();
        match YaraXEngine::from_dir(dir.path()).info().health {
            EngineHealth::Unavailable { reason } => assert!(reason.contains("99.0.0")),
            h => panic!("{h:?}"),
        }
    }

    #[test]
    fn timeout_is_reported_as_timeout() {
        // Absichtlich teure Regel: Schleife über sehr viele Treffer.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("slow.yar"),
            r#"rule Slow { meta: id = "T-SLOW" verdict = "suspicious" severity = "low" confidence = "low"
               author = "t" license = "CC0-1.0" source = "t" min_engine = "1.0.0"
               strings: $a = "A"
               condition: for all i in (1..#a) : ( for all j in (1..#a) : ( @a[i] + @a[j] >= 0 ) ) }"#,
        )
        .unwrap();
        let e = YaraXEngine::from_dir(dir.path());
        assert_eq!(e.info().health, EngineHealth::Ready, "{:?}", e.info());
        let data = vec![b'A'; 200_000];
        let o = e.scan(&ScanInput {
            data: &data,
            kind: &FileKind::Unknown,
            sha256: "",
            timeout: Duration::from_secs(1),
        });
        assert_eq!(o.verdict, Verdict::Timeout, "{o:?}");
        assert_eq!(o.gaps[0].reason, GapReason::EngineTimeout);
    }

    #[test]
    fn pinned_version_matches_lockfile() {
        let lock =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock"))
                .unwrap()
                .replace("\r\n", "\n");
        let needle = format!("name = \"yara-x\"\nversion = \"{YARAX_VERSION}\"");
        assert!(
            lock.contains(&needle),
            "YARAX_VERSION passt nicht zu Cargo.lock"
        );
    }
}
