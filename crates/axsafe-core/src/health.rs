//! Betriebszustand aus Gesundheit ableiten (AXS-019).
//!
//! Fünf Bestandteile werden GETRENNT erfasst – Scanner, Sensor, Richtlinie,
//! Definitionen, Primärschutz – plus der Hintergrunddienst. Der Gesamtzustand
//! wird ausschließlich daraus abgeleitet:
//!
//! * „geschützt“ nur, wenn ALLE Bestandteile bereit sind (heute unmöglich:
//!   es gibt keinen Echtzeitsensor, AXSafe ist kein Primärschutz);
//! * „unbekannt“, sobald der Scanner nicht sicher beurteilt werden kann;
//! * „nicht betriebsbereit“, wenn keine Engine bereit ist;
//! * sonst „eingeschränkt“.
//!
//! Fehlende Antworten werden zu `unknown`, nie zu `ready`.

use crate::engine::{ContentKind, EngineHealth, EngineInfo};
use serde::{Deserialize, Serialize};

/// Zustand eines Bestandteils.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Ready,
    /// Arbeitet, aber eingeschränkt (z. B. veraltete Signaturen, Teilausfall).
    Degraded,
    /// Nicht vorhanden oder ausgefallen.
    Missing,
    /// Nicht feststellbar (keine oder ungültige Antwort).
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub state: State,
    pub detail: String,
}

impl Component {
    fn new(state: State, detail: impl Into<String>) -> Self {
        Component {
            state,
            detail: detail.into(),
        }
    }
}

/// Gesamtzustand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Overall {
    Geschuetzt,
    Eingeschraenkt,
    NichtBetriebsbereit,
    Unbekannt,
}

/// Was über den Hintergrunddienst bekannt ist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum ServiceObservation {
    /// Dienst hat geantwortet und ist bereit.
    Ready,
    /// Dienst ist nicht installiert.
    NotInstalled,
    /// Dienst startet (installiert, Pipe noch nicht bereit).
    Starting,
    /// Keine oder ungültige Antwort.
    NoAnswer(String),
    /// Auf diesem System gibt es keinen Dienst (nicht Windows).
    NotApplicable,
}

/// Was über die Richtlinie bekannt ist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum PolicyObservation {
    /// Gültige Richtlinie geladen (Version, Herkunft).
    Loaded(String),
    /// Richtlinie beschädigt oder ungültig; sichere Vorgabe aktiv.
    Invalid(String),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    pub schema: String,
    pub checked_utc: String,
    pub overall: Overall,
    /// Kurzer Satz für die Anzeige.
    pub summary: String,
    pub scanner: Component,
    pub sensor: Component,
    pub policy: Component,
    pub definitions: Component,
    pub primary_protection: Component,
    pub service: Component,
}

pub const HEALTH_SCHEMA: &str = "axsafe.health/1";

/// Ab diesem Alter gelten Signaturen als veraltet.
pub const DEFINITIONS_MAX_AGE_HOURS: i64 = 72;

fn worst(a: State, b: State) -> State {
    let rank = |s: State| match s {
        State::Ready => 0,
        State::Degraded => 1,
        State::Unknown => 2,
        State::Missing => 3,
    };
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

fn scanner(engines: Option<&[EngineInfo]>) -> Component {
    let Some(engines) = engines else {
        return Component::new(State::Unknown, "Engines nicht abfragbar");
    };
    if engines.is_empty() {
        return Component::new(State::Missing, "keine Engine konfiguriert");
    }
    let ready: Vec<&str> = engines
        .iter()
        .filter(|e| e.health == EngineHealth::Ready)
        .map(|e| e.name.as_str())
        .collect();
    let failed: Vec<String> = engines
        .iter()
        .filter_map(|e| match &e.health {
            EngineHealth::Unavailable { reason } => Some(format!("{}: {reason}", e.name)),
            EngineHealth::Ready => None,
        })
        .collect();
    let not_isolated: Vec<&str> = engines
        .iter()
        .filter(|e| e.health == EngineHealth::Ready && !e.isolation.enforced)
        .map(|e| e.name.as_str())
        .collect();
    if ready.is_empty() {
        return Component::new(
            State::Missing,
            format!("keine Engine bereit ({})", failed.join("; ")),
        );
    }
    let mut detail = format!("bereit: {}", ready.join(", "));
    let mut state = State::Ready;
    if !failed.is_empty() {
        state = State::Degraded;
        detail.push_str(&format!("; ausgefallen: {}", failed.join("; ")));
    }
    if !not_isolated.is_empty() {
        state = State::Degraded;
        detail.push_str(&format!(
            "; ohne nachgewiesene Abschottung: {}",
            not_isolated.join(", ")
        ));
    }
    Component::new(state, detail)
}

fn definitions(engines: Option<&[EngineInfo]>, now: chrono::DateTime<chrono::Utc>) -> Component {
    let Some(engines) = engines else {
        return Component::new(State::Unknown, "Engines nicht abfragbar");
    };
    let ready: Vec<&EngineInfo> = engines
        .iter()
        .filter(|e| e.health == EngineHealth::Ready)
        .collect();
    if ready.is_empty() {
        return Component::new(State::Missing, "keine geladenen Definitionen");
    }
    let mut state = State::Ready;
    let mut parts = Vec::new();
    for e in ready {
        let (s, d) = match e.content_kind {
            ContentKind::TestOnly => (
                State::Degraded,
                "nur Funktionstest-Regeln (keine echte Erkennung)".to_string(),
            ),
            ContentKind::Unknown => (State::Unknown, "Inhalt unbekannt".to_string()),
            ContentKind::OfficialSignatures => match e
                .content_time_utc
                .as_deref()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            {
                Some(t) => {
                    let age = now.signed_duration_since(t.with_timezone(&chrono::Utc));
                    if age.num_hours() > DEFINITIONS_MAX_AGE_HOURS {
                        (
                            State::Degraded,
                            format!(
                                "VERALTET: Stand {} ({} Tage alt)",
                                e.content_version,
                                age.num_days()
                            ),
                        )
                    } else {
                        (
                            State::Ready,
                            format!(
                                "aktuell: {} (erstellt {}, {} h alt)",
                                e.content_version,
                                t.to_rfc3339(),
                                age.num_hours().max(0)
                            ),
                        )
                    }
                }
                None => (
                    State::Unknown,
                    format!("Stand {}, Alter nicht feststellbar", e.content_version),
                ),
            },
            ContentKind::Production | ContentKind::CustomSignatures => (
                State::Ready,
                format!("eigener Bestand {}", e.content_version),
            ),
        };
        state = worst(state, s);
        parts.push(format!("{}: {d}", e.name));
    }
    Component::new(state, parts.join("; "))
}

/// Leitet den Betriebszustand ab. `engines = None` heißt: Abfrage
/// gescheitert (→ unbekannt, nie bereit).
pub fn derive(
    engines: Option<&[EngineInfo]>,
    service: &ServiceObservation,
    policy: &PolicyObservation,
    now: chrono::DateTime<chrono::Utc>,
) -> HealthReport {
    let scanner = scanner(engines);
    let definitions = definitions(engines, now);
    let sensor = Component::new(
        State::Missing,
        "kein Echtzeitsensor (Dateisystem-Minifilter folgt in Phase P08)",
    );
    let primary_protection = Component::new(
        State::Missing,
        "AXSafe ist kein Primärschutz; Microsoft Defender bleibt zuständig",
    );
    let policy = match policy {
        PolicyObservation::Loaded(d) => Component::new(State::Ready, d.clone()),
        PolicyObservation::Invalid(d) => Component::new(State::Degraded, d.clone()),
        PolicyObservation::Unknown => Component::new(State::Unknown, "Richtlinie nicht abfragbar"),
    };
    let service = match service {
        ServiceObservation::Ready => Component::new(State::Ready, "Dienst bereit"),
        ServiceObservation::NotInstalled => {
            Component::new(State::Missing, "Dienst nicht installiert")
        }
        ServiceObservation::Starting => Component::new(State::Degraded, "Dienst startet"),
        ServiceObservation::NoAnswer(d) => Component::new(
            State::Unknown,
            format!("keine gültige Antwort des Dienstes: {d}"),
        ),
        ServiceObservation::NotApplicable => Component::new(
            State::Missing,
            "kein Dienst auf diesem System (nur Windows)",
        ),
    };
    let all = [
        &scanner,
        &sensor,
        &policy,
        &definitions,
        &primary_protection,
        &service,
    ];
    let overall = if scanner.state == State::Unknown {
        Overall::Unbekannt
    } else if scanner.state == State::Missing {
        Overall::NichtBetriebsbereit
    } else if all.iter().all(|c| c.state == State::Ready) {
        Overall::Geschuetzt
    } else {
        Overall::Eingeschraenkt
    };
    let summary = match overall {
        Overall::Geschuetzt => "Geschützt".to_string(),
        Overall::Unbekannt => "Zustand unbekannt – keine Aussage über den Schutz".to_string(),
        Overall::NichtBetriebsbereit => format!("Nicht betriebsbereit: {}", scanner.detail),
        Overall::Eingeschraenkt => {
            let mut why = Vec::new();
            if sensor.state != State::Ready {
                why.push("kein Echtzeitschutz");
            }
            if definitions.state != State::Ready {
                why.push("Definitionen eingeschränkt");
            }
            if scanner.state != State::Ready {
                why.push("Engine-Teilausfall");
            }
            if service.state != State::Ready {
                why.push("Dienst nicht bereit");
            }
            if policy.state != State::Ready {
                why.push("Richtlinie nicht sicher geladen");
            }
            format!("Eingeschränkt: {}", why.join(", "))
        }
    };
    HealthReport {
        schema: HEALTH_SCHEMA.into(),
        checked_utc: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        overall,
        summary,
        scanner,
        sensor,
        policy,
        definitions,
        primary_protection,
        service,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Isolation, IsolationKind};

    fn eng(name: &str, ready: bool, kind: ContentKind, time: Option<&str>) -> EngineInfo {
        EngineInfo {
            name: name.into(),
            engine_version: "1".into(),
            content_version: "v".into(),
            health: if ready {
                EngineHealth::Ready
            } else {
                EngineHealth::Unavailable {
                    reason: "kaputt".into(),
                }
            },
            license: String::new(),
            content_kind: kind,
            content_note: String::new(),
            inspects_contents_of: vec![],
            isolation: Isolation {
                kind: IsolationKind::SandboxedWorker,
                enforced: true,
                detail: String::new(),
            },
            content_time_utc: time.map(String::from),
        }
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-25T20:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    const POL: PolicyObservation = PolicyObservation::Unknown;

    fn loaded() -> PolicyObservation {
        PolicyObservation::Loaded("Richtlinie 1".into())
    }

    /// T-019: Keine Antwort erzeugt niemals „geschützt“ oder „bereit“.
    #[test]
    fn missing_answers_are_unknown_never_green() {
        let r = derive(
            None,
            &ServiceObservation::NoAnswer("Zeit".into()),
            &POL,
            now(),
        );
        assert_eq!(r.overall, Overall::Unbekannt);
        assert_eq!(r.scanner.state, State::Unknown);
        assert_eq!(r.service.state, State::Unknown);
        assert_eq!(r.policy.state, State::Unknown);
        assert_ne!(r.definitions.state, State::Ready);
    }

    /// Kaputte Engine ändert den Zustand.
    #[test]
    fn broken_engine_changes_status() {
        let ok = [eng("yara-x", true, ContentKind::Production, None)];
        let r = derive(Some(&ok), &ServiceObservation::Ready, &loaded(), now());
        assert_eq!(r.scanner.state, State::Ready);
        let broken = [
            eng("yara-x", true, ContentKind::Production, None),
            eng("clamav", false, ContentKind::OfficialSignatures, None),
        ];
        let r = derive(Some(&broken), &ServiceObservation::Ready, &loaded(), now());
        assert_eq!(r.scanner.state, State::Degraded);
        assert!(r.scanner.detail.contains("clamav: kaputt"));
        let none = [eng("yara-x", false, ContentKind::Production, None)];
        let r = derive(Some(&none), &ServiceObservation::Ready, &loaded(), now());
        assert_eq!(r.overall, Overall::NichtBetriebsbereit);
    }

    /// Dienstabsturz (keine Antwort) ändert den Zustand.
    #[test]
    fn service_loss_changes_status() {
        let e = [eng("yara-x", true, ContentKind::Production, None)];
        let a = derive(Some(&e), &ServiceObservation::Ready, &loaded(), now());
        let b = derive(
            Some(&e),
            &ServiceObservation::NoAnswer("Pipe fehlt".into()),
            &loaded(),
            now(),
        );
        assert_eq!(a.service.state, State::Ready);
        assert_eq!(b.service.state, State::Unknown);
        assert!(b.summary.contains("Dienst nicht bereit"));
    }

    /// Ohne Sensor und Primärschutz ist der Zustand nie „geschützt“.
    #[test]
    fn without_sensor_never_protected() {
        let e = [eng(
            "clamav",
            true,
            ContentKind::OfficialSignatures,
            Some("2026-10-25T06:00:00Z"),
        )];
        let r = derive(Some(&e), &ServiceObservation::Ready, &loaded(), now());
        assert_eq!(r.sensor.state, State::Missing);
        assert_eq!(r.primary_protection.state, State::Missing);
        assert_eq!(r.overall, Overall::Eingeschraenkt);
        assert_eq!(r.definitions.state, State::Ready);
    }

    #[test]
    fn stale_or_test_definitions_are_degraded() {
        let old = [eng(
            "clamav",
            true,
            ContentKind::OfficialSignatures,
            Some("2026-10-20T06:00:00Z"),
        )];
        let r = derive(Some(&old), &ServiceObservation::Ready, &loaded(), now());
        assert_eq!(r.definitions.state, State::Degraded);
        assert!(r.definitions.detail.contains("VERALTET"));
        let test = [eng("yara-x", true, ContentKind::TestOnly, None)];
        let r = derive(Some(&test), &ServiceObservation::Ready, &loaded(), now());
        assert_eq!(r.definitions.state, State::Degraded);
        let unknown_age = [eng("clamav", true, ContentKind::OfficialSignatures, None)];
        let r = derive(
            Some(&unknown_age),
            &ServiceObservation::Ready,
            &loaded(),
            now(),
        );
        assert_eq!(r.definitions.state, State::Unknown);
    }

    #[test]
    fn unisolated_engine_is_degraded() {
        let mut e = eng("clamav", true, ContentKind::Production, None);
        e.isolation.enforced = false;
        let r = derive(Some(&[e]), &ServiceObservation::Ready, &loaded(), now());
        assert_eq!(r.scanner.state, State::Degraded);
    }

    #[test]
    fn invalid_policy_is_visible() {
        let e = [eng("yara-x", true, ContentKind::Production, None)];
        let r = derive(
            Some(&e),
            &ServiceObservation::Ready,
            &PolicyObservation::Invalid("beschädigt".into()),
            now(),
        );
        assert_eq!(r.policy.state, State::Degraded);
        assert!(r.summary.contains("Richtlinie"));
    }
}
