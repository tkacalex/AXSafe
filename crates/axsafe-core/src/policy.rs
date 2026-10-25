//! Richtlinien und Ausnahmen (AXS-017).
//!
//! * Die Richtlinie ist eine versionierte JSON-Datei, die nur Administratoren
//!   schreiben dürfen (Windows: `%ProgramData%\AXSafe\policy.json`, Rechte
//!   setzt `install-service.ps1`). Über die Pipe gibt es KEINE Nachricht, mit
//!   der ein Benutzer Ausnahmen setzen könnte.
//! * Ausnahmen gelten nur für eine genaue Datei oder einen eng begrenzten
//!   Ordner. Laufwerkswurzeln, Systemordner, Programmordner, Benutzerprofile
//!   und Platzhalter werden abgelehnt. Jede Ausnahme braucht Grund, Urheber
//!   und Ablaufzeit (höchstens 90 Tage); abgelaufene gelten nicht.
//! * Eine beschädigte Richtlinie wird NICHT teilweise angewandt: Es gilt die
//!   sichere Vorgabe ohne Ausnahmen, und der Zustand „Richtlinie ungültig“ ist
//!   sichtbar (Betriebszustand, Bericht).
//! * Ausgenommene Objekte stehen im Bericht (`scope.excluded`) und machen den
//!   Auftrag unvollständig (Lücke `excluded_by_policy`) – verringerte
//!   Abdeckung, nie „vollständig geprüft“.

use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

pub const POLICY_SCHEMA: &str = "axsafe.policy/1";
/// Anfang jedes Ausschlussgrunds aus der Richtlinie (im Bericht).
pub const EXCLUSION_PREFIX: &str = "Ausnahme der Richtlinie";
/// Längste erlaubte Gültigkeit einer Ausnahme.
pub const MAX_EXCLUSION_DAYS: i64 = 90;
pub const MAX_EXCLUSIONS: usize = 100;
/// Größe der Richtliniendatei (Schutz vor unsinnig großen Dateien).
pub const MAX_POLICY_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionKind {
    /// Genau diese Datei.
    Datei,
    /// Dieser Ordner mit Inhalt (nur eng begrenzt).
    Ordner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    pub kind: ExclusionKind,
    pub path: String,
    pub reason: String,
    pub created_by: String,
    pub created_utc: String,
    pub expires_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub schema: String,
    /// Fortlaufende Versionsnummer (jede Änderung erhöht sie).
    pub version: u64,
    #[serde(default)]
    pub exclusions: Vec<Exclusion>,
}

/// Geltende Richtlinie nach Prüfung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// z. B. `policy-file-v3` oder `vorgabe`.
    pub version: String,
    pub source: String,
    pub exclusions: Vec<Exclusion>,
    /// Abgelaufene Ausnahmen (nicht angewandt, nur Hinweis).
    pub expired: usize,
    /// `Some`, wenn die Datei ungültig war und die Vorgabe gilt.
    pub invalid: Option<String>,
}

impl Policy {
    /// Sichere Vorgabe: keine Ausnahmen.
    pub fn default_policy(source: &str) -> Policy {
        Policy {
            version: "vorgabe".into(),
            source: source.into(),
            exclusions: Vec::new(),
            expired: 0,
            invalid: None,
        }
    }

    pub fn observation(&self) -> crate::health::PolicyObservation {
        match &self.invalid {
            Some(e) => crate::health::PolicyObservation::Invalid(format!(
                "Richtlinie ungültig, sichere Vorgabe ohne Ausnahmen aktiv: {e}"
            )),
            None => crate::health::PolicyObservation::Loaded(format!(
                "Richtlinie {} ({}), {} Ausnahme(n){}",
                self.version,
                self.source,
                self.exclusions.len(),
                if self.expired > 0 {
                    format!(", {} abgelaufen (nicht angewandt)", self.expired)
                } else {
                    String::new()
                }
            )),
        }
    }

    /// Passt eine Ausnahme auf diesen Pfad? Liefert den Grund für den Bericht.
    pub fn exclusion_for(&self, path: &Path) -> Option<String> {
        let p = normalize(path)?;
        for x in &self.exclusions {
            let Some(xp) = normalize(Path::new(&x.path)) else {
                continue;
            };
            let hit = match x.kind {
                ExclusionKind::Datei => p == xp,
                ExclusionKind::Ordner => p.starts_with(&xp),
            };
            if hit {
                return Some(format!(
                    "{EXCLUSION_PREFIX} {} ({:?} {}): {} – von {}, gültig bis {}",
                    self.version, x.kind, x.path, x.reason, x.created_by, x.expires_utc
                ));
            }
        }
        None
    }
}

/// Vergleichsform eines Pfads: absolut, ohne `.`/`..`, unter Windows
/// Kleinbuchstaben. `None` für relative oder ungültige Pfade.
fn normalize(p: &Path) -> Option<Vec<String>> {
    if !p.is_absolute() {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    for c in p.components() {
        match c {
            Component::Prefix(x) => out.push(fold(&x.as_os_str().to_string_lossy())),
            Component::RootDir => out.push(String::from("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop()?;
            }
            Component::Normal(n) => out.push(fold(&n.to_string_lossy())),
        }
    }
    Some(out)
}

fn fold(s: &str) -> String {
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s.to_string()
    }
}

/// Orte, die nie (auch nicht teilweise oberhalb) ausgenommen werden dürfen.
fn protected_roots() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if cfg!(windows) {
        for k in [
            "SystemRoot",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramData",
            "USERPROFILE",
            "PUBLIC",
        ] {
            if let Some(x) = std::env::var_os(k) {
                v.push(PathBuf::from(x));
            }
        }
        v.push(PathBuf::from(r"C:\Users"));
        v.push(PathBuf::from(r"C:\Windows"));
    } else {
        for x in [
            "/", "/home", "/root", "/usr", "/etc", "/var", "/tmp", "/opt",
        ] {
            v.push(PathBuf::from(x));
        }
        if let Some(h) = std::env::var_os("HOME") {
            v.push(PathBuf::from(h));
        }
    }
    v
}

/// Prüft eine Ausnahme. Fehler = Ausnahme wird abgelehnt.
pub fn validate_exclusion(
    x: &Exclusion,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool /* gültig (nicht abgelaufen) */, String> {
    if x.path.contains(['*', '?']) {
        return Err(format!("{}: Platzhalter sind nicht erlaubt", x.path));
    }
    if x.reason.trim().len() < 5 {
        return Err(format!("{}: Grund fehlt oder ist zu kurz", x.path));
    }
    if x.created_by.trim().is_empty() {
        return Err(format!("{}: Urheber fehlt", x.path));
    }
    let created = chrono::DateTime::parse_from_rfc3339(&x.created_utc)
        .map_err(|_| format!("{}: created_utc ist keine RFC-3339-Zeit", x.path))?;
    let expires = chrono::DateTime::parse_from_rfc3339(&x.expires_utc)
        .map_err(|_| format!("{}: expires_utc ist keine RFC-3339-Zeit", x.path))?;
    if expires <= created {
        return Err(format!(
            "{}: Ablauf liegt nicht nach der Erstellung",
            x.path
        ));
    }
    if (expires - created).num_days() > MAX_EXCLUSION_DAYS {
        return Err(format!(
            "{}: Gültigkeit länger als {MAX_EXCLUSION_DAYS} Tage",
            x.path
        ));
    }
    let p = Path::new(&x.path);
    let n = normalize(p).ok_or_else(|| format!("{}: kein absoluter Pfad", x.path))?;
    // Laufwerkswurzel bzw. "/" plus mindestens zwei Ebenen.
    let depth = n.len();
    let min_depth = if cfg!(windows) { 4 } else { 3 };
    if x.kind == ExclusionKind::Ordner && depth < min_depth {
        return Err(format!(
            "{}: Ordner zu weit oben (global) – nur eng begrenzte Ordner sind erlaubt",
            x.path
        ));
    }
    for root in protected_roots() {
        let Some(r) = normalize(&root) else { continue };
        // Die geschützte Wurzel selbst oder ein Ordner darüber: abgelehnt.
        if x.kind == ExclusionKind::Ordner && (r.starts_with(&n) || n == r) {
            return Err(format!(
                "{}: umfasst den geschützten Ort {} – nicht erlaubt",
                x.path,
                root.display()
            ));
        }
    }
    // Systemordner: auch einzelne Dateien und Unterordner nicht ausnehmen.
    for sys in system_dirs() {
        if let Some(s) = normalize(&sys) {
            if n.starts_with(&s) {
                return Err(format!(
                    "{}: liegt im Systemordner {} – nicht erlaubt",
                    x.path,
                    sys.display()
                ));
            }
        }
    }
    Ok(expires > now)
}

fn system_dirs() -> Vec<PathBuf> {
    if cfg!(windows) {
        let mut v = vec![PathBuf::from(r"C:\Windows")];
        if let Some(x) = std::env::var_os("SystemRoot") {
            v.push(PathBuf::from(x));
        }
        v
    } else {
        vec![PathBuf::from("/usr"), PathBuf::from("/etc")]
    }
}

/// Prüft den Inhalt einer Richtliniendatei.
pub fn parse_policy(
    text: &str,
    source: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Policy, String> {
    let f: PolicyFile =
        serde_json::from_str(text).map_err(|e| format!("Richtlinie nicht lesbar: {e}"))?;
    if f.schema != POLICY_SCHEMA {
        return Err(format!(
            "Schema {} nicht unterstützt (erwartet {POLICY_SCHEMA})",
            f.schema
        ));
    }
    if f.version == 0 {
        return Err("Version 0 ist ungültig".into());
    }
    if f.exclusions.len() > MAX_EXCLUSIONS {
        return Err(format!("mehr als {MAX_EXCLUSIONS} Ausnahmen"));
    }
    let mut active = Vec::new();
    let mut expired = 0;
    for x in f.exclusions {
        // Eine einzige unzulässige Ausnahme macht die ganze Datei ungültig:
        // keine teilweise Anwendung.
        if validate_exclusion(&x, now)? {
            active.push(x);
        } else {
            expired += 1;
        }
    }
    Ok(Policy {
        version: format!("policy-file-v{}", f.version),
        source: source.into(),
        exclusions: active,
        expired,
        invalid: None,
    })
}

/// Lädt die Richtlinie. Fehlt die Datei: Vorgabe. Ist sie ungültig: Vorgabe
/// mit sichtbarem Fehler.
pub fn load_policy(path: &Path, now: chrono::DateTime<chrono::Utc>) -> Policy {
    let source = path.display().to_string();
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Policy::default_policy(&format!("{source} nicht vorhanden"));
        }
        Err(e) => {
            let mut p = Policy::default_policy(&source);
            p.invalid = Some(format!("nicht lesbar: {e}"));
            return p;
        }
    };
    if meta.len() > MAX_POLICY_BYTES {
        let mut p = Policy::default_policy(&source);
        p.invalid = Some(format!("größer als {MAX_POLICY_BYTES} Bytes"));
        return p;
    }
    match std::fs::read_to_string(path)
        .map_err(|e| format!("nicht lesbar: {e}"))
        .and_then(|t| parse_policy(&t, &source, now))
    {
        Ok(p) => p,
        Err(e) => {
            let mut p = Policy::default_policy(&source);
            p.invalid = Some(e);
            p
        }
    }
}

/// Wie [`load_policy`], wendet die Datei aber nur an, wenn `only_admins`
/// für Datei UND Ordner bestätigt, dass nur Administratoren sie verändern
/// können. Sonst gilt die Vorgabe ohne Ausnahmen, mit sichtbarem Fehler –
/// ein Standardbenutzer kann so keine Ausnahme einschleusen.
pub fn load_policy_checked(
    path: &Path,
    now: chrono::DateTime<chrono::Utc>,
    only_admins: impl Fn(&Path) -> std::io::Result<Result<(), String>>,
) -> Policy {
    if !path.exists() {
        return load_policy(path, now);
    }
    let source = path.display().to_string();
    let mut targets = vec![path.to_path_buf()];
    if let Some(d) = path.parent() {
        targets.push(d.to_path_buf());
    }
    for t in targets {
        let verdict = match only_admins(&t) {
            Ok(Ok(())) => continue,
            Ok(Err(why)) => format!(
                "unsicher, {} ist nicht nur für Administratoren änderbar: {why}",
                t.display()
            ),
            Err(e) => format!("Rechte von {} nicht prüfbar: {e}", t.display()),
        };
        let mut p = Policy::default_policy(&source);
        p.invalid = Some(verdict);
        return p;
    }
    load_policy(path, now)
}

/// Standardort der Richtlinie.
pub fn default_policy_path() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("AXSafe")
            .join("Policy")
            .join("policy.json")
    } else {
        PathBuf::from("/etc/axsafe/policy.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-25T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn x(kind: ExclusionKind, path: &str) -> Exclusion {
        Exclusion {
            kind,
            path: path.into(),
            reason: "Build-Ausgabe, wird ständig neu erzeugt".into(),
            created_by: "Administrator".into(),
            created_utc: "2026-10-20T00:00:00Z".into(),
            expires_utc: "2026-11-20T00:00:00Z".into(),
        }
    }

    fn base() -> &'static str {
        if cfg!(windows) {
            r"D:\Projekte\app\build\out"
        } else {
            "/srv/projekte/app/build"
        }
    }

    /// T-017: globale Ausschlüsse werden abgelehnt.
    #[test]
    fn global_exclusions_are_refused() {
        let roots: Vec<&str> = if cfg!(windows) {
            vec![
                r"C:\",
                r"D:\",
                r"C:\Users",
                r"C:\Program Files",
                r"C:\Windows\System32",
            ]
        } else {
            vec!["/", "/home", "/usr/bin", "/srv"]
        };
        for r in roots {
            let e = validate_exclusion(&x(ExclusionKind::Ordner, r), now());
            assert!(e.is_err(), "{r} wurde akzeptiert");
        }
        assert!(validate_exclusion(&x(ExclusionKind::Datei, "C:/*.exe"), now()).is_err());
        assert!(validate_exclusion(&x(ExclusionKind::Ordner, "relativ/pfad"), now()).is_err());
    }

    #[test]
    fn narrow_exclusion_needs_reason_author_and_expiry() {
        assert_eq!(
            validate_exclusion(&x(ExclusionKind::Ordner, base()), now()),
            Ok(true)
        );
        let mut e = x(ExclusionKind::Ordner, base());
        e.reason = "".into();
        assert!(validate_exclusion(&e, now()).is_err());
        let mut e = x(ExclusionKind::Ordner, base());
        e.expires_utc = "2027-12-01T00:00:00Z".into();
        assert!(validate_exclusion(&e, now()).is_err(), "über 90 Tage");
        let mut e = x(ExclusionKind::Ordner, base());
        e.expires_utc = "2026-10-21T00:00:00Z".into();
        assert_eq!(validate_exclusion(&e, now()), Ok(false), "abgelaufen");
    }

    #[test]
    fn invalid_file_falls_back_to_safe_default_visibly() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("policy.json");
        std::fs::write(&p, "{ kaputt").unwrap();
        let pol = load_policy(&p, now());
        assert!(pol.exclusions.is_empty());
        assert!(pol.invalid.is_some());
        assert!(matches!(
            pol.observation(),
            crate::health::PolicyObservation::Invalid(_)
        ));
        // Eine unzulässige Ausnahme macht die ganze Datei ungültig.
        let f = PolicyFile {
            schema: POLICY_SCHEMA.into(),
            version: 2,
            exclusions: vec![
                x(ExclusionKind::Ordner, base()),
                x(
                    ExclusionKind::Ordner,
                    if cfg!(windows) { r"C:\" } else { "/" },
                ),
            ],
        };
        std::fs::write(&p, serde_json::to_string(&f).unwrap()).unwrap();
        let pol = load_policy(&p, now());
        assert!(pol.exclusions.is_empty());
        assert!(pol.invalid.is_some());
        // Unbekannte Felder (z. B. ein erfundenes "global": true) sind ungültig.
        std::fs::write(
            &p,
            r#"{"schema":"axsafe.policy/1","version":1,"global_exclude":true}"#,
        )
        .unwrap();
        assert!(load_policy(&p, now()).invalid.is_some());
    }

    /// T-017: Eine Datei, die ein Standardbenutzer schreiben kann, wird nie
    /// angewandt – auch wenn ihr Inhalt gültig ist.
    #[test]
    fn user_writable_policy_is_never_applied() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("policy.json");
        let f = PolicyFile {
            schema: POLICY_SCHEMA.into(),
            version: 4,
            exclusions: vec![x(ExclusionKind::Ordner, base())],
        };
        std::fs::write(&p, serde_json::to_string(&f).unwrap()).unwrap();
        let pol = load_policy_checked(&p, now(), |_| Ok(Err("Benutzer darf schreiben".into())));
        assert!(pol.exclusions.is_empty());
        assert!(pol.invalid.as_deref().unwrap().contains("unsicher"));
        let pol = load_policy_checked(&p, now(), |_| Ok(Ok(())));
        assert_eq!(pol.exclusions.len(), 1);
    }

    #[test]
    fn missing_file_is_default_without_exclusions() {
        let pol = load_policy(Path::new("/gibt/es/nicht/policy.json"), now());
        assert_eq!(pol.version, "vorgabe");
        assert!(pol.invalid.is_none());
        assert!(pol.exclusions.is_empty());
    }

    #[test]
    fn exclusion_matches_exact_file_or_folder_only() {
        let f = PolicyFile {
            schema: POLICY_SCHEMA.into(),
            version: 3,
            exclusions: vec![x(ExclusionKind::Ordner, base())],
        };
        let pol = parse_policy(&serde_json::to_string(&f).unwrap(), "test", now()).unwrap();
        assert_eq!(pol.version, "policy-file-v3");
        let inside = Path::new(base()).join("a.bin");
        assert!(pol.exclusion_for(&inside).is_some());
        let sibling = PathBuf::from(format!("{}2", base())).join("a.bin");
        assert!(
            pol.exclusion_for(&sibling).is_none(),
            "Präfix ist kein Ordner"
        );
        let escape = Path::new(base()).join("..").join("x.bin");
        assert!(
            pol.exclusion_for(&escape).is_none(),
            ".. verlässt den Ordner"
        );
    }
}
