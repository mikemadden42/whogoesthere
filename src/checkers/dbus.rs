use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};
use crate::util::{IniDoc, canonical_unique, parse_ini, real_users};

pub struct DbusChecker;

/// System-bus service registrations — auto-activated by system D-Bus daemon
/// when any client requests the bus name. Almost always `Exec=` runs as root.
const SYSTEM_BUS_DIRS: &[&str] = &[
    "/usr/share/dbus-1/system-services",
    "/etc/dbus-1/system-services",
    "/usr/local/share/dbus-1/system-services",
];

/// Session-bus service registrations — auto-activated when any user's
/// session bus client requests the bus name. Runs as the user whose session
/// dispatched the request.
const SESSION_BUS_DIRS: &[&str] = &[
    "/usr/share/dbus-1/services",
    "/etc/dbus-1/services",
    "/usr/local/share/dbus-1/services",
];

impl Checker for DbusChecker {
    fn name(&self) -> &'static str {
        "dbus"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen: HashSet<PathBuf> = HashSet::new();

        for dir in canonical_unique(SYSTEM_BUS_DIRS) {
            findings.extend(scan_dir(&dir, "system", &Scope::System, &mut seen));
        }
        for dir in canonical_unique(SESSION_BUS_DIRS) {
            findings.extend(scan_dir(&dir, "session", &Scope::System, &mut seen));
        }

        for user in real_users() {
            let mut user_seen: HashSet<PathBuf> = HashSet::new();
            let dir = user.home.join(".local/share/dbus-1/services");
            let scope = Scope::User {
                uid: user.uid,
                name: user.name,
            };
            findings.extend(scan_dir(&dir, "session", &scope, &mut user_seen));
        }

        findings
    }
}

fn scan_dir(
    dir: &Path,
    bus: &'static str,
    scope: &Scope,
    seen: &mut HashSet<PathBuf>,
) -> Vec<Finding> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("service") {
            continue;
        }
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if !seen.insert(canonical) {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        if let Some(f) = build_finding(&parse_ini(&content), &path, bus, scope) {
            findings.push(f);
        }
    }
    findings
}

/// Build one finding per service file. D-Bus service-file structure: a single
/// `[D-BUS Service]` section with `Name=`, `Exec=`, optional `User=`
/// (system bus only), and optional `SystemdService=` (defers activation to a
/// systemd unit instead of forking `Exec`). Files without an `Exec=` AND
/// without a `SystemdService=` are skipped — they wouldn't activate
/// anything.
fn build_finding(doc: &IniDoc, source: &Path, bus: &'static str, scope: &Scope) -> Option<Finding> {
    let svc = doc.get("D-BUS Service")?;
    let exec = svc.get("Exec").and_then(|v| v.last());
    let systemd_service = svc.get("SystemdService").and_then(|v| v.last());
    let target = match (exec, systemd_service) {
        (Some(e), _) => e.clone(),
        (None, Some(s)) => format!("(activates systemd unit) {s}"),
        (None, None) => return None,
    };

    let mut metadata: BTreeMap<String, String> = BTreeMap::new();
    metadata.insert("bus".to_string(), bus.to_string());
    if let Some(name) = svc.get("Name").and_then(|v| v.last()) {
        metadata.insert("bus_name".to_string(), name.clone());
    }
    if let Some(user) = svc.get("User").and_then(|v| v.last()) {
        metadata.insert("run_as".to_string(), user.clone());
    }
    if let (Some(_), Some(s)) = (exec, systemd_service) {
        // Both set is legal — Exec= wins, but record SystemdService= as
        // metadata so the analyst sees the alternate activation path.
        metadata.insert("systemd_service".to_string(), s.clone());
    }

    Some(Finding {
        category: "dbus".to_string(),
        mechanism: format!("D-Bus {bus}-bus auto-activation"),
        source: source.to_path_buf(),
        target: Some(target),
        scope: scope.clone(),
        package: PackageOrigin::Unknown,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> Option<Finding> {
        build_finding(
            &parse_ini(content),
            Path::new("/usr/share/dbus-1/services/test.service"),
            "session",
            &Scope::System,
        )
    }

    #[test]
    fn exec_directive_yields_one_finding_with_target() {
        let content = "[D-BUS Service]
Name=org.gnome.SomeApp
Exec=/usr/libexec/some-app --gapplication-service
";
        let f = parse(content).expect("parses");
        assert_eq!(
            f.target.as_deref(),
            Some("/usr/libexec/some-app --gapplication-service")
        );
        assert_eq!(
            f.metadata.get("bus_name").map(String::as_str),
            Some("org.gnome.SomeApp")
        );
        assert_eq!(f.metadata.get("bus").map(String::as_str), Some("session"));
    }

    #[test]
    fn systemd_service_alone_activates_via_systemd_unit() {
        // No Exec= but SystemdService= — auto-activation defers to systemd.
        // Target should call this out clearly so the analyst can pivot to the
        // unit.
        let content = "[D-BUS Service]
Name=org.freedesktop.NetworkManager
SystemdService=NetworkManager.service
";
        let f = parse(content).expect("parses");
        assert_eq!(
            f.target.as_deref(),
            Some("(activates systemd unit) NetworkManager.service")
        );
    }

    #[test]
    fn user_directive_surfaces_run_as_metadata() {
        // User= is system-bus-only in practice; surface it so an analyst can
        // see whether the activation runs as root or some service account.
        let content = "[D-BUS Service]
Name=org.example.PrivilegedThing
Exec=/usr/sbin/privileged-thing
User=root
";
        let f = parse(content).expect("parses");
        assert_eq!(f.metadata.get("run_as").map(String::as_str), Some("root"));
    }

    #[test]
    fn both_exec_and_systemd_service_emits_exec_as_target_and_records_alternate() {
        // When both directives are present, dbus-daemon prefers Exec=;
        // record SystemdService= as metadata so the alternate activation
        // path is auditable.
        let content = "[D-BUS Service]
Name=org.foo.Bar
Exec=/usr/bin/foo-bar
SystemdService=foo-bar.service
";
        let f = parse(content).expect("parses");
        assert_eq!(f.target.as_deref(), Some("/usr/bin/foo-bar"));
        assert_eq!(
            f.metadata.get("systemd_service").map(String::as_str),
            Some("foo-bar.service")
        );
    }

    #[test]
    fn missing_section_returns_no_finding() {
        // No [D-BUS Service] header — not a valid service file, skip.
        let content = "[Some Other Section]
Exec=/usr/bin/whatever
";
        assert!(parse(content).is_none());
    }

    #[test]
    fn neither_exec_nor_systemd_service_returns_no_finding() {
        // Without an activation directive there's nothing for D-Bus to do
        // with this file — skip rather than emit a useless finding.
        let content = "[D-BUS Service]
Name=org.empty.NoActivation
";
        assert!(parse(content).is_none());
    }
}
