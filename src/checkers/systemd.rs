use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};
use crate::util::{canonical_unique, real_users};

pub struct SystemdChecker;

const SYSTEM_UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
];

const GLOBAL_USER_UNIT_DIRS: &[&str] = &[
    "/etc/systemd/user",
    "/run/systemd/user",
    "/lib/systemd/user",
    "/usr/lib/systemd/user",
];

const UNIT_EXTS: &[&str] = &["service", "timer", "path", "socket"];

impl Checker for SystemdChecker {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut system_seen: HashSet<PathBuf> = HashSet::new();

        for dir in canonical_unique(SYSTEM_UNIT_DIRS) {
            findings.extend(scan_unit_dir(
                &dir,
                &mut system_seen,
                &Scope::System,
                "system",
            ));
        }
        for dir in canonical_unique(GLOBAL_USER_UNIT_DIRS) {
            findings.extend(scan_unit_dir(
                &dir,
                &mut system_seen,
                &Scope::System,
                "user-global",
            ));
        }

        for user in real_users() {
            let mut user_seen: HashSet<PathBuf> = HashSet::new();
            let dir = user.home.join(".config/systemd/user");
            let scope = Scope::User {
                uid: user.uid,
                name: user.name,
            };
            findings.extend(scan_unit_dir(&dir, &mut user_seen, &scope, "user-personal"));
        }

        findings
    }
}

fn scan_unit_dir(
    dir: &Path,
    seen: &mut HashSet<PathBuf>,
    scope: &Scope,
    location: &'static str,
) -> Vec<Finding> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        // Drop-in dirs like foo.service.d/ hold *.conf override fragments that
        // can add ExecStart=, OnCalendar=, Listen=, etc. to the base unit. A
        // malicious override in /etc/systemd/system/foo.service.d/ is a real
        // persistence vector and the conf file's path is what gets attributed.
        if path.is_dir() && is_dropin_dir(&path) {
            findings.extend(scan_dropin_dir(&path, seen, scope, location));
            continue;
        }
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !UNIT_EXTS.contains(&ext) {
            continue;
        }
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if !seen.insert(canonical) {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let unit = parse_ini(&content);
        findings.extend(emit_findings(&unit, &path, ext, scope, location));
    }
    findings
}

/// True for `<unit>.<ext>.d` where `<ext>` is one of our surveyed unit types.
/// Filters out the unrelated `*.wants/` and `*.requires/` symlink farms that
/// also live in unit dirs.
fn is_dropin_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(unit_name) = name.strip_suffix(".d") else {
        return false;
    };
    Path::new(unit_name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| UNIT_EXTS.contains(&ext))
}

fn scan_dropin_dir(
    dir: &Path,
    seen: &mut HashSet<PathBuf>,
    scope: &Scope,
    location: &'static str,
) -> Vec<Finding> {
    let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let Some(unit_name) = name.strip_suffix(".d") else {
        return Vec::new();
    };
    let Some(ext) = Path::new(unit_name).extension().and_then(|e| e.to_str()) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if !seen.insert(canonical) {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let unit = parse_ini(&content);
        let mut emitted = emit_findings(&unit, &path, ext, scope, location);
        for f in &mut emitted {
            f.metadata
                .insert("overrides".to_string(), unit_name.to_string());
            if let Some(idx) = f.mechanism.rfind(" (") {
                f.mechanism.insert_str(idx, " override");
            }
        }
        findings.extend(emitted);
    }
    findings
}

// ─── INI parser ──────────────────────────────────────────────────────────────

type Section = BTreeMap<String, Vec<String>>;
type Unit = BTreeMap<String, Section>;

fn parse_ini(content: &str) -> Unit {
    let mut unit: Unit = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current = Some(trimmed[1..trimmed.len() - 1].to_string());
            continue;
        }
        let Some(section) = &current else { continue };
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        unit.entry(section.clone())
            .or_default()
            .entry(key.trim().to_string())
            .or_default()
            .push(value.trim().to_string());
    }
    unit
}

// ─── finding emission per unit type ──────────────────────────────────────────

fn emit_findings(
    unit: &Unit,
    source: &Path,
    ext: &str,
    scope: &Scope,
    location: &str,
) -> Vec<Finding> {
    match ext {
        "service" => emit_service(unit, source, scope, location),
        "timer" => emit_timer(unit, source, scope, location),
        "path" => emit_path(unit, source, scope, location),
        "socket" => emit_socket(unit, source, scope, location),
        _ => Vec::new(),
    }
}

fn emit_service(unit: &Unit, source: &Path, scope: &Scope, location: &str) -> Vec<Finding> {
    let Some(svc) = unit.get("Service") else {
        return Vec::new();
    };
    // Order chosen to reflect lifecycle, not alphabet.
    let exec_keys: &[&str] = &[
        "ExecCondition",
        "ExecStartPre",
        "ExecStart",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
    ];
    let mut findings = Vec::new();
    for key in exec_keys {
        let Some(values) = svc.get(*key) else {
            continue;
        };
        for value in values {
            let value = value.trim();
            if value.is_empty() {
                // An explicit empty value resets the directive — not a finding.
                continue;
            }
            let mut metadata = base_metadata(unit, location);
            metadata.insert("directive".to_string(), key.to_string());
            if let Some(t) = svc.get("Type").and_then(|v| v.last()) {
                metadata.insert("service_type".to_string(), t.clone());
            }
            if let Some(u) = svc.get("User").and_then(|v| v.last()) {
                metadata.insert("run_as".to_string(), u.clone());
            }
            findings.push(Finding {
                category: "systemd".to_string(),
                mechanism: format!("systemd service {key}= ({location})"),
                source: source.to_path_buf(),
                target: Some(value.to_string()),
                scope: scope.clone(),
                package: PackageOrigin::Unknown,
                metadata,
            });
        }
    }
    findings
}

fn emit_timer(unit: &Unit, source: &Path, scope: &Scope, location: &str) -> Vec<Finding> {
    let Some(tmr) = unit.get("Timer") else {
        return Vec::new();
    };
    let trigger_keys: &[&str] = &[
        "OnCalendar",
        "OnBootSec",
        "OnStartupSec",
        "OnActiveSec",
        "OnUnitActiveSec",
        "OnUnitInactiveSec",
    ];
    let bits = collect_keys(tmr, trigger_keys);
    if bits.is_empty() {
        return Vec::new();
    }
    let mut metadata = base_metadata(unit, location);
    if let Some(p) = tmr.get("Persistent").and_then(|v| v.last()) {
        metadata.insert("persistent".to_string(), p.clone());
    }
    if let Some(a) = activated_unit_name(unit, source, "Timer", "Unit") {
        metadata.insert("activates".to_string(), a);
    }
    vec![Finding {
        category: "systemd".to_string(),
        mechanism: format!("systemd timer ({location})"),
        source: source.to_path_buf(),
        target: Some(bits.join("; ")),
        scope: scope.clone(),
        package: PackageOrigin::Unknown,
        metadata,
    }]
}

fn emit_path(unit: &Unit, source: &Path, scope: &Scope, location: &str) -> Vec<Finding> {
    let Some(p) = unit.get("Path") else {
        return Vec::new();
    };
    let trigger_keys: &[&str] = &[
        "PathExists",
        "PathExistsGlob",
        "PathChanged",
        "PathModified",
        "DirectoryNotEmpty",
    ];
    let bits = collect_keys(p, trigger_keys);
    if bits.is_empty() {
        return Vec::new();
    }
    let mut metadata = base_metadata(unit, location);
    if let Some(a) = activated_unit_name(unit, source, "Path", "Unit") {
        metadata.insert("activates".to_string(), a);
    }
    vec![Finding {
        category: "systemd".to_string(),
        mechanism: format!("systemd path watcher ({location})"),
        source: source.to_path_buf(),
        target: Some(bits.join("; ")),
        scope: scope.clone(),
        package: PackageOrigin::Unknown,
        metadata,
    }]
}

fn emit_socket(unit: &Unit, source: &Path, scope: &Scope, location: &str) -> Vec<Finding> {
    let Some(s) = unit.get("Socket") else {
        return Vec::new();
    };
    let trigger_keys: &[&str] = &[
        "ListenStream",
        "ListenDatagram",
        "ListenSequentialPacket",
        "ListenFIFO",
        "ListenSpecial",
        "ListenNetlink",
        "ListenMessageQueue",
        "ListenUSBFunction",
    ];
    let bits = collect_keys(s, trigger_keys);
    if bits.is_empty() {
        return Vec::new();
    }
    let mut metadata = base_metadata(unit, location);
    if let Some(a) = activated_unit_name(unit, source, "Socket", "Service") {
        metadata.insert("activates".to_string(), a);
    }
    vec![Finding {
        category: "systemd".to_string(),
        mechanism: format!("systemd socket activation ({location})"),
        source: source.to_path_buf(),
        target: Some(bits.join("; ")),
        scope: scope.clone(),
        package: PackageOrigin::Unknown,
        metadata,
    }]
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn collect_keys(section: &Section, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for k in keys {
        if let Some(vals) = section.get(*k) {
            for v in vals {
                out.push(format!("{k}={v}"));
            }
        }
    }
    out
}

fn base_metadata(unit: &Unit, location: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("location".to_string(), location.to_string());
    if let Some(d) = unit
        .get("Unit")
        .and_then(|s| s.get("Description"))
        .and_then(|v| v.last())
    {
        m.insert("description".to_string(), d.clone());
    }
    if let Some(install) = unit.get("Install") {
        for (key, lower) in &[("WantedBy", "wanted_by"), ("RequiredBy", "required_by")] {
            if let Some(vals) = install.get(*key)
                && !vals.is_empty()
            {
                m.insert(lower.to_string(), vals.join(", "));
            }
        }
    }
    m
}

/// Resolves which unit a timer/path/socket activates.
/// Default per systemd: same basename, .service extension.
/// Override via [Timer]Unit= / [Path]Unit= / [Socket]Service=.
fn activated_unit_name(unit: &Unit, source: &Path, section: &str, key: &str) -> Option<String> {
    if let Some(v) = unit
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(|v| v.last())
    {
        return Some(v.clone());
    }
    let stem = source.file_stem()?.to_str()?;
    Some(format!("{stem}.service"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropin_dirs_match_known_unit_extensions() {
        assert!(is_dropin_dir(Path::new(
            "/etc/systemd/system/sshd.service.d"
        )));
        assert!(is_dropin_dir(Path::new("/etc/systemd/system/foo.timer.d")));
        assert!(is_dropin_dir(Path::new("/etc/systemd/system/foo.path.d")));
        assert!(is_dropin_dir(Path::new("/etc/systemd/system/foo.socket.d")));
    }

    #[test]
    fn parse_ini_captures_sections_and_repeated_keys() {
        let content = "\
[Unit]
Description=My Service

[Service]
Type=simple
ExecStart=/usr/bin/foo
ExecStart=/usr/bin/bar
";
        let unit = parse_ini(content);
        assert_eq!(
            unit.get("Unit").unwrap().get("Description").unwrap(),
            &vec!["My Service".to_string()]
        );
        assert_eq!(
            unit.get("Service").unwrap().get("Type").unwrap(),
            &vec!["simple".to_string()]
        );
        // ExecStart appears twice — both captured. The list-valued semantics
        // are load-bearing for emit_service, which emits one finding per value.
        assert_eq!(
            unit.get("Service").unwrap().get("ExecStart").unwrap(),
            &vec!["/usr/bin/foo".to_string(), "/usr/bin/bar".to_string()]
        );
    }

    #[test]
    fn parse_ini_skips_comments_blanks_and_pre_section_lines() {
        let content = "\
# hash comment outside any section
; semicolon comment outside any section
OrphanKeyBeforeSection=ignored

[Service]
# in-section hash comment
; in-section semicolon comment

ExecStart=/usr/bin/foo
";
        let unit = parse_ini(content);
        // No phantom empty-named section from the orphan line.
        assert!(!unit.contains_key(""));
        assert_eq!(unit.len(), 1);
        assert_eq!(
            unit.get("Service").unwrap().get("ExecStart").unwrap(),
            &vec!["/usr/bin/foo".to_string()]
        );
    }

    #[test]
    fn parse_ini_trims_whitespace_around_key_and_value() {
        let content = "[Service]\n  ExecStart =   /usr/bin/foo  \n";
        let unit = parse_ini(content);
        assert_eq!(
            unit.get("Service").unwrap().get("ExecStart").unwrap(),
            &vec!["/usr/bin/foo".to_string()]
        );
    }

    #[test]
    fn activated_unit_name_defaults_to_filename_with_dot_service() {
        let unit = Unit::new();
        let path = Path::new("/etc/systemd/system/foo.timer");
        assert_eq!(
            activated_unit_name(&unit, path, "Timer", "Unit"),
            Some("foo.service".to_string())
        );
    }

    #[test]
    fn activated_unit_name_honors_explicit_override() {
        let mut unit = Unit::new();
        let mut sec = Section::new();
        sec.insert("Unit".to_string(), vec!["bar.service".to_string()]);
        unit.insert("Timer".to_string(), sec);
        let path = Path::new("/etc/systemd/system/foo.timer");
        assert_eq!(
            activated_unit_name(&unit, path, "Timer", "Unit"),
            Some("bar.service".to_string())
        );
    }

    #[test]
    fn activated_unit_name_picks_last_when_key_repeats() {
        let mut unit = Unit::new();
        let mut sec = Section::new();
        sec.insert(
            "Service".to_string(),
            vec!["first.service".to_string(), "last.service".to_string()],
        );
        unit.insert("Socket".to_string(), sec);
        let path = Path::new("/etc/systemd/system/foo.socket");
        assert_eq!(
            activated_unit_name(&unit, path, "Socket", "Service"),
            Some("last.service".to_string())
        );
    }

    #[test]
    fn rejects_wants_requires_and_unsurveyed_unit_types() {
        // multi-user.target.wants/ and foo.service.wants/ are symlink farms,
        // not drop-ins.
        assert!(!is_dropin_dir(Path::new(
            "/etc/systemd/system/multi-user.target.wants"
        )));
        assert!(!is_dropin_dir(Path::new(
            "/etc/systemd/system/sshd.service.wants"
        )));
        // Targets and slices aren't surveyed, so their drop-ins aren't either.
        assert!(!is_dropin_dir(Path::new(
            "/etc/systemd/system/multi-user.target.d"
        )));
        assert!(!is_dropin_dir(Path::new(
            "/usr/lib/systemd/system/system.slice.d"
        )));
        // A bare `.d` suffix with no unit extension is not a drop-in.
        assert!(!is_dropin_dir(Path::new("/etc/systemd/system/foo.d")));
    }
}
