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
                category: "systemd",
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
        category: "systemd",
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
        category: "systemd",
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
        category: "systemd",
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
