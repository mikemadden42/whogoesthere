use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};

pub struct InitChecker;

impl Checker for InitChecker {
    fn name(&self) -> &'static str {
        "init"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_initd());
        if let Some(f) = scan_rc_local() {
            findings.push(f);
        }
        findings.extend(scan_inittab());
        findings
    }
}

fn scan_initd() -> Vec<Finding> {
    // /etc/init.d may be a symlink to /etc/rc.d/init.d on RHEL/Fedora — canonicalize.
    let path = Path::new("/etc/init.d");
    let dir = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };

    let runlevel_map = build_runlevel_map();
    let mut findings = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Skip non-service files commonly found in init.d
        if name == "README" || name == "skeleton" || name.starts_with('.') {
            continue;
        }
        let mode = meta.permissions().mode();
        let executable = mode & 0o111 != 0;

        let mut metadata = BTreeMap::new();
        metadata.insert("size_bytes".to_string(), meta.len().to_string());
        metadata.insert("executable".to_string(), executable.to_string());
        if let Some(rls) = runlevel_map.get(name) {
            metadata.insert("enabled".to_string(), rls.join(", "));
        }

        findings.push(Finding {
            category: "init",
            mechanism: "SysV init script".to_string(),
            source: path,
            target: None,
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata,
        });
    }
    findings
}

/// Map of script-name → list of runlevel actions (e.g. "rc3 start", "rc5 start").
/// rc{0..6}.d/ contain symlinks like S99name (start) or K01name (stop), pointing
/// to scripts in init.d/. The presence of a symlink means the script is enabled
/// for that runlevel; the action is encoded by the prefix.
fn build_runlevel_map() -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for level in 0..=6 {
        let dir = format!("/etc/rc{level}.d");
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let fname = fname.to_string_lossy();
            if fname.len() < 4 {
                continue;
            }
            let action = match fname.chars().next() {
                Some('S') => "start",
                Some('K') => "stop",
                _ => continue,
            };
            // S99name / K01name: prefix is 3 chars (S/K + 2-digit order)
            let script_name = &fname[3..];
            map.entry(script_name.to_string())
                .or_default()
                .push(format!("rc{level} {action}"));
        }
    }
    map
}

fn scan_rc_local() -> Option<Finding> {
    let path = Path::new("/etc/rc.local");
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() == 0 {
        return None;
    }
    let mode = meta.permissions().mode();
    let executable = mode & 0o111 != 0;

    let mut metadata = BTreeMap::new();
    metadata.insert("size_bytes".to_string(), meta.len().to_string());
    metadata.insert("executable".to_string(), executable.to_string());
    if !executable {
        metadata.insert(
            "note".to_string(),
            "non-executable — present but won't run at boot".to_string(),
        );
    }

    Some(Finding {
        category: "init",
        mechanism: "/etc/rc.local — runs on boot if executable".to_string(),
        source: path.to_path_buf(),
        target: None,
        scope: Scope::System,
        package: PackageOrigin::Unknown,
        metadata,
    })
}

fn scan_inittab() -> Vec<Finding> {
    let path = Path::new("/etc/inittab");
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Format: id:runlevels:action:process
        let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
        if parts.len() < 4 {
            continue;
        }
        let process = parts[3].trim();
        // initdefault has no process; skip rows where process is empty
        if process.is_empty() {
            continue;
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("id".to_string(), parts[0].to_string());
        metadata.insert("runlevels".to_string(), parts[1].to_string());
        metadata.insert("action".to_string(), parts[2].to_string());
        metadata.insert("line".to_string(), (lineno + 1).to_string());

        findings.push(Finding {
            category: "init",
            mechanism: format!("inittab `{}`", parts[2]),
            source: path.to_path_buf(),
            target: Some(process.to_string()),
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata,
        });
    }
    findings
}
