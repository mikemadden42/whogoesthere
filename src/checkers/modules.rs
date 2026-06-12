use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};
use crate::util::canonical_unique;

pub struct ModulesChecker;

const LOAD_DIRS: &[&str] = &[
    "/etc/modules-load.d",
    "/usr/lib/modules-load.d",
    "/run/modules-load.d",
];

const PROBE_DIRS: &[&str] = &[
    "/etc/modprobe.d",
    "/usr/lib/modprobe.d",
    "/lib/modprobe.d",
    "/run/modprobe.d",
];

impl Checker for ModulesChecker {
    fn name(&self) -> &'static str {
        "modules"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Debian/Ubuntu legacy /etc/modules
        if let Ok(content) = fs::read_to_string("/etc/modules") {
            findings.extend(parse_module_list(
                &content,
                Path::new("/etc/modules"),
                "auto-loaded at boot (Debian/Ubuntu /etc/modules)",
            ));
        }

        // systemd modules-load.d (dedup symlinked /lib → /usr/lib)
        for dir in canonical_unique(LOAD_DIRS) {
            findings.extend(scan_load_dir(&dir));
        }

        // modprobe.d — focus on `install` directives (arbitrary code execution)
        for dir in canonical_unique(PROBE_DIRS) {
            findings.extend(scan_probe_dir(&dir));
        }

        findings
    }
}

fn scan_load_dir(dir: &Path) -> Vec<Finding> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mechanism = format!("auto-loaded at boot ({})", dir.display());
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        findings.extend(parse_module_list(&content, &path, &mechanism));
    }
    findings
}

fn parse_module_list(content: &str, source: &Path, mechanism: &str) -> Vec<Finding> {
    // modules-load.d format: one module per line. '#' or ';' as the first
    // non-whitespace character marks a full-line comment.
    content
        .lines()
        .filter(|l| !l.trim_start().starts_with(';'))
        .map(strip_comment)
        .filter(|l| !l.is_empty())
        .map(|module| Finding {
            category: "modules",
            mechanism: mechanism.to_string(),
            source: source.to_path_buf(),
            target: Some(module.to_string()),
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata: BTreeMap::new(),
        })
        .collect()
}

fn scan_probe_dir(dir: &Path) -> Vec<Finding> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let line = strip_comment(line);
            if line.is_empty() {
                continue;
            }
            if let Some(f) = parse_install_directive(line, &path) {
                findings.push(f);
            }
        }
    }
    findings
}

fn parse_install_directive(line: &str, source: &Path) -> Option<Finding> {
    let mut iter = line.split_whitespace();
    if iter.next()? != "install" {
        return None;
    }
    let module = iter.next()?;
    let command: Vec<&str> = iter.collect();
    if command.is_empty() {
        return None;
    }
    let command = command.join(" ");

    let mut metadata = BTreeMap::new();
    metadata.insert("module".to_string(), module.to_string());
    metadata.insert("directive".to_string(), "install".to_string());

    Some(Finding {
        category: "modules",
        mechanism: format!(
            "modprobe `install {module}` — runs command instead of loading the module"
        ),
        source: source.to_path_buf(),
        target: Some(command),
        scope: Scope::System,
        package: PackageOrigin::Unknown,
        metadata,
    })
}

fn strip_comment(line: &str) -> &str {
    // '#' is the only mid-line comment marker recognized by modprobe and
    // modules-load. ';' is NOT a comment in either context except as the
    // very first non-whitespace character of a modules-load line (handled
    // separately by parse_module_list).
    line.split('#').next().unwrap_or("").trim()
}
