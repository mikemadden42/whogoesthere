use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};
use crate::util::canonical_unique;

pub struct UdevChecker;

const RULE_DIRS: &[&str] = &[
    "/etc/udev/rules.d",
    "/run/udev/rules.d",
    "/lib/udev/rules.d",
    "/usr/lib/udev/rules.d",
];

const RUN_PREFIXES: &[&str] = &[
    "RUN{program}+=",
    "RUN{program}:=",
    "RUN{program}=",
    "RUN+=",
    "RUN:=",
    "RUN=",
];

const IMPORT_PROGRAM_PREFIXES: &[&str] = &[
    "IMPORT{program}+=",
    "IMPORT{program}:=",
    "IMPORT{program}=",
];

impl Checker for UdevChecker {
    fn name(&self) -> &'static str {
        "udev"
    }

    fn run(&self) -> Vec<Finding> {
        canonical_unique(RULE_DIRS)
            .iter()
            .flat_map(|d| scan_rules_dir(d))
            .collect()
    }
}

fn scan_rules_dir(dir: &Path) -> Vec<Finding> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rules") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        findings.extend(scan_rules_file(&content, &path));
    }
    findings
}

fn scan_rules_file(content: &str, source: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for (directive, value) in extract_directives(line) {
            let mut metadata = BTreeMap::new();
            metadata.insert("directive".to_string(), directive.to_string());
            metadata.insert("line".to_string(), (lineno + 1).to_string());
            findings.push(Finding {
                category: "udev",
                mechanism: format!("udev rule {directive} — runs command on matching device event"),
                source: source.to_path_buf(),
                target: Some(value),
                scope: Scope::System,
                package: PackageOrigin::Unknown,
                metadata,
            });
        }
    }
    findings
}

fn extract_directives(line: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    extract_with_prefixes(line, RUN_PREFIXES, "RUN", &mut out);
    extract_with_prefixes(line, IMPORT_PROGRAM_PREFIXES, "IMPORT{program}", &mut out);
    out
}

fn extract_with_prefixes(
    line: &str,
    prefixes: &[&str],
    canonical: &'static str,
    out: &mut Vec<(&'static str, String)>,
) {
    let mut pos = 0;
    while pos < line.len() {
        let mut best: Option<(usize, usize)> = None;
        for p in prefixes {
            if let Some(idx) = line[pos..].find(p) {
                let abs = pos + idx;
                if best.is_none_or(|(s, _)| abs < s) {
                    best = Some((abs, p.len()));
                }
            }
        }
        let Some((start, plen)) = best else { return };
        let after = start + plen;
        let bytes = line.as_bytes();
        if after >= bytes.len() || bytes[after] != b'"' {
            pos = after;
            continue;
        }
        let val_start = after + 1;
        let Some(close_offset) = line[val_start..].find('"') else { return };
        let value = &line[val_start..val_start + close_offset];
        out.push((canonical, value.to_string()));
        pos = val_start + close_offset + 1;
    }
}
