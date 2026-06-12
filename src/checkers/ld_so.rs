use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};

pub struct LdSoChecker;

impl Checker for LdSoChecker {
    fn name(&self) -> &'static str {
        "ld_so"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(check_preload_file());
        findings.extend(check_environment_file());
        findings
    }
}

fn check_preload_file() -> Vec<Finding> {
    let path = Path::new("/etc/ld.so.preload");
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| Finding {
            category: "ld_so",
            mechanism: "ld.so preload (loaded into every dynamically-linked process)".into(),
            source: path.to_path_buf(),
            target: Some(line.to_string()),
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata: BTreeMap::new(),
        })
        .collect()
}

fn check_environment_file() -> Vec<Finding> {
    let path = Path::new("/etc/environment");
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("LD_PRELOAD="))
        .map(|value| {
            let value = value.trim_matches(|c| c == '"' || c == '\'');
            Finding {
                category: "ld_so",
                mechanism: "LD_PRELOAD set in /etc/environment".into(),
                source: path.to_path_buf(),
                target: Some(value.to_string()),
                scope: Scope::System,
                package: PackageOrigin::Unknown,
                metadata: BTreeMap::new(),
            }
        })
        .collect()
}
