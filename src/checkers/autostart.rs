use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};
use crate::util::{canonical_unique, real_users};

pub struct AutostartChecker;

const SYSTEM_DIRS: &[&str] = &[
    "/etc/xdg/autostart",
    "/usr/xdg/autostart",
];

impl Checker for AutostartChecker {
    fn name(&self) -> &'static str {
        "autostart"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for dir in canonical_unique(SYSTEM_DIRS) {
            findings.extend(scan_autostart_dir(&dir, Scope::System));
        }

        for user in real_users() {
            let dir = user.home.join(".config/autostart");
            let scope = Scope::User { uid: user.uid, name: user.name };
            findings.extend(scan_autostart_dir(&dir, scope));
        }

        findings
    }
}

fn scan_autostart_dir(dir: &Path, scope: Scope) -> Vec<Finding> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        if let Some(f) = build_finding(&content, &path, scope.clone()) {
            findings.push(f);
        }
    }
    findings
}

#[derive(Default)]
struct DesktopEntry {
    exec: Option<String>,
    try_exec: Option<String>,
    name: Option<String>,
    type_: Option<String>,
    hidden: Option<String>,
    no_display: Option<String>,
    autostart_enabled: Option<String>,
    only_show_in: Option<String>,
    not_show_in: Option<String>,
}

fn parse_desktop(content: &str) -> DesktopEntry {
    let mut entry = DesktopEntry::default();
    let mut in_section = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_section = line == "[Desktop Entry]";
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        // Skip localized keys like Name[de]
        if key.contains('[') {
            continue;
        }
        let key = key.trim();
        let value = value.trim().to_string();
        match key {
            "Exec" => entry.exec = Some(value),
            "TryExec" => entry.try_exec = Some(value),
            "Name" => entry.name = Some(value),
            "Type" => entry.type_ = Some(value),
            "Hidden" => entry.hidden = Some(value),
            "NoDisplay" => entry.no_display = Some(value),
            "X-GNOME-Autostart-enabled" => entry.autostart_enabled = Some(value),
            "OnlyShowIn" => entry.only_show_in = Some(value),
            "NotShowIn" => entry.not_show_in = Some(value),
            _ => {}
        }
    }
    entry
}

fn build_finding(content: &str, source: &Path, scope: Scope) -> Option<Finding> {
    let entry = parse_desktop(content);
    let exec = entry.exec?;

    let mut metadata = BTreeMap::new();
    if let Some(n) = entry.name {
        metadata.insert("name".to_string(), n);
    }
    if let Some(t) = entry.type_ {
        metadata.insert("type".to_string(), t);
    }
    if let Some(t) = entry.try_exec {
        metadata.insert("try_exec".to_string(), t);
    }
    // Highlight effective-disabled state, since the file is still
    // present and could be re-enabled by editing one line.
    if let Some(h) = entry.hidden {
        if h.eq_ignore_ascii_case("true") {
            metadata.insert("disabled_by".to_string(), "Hidden=true".to_string());
        }
    }
    if let Some(e) = entry.autostart_enabled {
        if e.eq_ignore_ascii_case("false") {
            metadata.insert(
                "disabled_by".to_string(),
                "X-GNOME-Autostart-enabled=false".to_string(),
            );
        }
    }
    if let Some(n) = entry.no_display {
        if n.eq_ignore_ascii_case("true") {
            metadata.insert("no_display".to_string(), "true".to_string());
        }
    }
    if let Some(o) = entry.only_show_in {
        metadata.insert("only_show_in".to_string(), o);
    }
    if let Some(n) = entry.not_show_in {
        metadata.insert("not_show_in".to_string(), n);
    }

    Some(Finding {
        category: "autostart",
        mechanism: "XDG autostart .desktop entry".to_string(),
        source: source.to_path_buf(),
        target: Some(exec),
        scope,
        package: PackageOrigin::Unknown,
        metadata,
    })
}
