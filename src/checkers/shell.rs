use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};
use crate::util::real_users;

pub struct ShellChecker;

const SYSTEM_FILES: &[(&str, &str, &str)] = &[
    ("posix", "/etc/profile", "login shell, system-wide"),
    (
        "bash",
        "/etc/bash.bashrc",
        "bash interactive non-login, system-wide",
    ),
    (
        "bash",
        "/etc/bashrc",
        "bash interactive non-login, system-wide (RHEL/Fedora)",
    ),
    (
        "zsh",
        "/etc/zsh/zshenv",
        "zsh — every invocation, system-wide",
    ),
    ("zsh", "/etc/zsh/zprofile", "zsh login, system-wide"),
    ("zsh", "/etc/zsh/zshrc", "zsh interactive, system-wide"),
    (
        "zsh",
        "/etc/zsh/zlogin",
        "zsh login (after zshrc), system-wide",
    ),
    (
        "zsh",
        "/etc/zshenv",
        "zsh — every invocation, system-wide (alt path)",
    ),
    ("zsh", "/etc/zprofile", "zsh login, system-wide (alt path)"),
    (
        "zsh",
        "/etc/zshrc",
        "zsh interactive, system-wide (alt path)",
    ),
    (
        "zsh",
        "/etc/zlogin",
        "zsh login (after zshrc), system-wide (alt path)",
    ),
];

const USER_FILES: &[(&str, &str, &str)] = &[
    ("posix", ".profile", "login shell"),
    ("bash", ".bash_profile", "bash login shell"),
    ("bash", ".bash_login", "bash login shell (fallback)"),
    ("bash", ".bashrc", "bash interactive non-login"),
    ("bash", ".bash_logout", "bash logout"),
    ("zsh", ".zshenv", "zsh — every invocation"),
    ("zsh", ".zprofile", "zsh login shell"),
    ("zsh", ".zshrc", "zsh interactive"),
    ("zsh", ".zlogin", "zsh login (after .zshrc)"),
    ("zsh", ".zlogout", "zsh logout"),
];

impl Checker for ShellChecker {
    fn name(&self) -> &'static str {
        "shell"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (shell, path, when) in SYSTEM_FILES {
            if let Some(f) = check_file(Path::new(path), shell, when, Scope::System) {
                findings.push(f);
            }
        }

        if let Ok(entries) = fs::read_dir("/etc/profile.d") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("sh")
                    && let Some(f) =
                        check_file(&path, "posix", "sourced by /etc/profile", Scope::System)
                {
                    findings.push(f);
                }
            }
        }

        for user in real_users() {
            let scope = Scope::User {
                uid: user.uid,
                name: user.name,
            };
            for (shell, rel, when) in USER_FILES {
                let path = user.home.join(rel);
                if let Some(f) = check_file(&path, shell, when, scope.clone()) {
                    findings.push(f);
                }
            }
        }

        findings
    }
}

fn check_file(path: &Path, shell: &str, when: &str, scope: Scope) -> Option<Finding> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() == 0 {
        return None;
    }
    let mut metadata = BTreeMap::new();
    metadata.insert("shell".to_string(), shell.to_string());
    metadata.insert("size_bytes".to_string(), meta.len().to_string());
    Some(Finding {
        category: "shell",
        mechanism: when.to_string(),
        source: path.to_path_buf(),
        target: None,
        scope,
        package: PackageOrigin::Unknown,
        metadata,
    })
}
