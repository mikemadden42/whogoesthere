use std::path::Path;
use std::process::Command;

use crate::finding::PackageOrigin;

#[derive(Debug, Clone, Copy)]
pub enum PackageManager {
    Dpkg,
    Rpm,
    None,
}

pub fn detect() -> PackageManager {
    if which("dpkg") {
        PackageManager::Dpkg
    } else if which("rpm") {
        PackageManager::Rpm
    } else {
        PackageManager::None
    }
}

pub fn owner(path: &Path, pm: PackageManager) -> PackageOrigin {
    match pm {
        PackageManager::Dpkg => dpkg_owner(path),
        PackageManager::Rpm => rpm_owner(path),
        PackageManager::None => PackageOrigin::Unknown,
    }
}

fn dpkg_owner(path: &Path) -> PackageOrigin {
    let out = Command::new("dpkg").arg("-S").arg(path).output();
    let Ok(out) = out else { return PackageOrigin::Unknown };
    if !out.status.success() {
        return PackageOrigin::Untracked;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pkg = stdout.split(':').next().unwrap_or("").trim();
    if pkg.is_empty() {
        PackageOrigin::Untracked
    } else {
        PackageOrigin::Owned { package: pkg.to_string() }
    }
}

fn rpm_owner(path: &Path) -> PackageOrigin {
    let out = Command::new("rpm").arg("-qf").arg(path).output();
    let Ok(out) = out else { return PackageOrigin::Unknown };
    if !out.status.success() {
        return PackageOrigin::Untracked;
    }
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if stdout.is_empty() || stdout.contains("not owned") {
        PackageOrigin::Untracked
    } else {
        PackageOrigin::Owned { package: stdout }
    }
}

fn which(prog: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {prog}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
