use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::finding::PackageOrigin;

/// One-shot index of every package-owned file on the system. Built once at
/// startup so that per-finding ownership lookups are O(1) hash hits instead
/// of `rpm -qf` / `dpkg -S` / `pacman -Qo` forks.
pub struct OwnershipIndex {
    files: Option<HashMap<PathBuf, String>>,
}

enum PackageManager {
    Dpkg,
    Rpm,
    Pacman,
    None,
}

impl OwnershipIndex {
    pub fn build() -> Self {
        let files = match detect() {
            PackageManager::Dpkg => build_dpkg_index(),
            PackageManager::Rpm => build_rpm_index(),
            PackageManager::Pacman => build_pacman_index(),
            PackageManager::None => None,
        };
        Self { files }
    }

    /// Returns the package that owns `path`, or `Untracked` if no package
    /// claims it. Lookup is literal — symlinks are NOT resolved here, because
    /// a symlink at /etc/systemd/system/foo.service pointing to an owned
    /// /usr/lib/... target is itself untracked, and that's exactly the kind
    /// of admin- or malware-installed entry we want to flag. Checkers that
    /// scan symlinked dir trees (e.g. /lib → /usr/lib) already canonicalize
    /// at the directory level via `util::canonical_unique`, so the finding's
    /// source path lands on the canonical entry the package registered.
    pub fn owner(&self, path: &Path) -> PackageOrigin {
        let Some(files) = &self.files else {
            return PackageOrigin::Unknown;
        };
        if let Some(pkg) = files.get(path) {
            return PackageOrigin::Owned {
                package: pkg.clone(),
            };
        }
        PackageOrigin::Untracked
    }
}

fn detect() -> PackageManager {
    if which("dpkg") {
        PackageManager::Dpkg
    } else if which("rpm") {
        PackageManager::Rpm
    } else if which("pacman") {
        PackageManager::Pacman
    } else {
        PackageManager::None
    }
}

/// rpm: emit (NVRA, filename) pairs for every file in every installed package.
/// The `=` prefix on the scalar tags lets them be referenced inside the
/// `[ ]` array iterator that walks FILENAMES.
fn build_rpm_index() -> Option<HashMap<PathBuf, String>> {
    let out = Command::new("rpm")
        .args([
            "-qa",
            "--qf",
            "[%{=NAME}-%{=VERSION}-%{=RELEASE}.%{=ARCH}\t%{FILENAMES}\n]",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut map = HashMap::with_capacity(stdout.lines().size_hint().0);
    for line in stdout.lines() {
        let Some((pkg, path)) = line.split_once('\t') else {
            continue;
        };
        map.insert(PathBuf::from(path), pkg.to_string());
    }
    if map.is_empty() { None } else { Some(map) }
}

/// dpkg: every installed package has a `/var/lib/dpkg/info/<pkg>.list` file
/// listing the paths it owns, one per line. Filename is `<pkg>.list` or
/// `<pkg>:<arch>.list` — strip the `:arch` to match what `dpkg -S` reports.
fn build_dpkg_index() -> Option<HashMap<PathBuf, String>> {
    let info = Path::new("/var/lib/dpkg/info");
    let entries = fs::read_dir(info).ok()?;
    let merged = is_merged_usr();
    let mut map: HashMap<PathBuf, String> = HashMap::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".list") else {
            continue;
        };
        let pkg = stem.split(':').next().unwrap_or(stem).to_string();
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let owned = PathBuf::from(line);
            // On merged-/usr systems dpkg records the unmerged spelling
            // (/lib/...), but checkers canonicalize finding sources to the
            // merged spelling (/usr/lib/...). Key under both so lookups hit
            // regardless of which form the finding carries.
            if merged && let Some(rewritten) = merged_usr_rewrite(&owned) {
                map.insert(rewritten, pkg.clone());
            }
            map.insert(owned, pkg.clone());
        }
    }
    if map.is_empty() { None } else { Some(map) }
}

/// True on merged-`/usr` systems, where `/lib` is a symlink into `/usr/lib`
/// (likewise `/bin`, `/sbin`). Checked via `symlink_metadata` so the symlink
/// itself is inspected rather than its target.
fn is_merged_usr() -> bool {
    Path::new("/lib")
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
}

/// Rewrite an unmerged path (`/lib/...`, `/bin/...`, `/sbin/...`) to its
/// merged-`/usr` spelling (`/usr/lib/...`, etc.), matching what
/// `Path::canonicalize` produces for finding sources on a merged system.
/// Returns `None` for paths that don't live under one of those dirs.
fn merged_usr_rewrite(path: &Path) -> Option<PathBuf> {
    let s = path.to_str()?;
    for prefix in ["/lib/", "/bin/", "/sbin/"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return Some(PathBuf::from(format!("/usr{prefix}{rest}")));
        }
    }
    None
}

/// pacman: every installed package has its own directory under
/// `/var/lib/pacman/local/<pkgname>-<version>-<release>/`. The `files`
/// sub-file lists owned paths after a `%FILES%` header, one per line,
/// relative to `/` — prepend a leading slash to get an absolute path.
/// Other section headers (e.g. `%BACKUP%`) may appear and gate `in_files`
/// off. Uses the directory name verbatim as the package identifier,
/// matching what `pacman -Qo` reports.
fn build_pacman_index() -> Option<HashMap<PathBuf, String>> {
    let local = Path::new("/var/lib/pacman/local");
    let entries = fs::read_dir(local).ok()?;
    let mut map: HashMap<PathBuf, String> = HashMap::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        let Some(pkg) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(content) = fs::read_to_string(dir.join("files")) else {
            continue;
        };
        let mut in_files = false;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('%') && line.ends_with('%') {
                in_files = line == "%FILES%";
                continue;
            }
            if !in_files {
                continue;
            }
            map.insert(PathBuf::from(format!("/{line}")), pkg.to_string());
        }
    }
    if map.is_empty() { None } else { Some(map) }
}

fn which(prog: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {prog}"))
        .output()
        .is_ok_and(|o| o.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_merged_usr_dirs() {
        assert_eq!(
            merged_usr_rewrite(Path::new("/lib/systemd/system/rsyslog.service")),
            Some(PathBuf::from("/usr/lib/systemd/system/rsyslog.service"))
        );
        assert_eq!(
            merged_usr_rewrite(Path::new("/bin/ls")),
            Some(PathBuf::from("/usr/bin/ls"))
        );
        assert_eq!(
            merged_usr_rewrite(Path::new("/sbin/init")),
            Some(PathBuf::from("/usr/sbin/init"))
        );
    }

    #[test]
    fn leaves_non_merged_paths_alone() {
        assert_eq!(merged_usr_rewrite(Path::new("/etc/crontab")), None);
        assert_eq!(merged_usr_rewrite(Path::new("/usr/lib/foo")), None);
        assert_eq!(merged_usr_rewrite(Path::new("/var/spool/cron")), None);
        // The dir symlinks themselves (no trailing slash) are not rewritten —
        // only paths *under* them, which is what dpkg .list entries are.
        assert_eq!(merged_usr_rewrite(Path::new("/lib")), None);
    }
}
