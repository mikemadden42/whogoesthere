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

    /// For paths matching a known distribution-shipped alias pattern, resolve
    /// to the target path's owning package. Returns `(package, resolved_target)`
    /// only if the symlink resolves AND lands on a package-owned file. A
    /// malicious `dbus-org.*` symlink pointing at `/tmp/evil.service` would
    /// not resolve to an owned target and stays `Untracked` — the security
    /// property holds. Currently recognizes Fedora's
    /// `/etc/systemd/system/dbus-org.*.service` D-Bus activation symlinks,
    /// which are created at install time (not packaged) but alias to owned
    /// unit files and reliably show up as the dominant UNTRACKED noise.
    pub fn resolve_benign_alias(&self, path: &Path) -> Option<(String, PathBuf)> {
        let files = self.files.as_ref()?;
        if !is_fedora_dbus_alias(path) {
            return None;
        }
        let target = path.canonicalize().ok()?;
        let pkg = files.get(&target)?;
        Some((pkg.clone(), target))
    }
}

/// `/etc/systemd/{system,user}/dbus-org.<bus.name>.service` — the canonical
/// Fedora shape for D-Bus activation aliases at both system and user scope.
fn is_fedora_dbus_alias(path: &Path) -> bool {
    let parent = path.parent();
    if parent != Some(Path::new("/etc/systemd/system"))
        && parent != Some(Path::new("/etc/systemd/user"))
    {
        return false;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.starts_with("dbus-org.") && name.ends_with(".service")
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
    let map: HashMap<PathBuf, String> = parse_rpm_qf_output(&stdout).into_iter().collect();
    if map.is_empty() { None } else { Some(map) }
}

/// Parse `rpm -qa --qf "...\t..."` output: one `<NVRA>\t<filename>\n` line per
/// file. Lines without a tab are silently skipped — they shouldn't occur in
/// well-formed output but the parser is tolerant of any rpm format drift that
/// would otherwise crash the whole index build.
fn parse_rpm_qf_output(stdout: &str) -> Vec<(PathBuf, String)> {
    stdout
        .lines()
        .filter_map(|line| {
            let (pkg, path) = line.split_once('\t')?;
            Some((PathBuf::from(path), pkg.to_string()))
        })
        .collect()
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
        let pkg = dpkg_pkg_from_stem(stem).to_string();
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for owned in parse_dpkg_list_content(&content) {
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

/// Strip `:arch` from a dpkg `.list` filename stem so the result matches what
/// `dpkg -S` reports. `foo` → `foo`, `foo:amd64` → `foo`. Edge case:
/// `foo:any:weird` → `foo` (we strip from the first colon).
fn dpkg_pkg_from_stem(stem: &str) -> &str {
    stem.split(':').next().unwrap_or(stem)
}

/// dpkg `.list` files are one absolute path per line; blank lines tolerated.
fn parse_dpkg_list_content(content: &str) -> Vec<PathBuf> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect()
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
        for owned in parse_pacman_files_content(&content) {
            map.insert(owned, pkg.to_string());
        }
    }
    if map.is_empty() { None } else { Some(map) }
}

/// Parse a pacman `files` file: extract one path per line from the `%FILES%`
/// section, prepending `/` to make each absolute. Other section headers
/// (`%BACKUP%` is the common one) gate `in_files` off.
fn parse_pacman_files_content(content: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
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
        if in_files {
            out.push(PathBuf::from(format!("/{line}")));
        }
    }
    out
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

    #[test]
    fn recognizes_dbus_org_aliases_at_both_scopes() {
        assert!(is_fedora_dbus_alias(Path::new(
            "/etc/systemd/system/dbus-org.bluez.service"
        )));
        assert!(is_fedora_dbus_alias(Path::new(
            "/etc/systemd/system/dbus-org.freedesktop.Avahi.service"
        )));
        assert!(is_fedora_dbus_alias(Path::new(
            "/etc/systemd/user/dbus-org.bluez.obex.service"
        )));
    }

    #[test]
    fn rpm_parser_pairs_each_line_on_tab() {
        let stdout = "\
bluez-5.86-4.fc44.x86_64\t/usr/lib/systemd/system/bluetooth.service
coreutils-9.5-9.fc44.x86_64\t/usr/bin/ls
coreutils-9.5-9.fc44.x86_64\t/usr/bin/cat
";
        let pairs = parse_rpm_qf_output(stdout);
        assert_eq!(pairs.len(), 3);
        assert!(pairs.contains(&(
            PathBuf::from("/usr/bin/ls"),
            "coreutils-9.5-9.fc44.x86_64".to_string()
        )));
        assert!(pairs.contains(&(
            PathBuf::from("/usr/lib/systemd/system/bluetooth.service"),
            "bluez-5.86-4.fc44.x86_64".to_string()
        )));
    }

    #[test]
    fn rpm_parser_skips_lines_without_tab_and_handles_empty_input() {
        // Tolerates format drift / blank lines without crashing the whole
        // index build.
        let stdout = "no-tab-here\n\nfoo-1\t/bin/foo\n";
        let pairs = parse_rpm_qf_output(stdout);
        assert_eq!(
            pairs,
            vec![(PathBuf::from("/bin/foo"), "foo-1".to_string())]
        );
        assert!(parse_rpm_qf_output("").is_empty());
    }

    #[test]
    fn dpkg_pkg_from_stem_strips_arch_suffix() {
        assert_eq!(dpkg_pkg_from_stem("bash"), "bash");
        assert_eq!(dpkg_pkg_from_stem("libfoo:amd64"), "libfoo");
        // Multiple colons — strip everything from the first one.
        assert_eq!(dpkg_pkg_from_stem("weird:any:thing"), "weird");
        assert_eq!(dpkg_pkg_from_stem(""), "");
    }

    #[test]
    fn dpkg_list_parser_one_path_per_line() {
        let content = "/usr/bin/foo\n/etc/foo/config\n\n  /var/lib/foo  \n";
        let paths = parse_dpkg_list_content(content);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/usr/bin/foo"),
                PathBuf::from("/etc/foo/config"),
                // Trims surrounding whitespace.
                PathBuf::from("/var/lib/foo"),
            ]
        );
        assert!(parse_dpkg_list_content("").is_empty());
    }

    #[test]
    fn pacman_files_parser_only_picks_files_section_and_prepends_slash() {
        let content = "%NAME%
bluez

%VERSION%
5.86-4

%FILES%
usr/bin/bluetoothctl
usr/lib/systemd/system/bluetooth.service

%BACKUP%
etc/bluetooth/main.conf\t<hash>

%FILES%
usr/share/man/man1/bluetoothctl.1.gz
";
        let paths = parse_pacman_files_content(content);
        // Both %FILES% sections are picked up; %BACKUP% content is ignored;
        // every path gains a leading slash.
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/usr/bin/bluetoothctl"),
                PathBuf::from("/usr/lib/systemd/system/bluetooth.service"),
                PathBuf::from("/usr/share/man/man1/bluetoothctl.1.gz"),
            ]
        );
    }

    #[test]
    fn pacman_files_parser_empty_when_no_files_section() {
        let content = "%NAME%\nfoo\n\n%VERSION%\n1.0-1\n";
        assert!(parse_pacman_files_content(content).is_empty());
    }

    #[test]
    fn rejects_non_dbus_org_and_wrong_locations() {
        // Wrong filename prefix.
        assert!(!is_fedora_dbus_alias(Path::new(
            "/etc/systemd/system/sshd.service"
        )));
        // Right prefix, wrong extension.
        assert!(!is_fedora_dbus_alias(Path::new(
            "/etc/systemd/system/dbus-org.bluez.timer"
        )));
        // Right shape, wrong directory — package dirs are off-limits because
        // packages do own files there, and we'd shadow that attribution.
        assert!(!is_fedora_dbus_alias(Path::new(
            "/usr/lib/systemd/system/dbus-org.bluez.service"
        )));
        // Adjacent-but-different scope; only /etc/systemd/{system,user} match.
        assert!(!is_fedora_dbus_alias(Path::new(
            "/run/systemd/system/dbus-org.bluez.service"
        )));
    }
}
