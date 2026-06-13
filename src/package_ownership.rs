use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::finding::PackageOrigin;

/// One-shot index of every package-owned file on the system. Built once at
/// startup so that per-finding ownership lookups are O(1) hash hits instead
/// of `rpm -qf` / `dpkg -S` / `pacman -Qo` forks.
pub struct OwnershipIndex {
    files: Option<HashMap<PathBuf, String>>,
    snaps: Option<HashSet<String>>,
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
        let snaps = build_snap_set();
        Self { files, snaps }
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

    /// For paths matching one of the known "benign symlink" shapes, resolve
    /// to the canonical target's owning package. Returns
    /// `(package, resolved_target, pattern_tag)` only if the symlink resolves
    /// AND lands on a package-owned file. A malicious `→ /tmp/evil` doesn't
    /// resolve to an owned target and stays `Untracked` — the security
    /// property holds across all patterns.
    ///
    /// Currently recognized shapes:
    ///   * `systemd-enable-symlink` —
    ///     `/etc/systemd/{system,user}/<name>.{service,timer,path,socket}`
    ///     that `systemctl enable` (or D-Bus activation) creates back into
    ///     `/usr/lib/systemd/`. Originally added for Fedora's `dbus-org.*`
    ///     aliases; generalized after the Ubuntu 24.04 baseline showed
    ///     `sshd.service`, `samba.service`, etc. follow the same shape.
    ///   * `shell-profile-symlink` — `/etc/profile.d/*.sh` symlinks that
    ///     packages' postinst scripts create back into
    ///     `/usr/share/<pkg>/...`. Added after the Ubuntu 24.04 diagnosis of
    ///     `/etc/profile.d/debuginfod.sh →
    ///     /usr/share/libdebuginfod-common/debuginfod.sh`.
    pub fn resolve_benign_alias(&self, path: &Path) -> Option<(String, PathBuf, &'static str)> {
        let files = self.files.as_ref()?;
        let pattern = benign_alias_pattern(path)?;
        let target = path.canonicalize().ok()?;
        let pkg = files.get(&target)?;
        Some((pkg.clone(), target, pattern))
    }

    /// For files that snapd emits at install time (and that dpkg therefore
    /// doesn't index), attribute through to the owning snap by parsing the
    /// filename pattern and confirming the snap is actually installed. Returns
    /// the `snap:<name>` identifier. A malicious
    /// `/etc/systemd/system/snap.evil.payload.service` with no matching snap
    /// installed wouldn't satisfy the install check and stays `Untracked` —
    /// the security property holds. Currently recognizes:
    ///   * `/etc/systemd/{system,user}/snap.<snap>.<app>.<ext>` (service,
    ///     timer, path, socket)
    ///   * `/etc/udev/rules.d/70-snap.<snap>.rules`
    pub fn resolve_snap_attribution(&self, path: &Path) -> Option<String> {
        let snaps = self.snaps.as_ref()?;
        let name = extract_snap_name(path)?;
        if snaps.contains(name.as_str()) {
            Some(format!("snap:{name}"))
        } else {
            None
        }
    }

    /// For files that a Debian/Ubuntu package's postinst script creates (and
    /// that dpkg therefore doesn't track in `.list`), attribute through to the
    /// known owning package. Returns the package name as a `&'static str` —
    /// the allowlist is a static table. A finding is only reattributed if it
    /// reached this pass as `Untracked`, so a malicious file that *is* in some
    /// package's `.list` (genuine ownership) is unaffected. The attribution is
    /// best understood as "this file is known to be associated with package X
    /// via its postinst" — same semantic as dpkg/rpm file ownership, which
    /// also doesn't validate contents.
    ///
    /// Catalogued cases (all diagnosed on Ubuntu 24.04):
    ///   * `/etc/profile` ← base-files postinst
    ///   * `/etc/pam.d/common-{auth,account,password,session,
    ///     session-noninteractive}` ← libpam-runtime via `pam-auth-update`
    ///   * `/etc/modules` ← kmod postinst (initramfs-tools on older releases)
    pub fn resolve_postinst_allowlist(&self, path: &Path) -> Option<&'static str> {
        // Gate on having a real package backend — on a host where `detect()`
        // returned None, fabricating package names is wrong.
        self.files.as_ref()?;
        POSTINST_ALLOWLIST
            .iter()
            .find(|(p, _)| Path::new(p) == path)
            .map(|(_, pkg)| *pkg)
    }
}

/// Path → owning package for files known to be created by dpkg postinst
/// scripts. dpkg's `.list` only records archive-unpacked files; postinst
/// output is invisible to `dpkg-query -S`. rpm includes scriptlet-created
/// files in its database, which is why this allowlist is dpkg-specific in
/// practice — on rpm-based hosts these paths either don't exist (PAM
/// `common-*`, `/etc/modules`) or are correctly attributed via the file
/// index (`/etc/profile` → `setup` on Fedora).
const POSTINST_ALLOWLIST: &[(&str, &str)] = &[
    ("/etc/profile", "base-files"),
    ("/etc/pam.d/common-auth", "libpam-runtime"),
    ("/etc/pam.d/common-account", "libpam-runtime"),
    ("/etc/pam.d/common-password", "libpam-runtime"),
    ("/etc/pam.d/common-session", "libpam-runtime"),
    ("/etc/pam.d/common-session-noninteractive", "libpam-runtime"),
    ("/etc/modules", "kmod"),
];

/// Try each known benign-symlink discriminator in turn; return the matching
/// pattern tag (used as `benign_pattern` metadata on the reattributed
/// finding) or `None` if no shape matches.
fn benign_alias_pattern(path: &Path) -> Option<&'static str> {
    if is_systemd_enable_symlink_candidate(path) {
        return Some("systemd-enable-symlink");
    }
    if is_profile_d_symlink_candidate(path) {
        return Some("shell-profile-symlink");
    }
    None
}

/// `/etc/systemd/{system,user}/<name>.{service,timer,path,socket}` — the
/// shape of a unit-file alias that `systemctl enable` or D-Bus activation
/// would create. Restricted to `/etc/systemd/...` because `/usr/lib/systemd/`
/// is the package-owned side; reattributing there would shadow real ownership.
/// `/run/systemd/...` is also excluded — it's runtime-generated and we don't
/// want to silently attribute generated units to a real package.
fn is_systemd_enable_symlink_candidate(path: &Path) -> bool {
    let parent = path.parent();
    if parent != Some(Path::new("/etc/systemd/system"))
        && parent != Some(Path::new("/etc/systemd/user"))
    {
        return false;
    }
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(ext, "service" | "timer" | "path" | "socket")
}

/// `/etc/profile.d/<name>.sh` — shell-rc snippets that a package's postinst
/// commonly symlinks back into `/usr/share/<pkg>/...`. The reattribution
/// only fires if `canonicalize` lands on a path that's *itself* in the
/// package index, so a malicious `/etc/profile.d/evil.sh → /tmp/evil.sh`
/// stays UNTRACKED.
fn is_profile_d_symlink_candidate(path: &Path) -> bool {
    if path.parent() != Some(Path::new("/etc/profile.d")) {
        return false;
    }
    path.extension().and_then(|e| e.to_str()) == Some("sh")
}

/// Extract the snap name from a path that follows one of the snapd-emitted
/// shapes. Returns `None` for non-matching paths; the snap-installed check is
/// done by the caller against the pre-scanned snap set. The 2nd dot-separated
/// component of the filename is the snap name in both shapes (snap names are
/// restricted to `[a-z0-9-]` by snapcraft, so a literal `.` split is safe).
fn extract_snap_name(path: &Path) -> Option<String> {
    let parent = path.parent()?;
    let name = path.file_name().and_then(|n| n.to_str())?;

    // systemd: /etc/systemd/{system,user}/snap.<snap>.<rest>.<ext>
    if (parent == Path::new("/etc/systemd/system") || parent == Path::new("/etc/systemd/user"))
        && let Some(rest) = name.strip_prefix("snap.")
        && let Some(ext) = path.extension().and_then(|e| e.to_str())
        && matches!(ext, "service" | "timer" | "path" | "socket")
    {
        return rest.split('.').next().map(str::to_string);
    }

    // udev: /etc/udev/rules.d/70-snap.<snap>.rules
    if parent == Path::new("/etc/udev/rules.d")
        && let Some(stem) = name
            .strip_prefix("70-snap.")
            .and_then(|s| s.strip_suffix(".rules"))
    {
        return Some(stem.to_string());
    }

    None
}

/// Enumerate installed snap names by probing both standard locations: the
/// `/snap/<name>/` directory layout (one subdir per snap, plus a `bin/`
/// shim dir that's not a snap) and the `/var/lib/snapd/snaps/<name>_<rev>.snap`
/// blob layout. Returns `None` if neither location yields any snaps — that
/// host doesn't run snapd and the attribution pass is a no-op.
fn build_snap_set() -> Option<HashSet<String>> {
    let mut set: HashSet<String> = HashSet::new();
    if let Ok(entries) = fs::read_dir("/snap") {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name == "bin" || name.starts_with('.') {
                continue;
            }
            if entry.metadata().is_ok_and(|m| m.is_dir()) {
                set.insert(name);
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/var/lib/snapd/snaps") {
        for entry in entries.flatten() {
            let Some(fname) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if let Some(stem) = fname.strip_suffix(".snap")
                && let Some((name, _rev)) = stem.split_once('_')
            {
                set.insert(name.to_string());
            }
        }
    }
    if set.is_empty() { None } else { Some(set) }
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
    fn recognizes_systemd_enable_symlinks_at_both_scopes() {
        // The original Fedora dbus-org.* cases.
        assert!(is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/dbus-org.bluez.service"
        )));
        assert!(is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/user/dbus-org.bluez.obex.service"
        )));
        // The Ubuntu `systemctl enable` cases that motivated generalizing.
        assert!(is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/sshd.service"
        )));
        assert!(is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/display-manager.service"
        )));
        assert!(is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/iscsi.service"
        )));
        // Non-.service unit types are also enableable.
        assert!(is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/logrotate.timer"
        )));
        assert!(is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/systemd-journald.socket"
        )));
        assert!(is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/foo.path"
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
    fn profile_d_symlink_candidate_matches_sh_under_etc_profile_d() {
        // The case that motivated this: libdebuginfod-common's postinst
        // symlink, /etc/profile.d/debuginfod.sh →
        // /usr/share/libdebuginfod-common/debuginfod.sh.
        assert!(is_profile_d_symlink_candidate(Path::new(
            "/etc/profile.d/debuginfod.sh"
        )));
        // Hyphens and digits in the basename are fine.
        assert!(is_profile_d_symlink_candidate(Path::new(
            "/etc/profile.d/01-locale-fix.sh"
        )));
    }

    #[test]
    fn profile_d_symlink_candidate_rejects_other_dirs_and_extensions() {
        // Wrong directory — /etc/bash.bashrc is a real shell rc file but
        // not where this pattern applies.
        assert!(!is_profile_d_symlink_candidate(Path::new(
            "/etc/bash.bashrc"
        )));
        // Right dir, no extension.
        assert!(!is_profile_d_symlink_candidate(Path::new(
            "/etc/profile.d/README"
        )));
        // Right dir, wrong extension.
        assert!(!is_profile_d_symlink_candidate(Path::new(
            "/etc/profile.d/debuginfod.csh"
        )));
        // Right shape but the package dir — packages do own .sh files
        // under /usr/share/, and reattributing here would shadow that.
        assert!(!is_profile_d_symlink_candidate(Path::new(
            "/usr/share/libdebuginfod-common/debuginfod.sh"
        )));
    }

    fn idx_with_backend() -> OwnershipIndex {
        OwnershipIndex {
            files: Some(HashMap::new()),
            snaps: None,
        }
    }

    #[test]
    fn postinst_allowlist_returns_owning_package_for_known_paths() {
        let idx = idx_with_backend();
        // /etc/profile is created by base-files postinst on Debian/Ubuntu.
        assert_eq!(
            idx.resolve_postinst_allowlist(Path::new("/etc/profile")),
            Some("base-files")
        );
        // All five PAM common-* files aggregate to libpam-runtime via
        // pam-auth-update.
        for name in [
            "common-auth",
            "common-account",
            "common-password",
            "common-session",
            "common-session-noninteractive",
        ] {
            assert_eq!(
                idx.resolve_postinst_allowlist(&Path::new("/etc/pam.d").join(name)),
                Some("libpam-runtime"),
                "expected {name} → libpam-runtime"
            );
        }
        // /etc/modules is created by kmod postinst on modern Debian/Ubuntu
        // (was initramfs-tools on older releases).
        assert_eq!(
            idx.resolve_postinst_allowlist(Path::new("/etc/modules")),
            Some("kmod")
        );
    }

    #[test]
    fn postinst_allowlist_returns_none_for_unrelated_paths() {
        let idx = idx_with_backend();
        // Real shell file but not on the allowlist (rpm's setup ships it,
        // dpkg's base-files generates it — different category from the
        // postinst-created files we catalogue).
        assert!(
            idx.resolve_postinst_allowlist(Path::new("/etc/bash.bashrc"))
                .is_none()
        );
        // Adjacent PAM file that is package-shipped, not postinst-generated.
        assert!(
            idx.resolve_postinst_allowlist(Path::new("/etc/pam.d/sshd"))
                .is_none()
        );
        // Random path.
        assert!(
            idx.resolve_postinst_allowlist(Path::new("/etc/passwd"))
                .is_none()
        );
    }

    #[test]
    fn postinst_allowlist_does_not_fire_without_a_package_backend() {
        // No file index → no detected package manager → we mustn't fabricate
        // attribution, even for paths that would otherwise match.
        let idx = OwnershipIndex {
            files: None,
            snaps: None,
        };
        assert!(
            idx.resolve_postinst_allowlist(Path::new("/etc/profile"))
                .is_none()
        );
        assert!(
            idx.resolve_postinst_allowlist(Path::new("/etc/pam.d/common-auth"))
                .is_none()
        );
    }

    #[test]
    fn benign_alias_pattern_dispatches_to_the_right_tag() {
        // Systemd-unit shape returns the systemd tag.
        assert_eq!(
            benign_alias_pattern(Path::new("/etc/systemd/system/sshd.service")),
            Some("systemd-enable-symlink")
        );
        // Profile.d shape returns the shell-profile tag.
        assert_eq!(
            benign_alias_pattern(Path::new("/etc/profile.d/debuginfod.sh")),
            Some("shell-profile-symlink")
        );
        // Neither shape returns None.
        assert_eq!(benign_alias_pattern(Path::new("/etc/passwd")), None);
    }

    #[test]
    fn extracts_snap_name_from_systemd_unit_paths() {
        // 2nd dot-separated component is the snap; rest is app + ext.
        assert_eq!(
            extract_snap_name(Path::new("/etc/systemd/system/snap.cups.cupsd.service")),
            Some("cups".to_string())
        );
        assert_eq!(
            extract_snap_name(Path::new(
                "/etc/systemd/system/snap.mesa-2404.component-monitor.service"
            )),
            Some("mesa-2404".to_string())
        );
        // user-global scope is also valid for snap units.
        assert_eq!(
            extract_snap_name(Path::new(
                "/etc/systemd/user/snap.firmware-updater.firmware-notifier.timer"
            )),
            Some("firmware-updater".to_string())
        );
        // Hyphenated snap name with multi-dot app slug.
        assert_eq!(
            extract_snap_name(Path::new(
                "/etc/systemd/user/snap.snapd-desktop-integration.snapd-desktop-integration.service"
            )),
            Some("snapd-desktop-integration".to_string())
        );
    }

    #[test]
    fn extracts_snap_name_from_udev_rule_paths() {
        // 70-snap.<name>.rules — name is the slug between the prefix and .rules.
        assert_eq!(
            extract_snap_name(Path::new("/etc/udev/rules.d/70-snap.chromium.rules")),
            Some("chromium".to_string())
        );
        assert_eq!(
            extract_snap_name(Path::new("/etc/udev/rules.d/70-snap.snap-store.rules")),
            Some("snap-store".to_string())
        );
    }

    #[test]
    fn extract_snap_name_rejects_non_snap_paths() {
        // Right shape but wrong directory — a snap.foo.service under
        // /usr/lib/systemd/system/ would already be package-attributed by
        // the file index, and we don't want to second-guess.
        assert!(
            extract_snap_name(Path::new("/usr/lib/systemd/system/snap.cups.cupsd.service"))
                .is_none()
        );
        // Right dir, wrong filename prefix.
        assert!(extract_snap_name(Path::new("/etc/systemd/system/sshd.service")).is_none());
        // Unit-type extensions we don't survey.
        assert!(extract_snap_name(Path::new("/etc/systemd/system/snap.cups.target")).is_none());
        // udev: wrong prefix.
        assert!(extract_snap_name(Path::new("/etc/udev/rules.d/99-foo.rules")).is_none());
        // udev: right prefix, wrong extension.
        assert!(extract_snap_name(Path::new("/etc/udev/rules.d/70-snap.cups.conf")).is_none());
    }

    #[test]
    fn rejects_wrong_extension_and_wrong_directories() {
        // Extensions we don't survey aren't enableable units in the
        // persistence sense, so we don't reattribute through them.
        assert!(!is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/foo.conf"
        )));
        assert!(!is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/foo.target"
        )));
        // Missing extension entirely.
        assert!(!is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/foo"
        )));
        // Package dirs are off-limits — packages do own files there, and
        // reattributing would shadow real ownership.
        assert!(!is_systemd_enable_symlink_candidate(Path::new(
            "/usr/lib/systemd/system/sshd.service"
        )));
        assert!(!is_systemd_enable_symlink_candidate(Path::new(
            "/lib/systemd/system/sshd.service"
        )));
        // Runtime-generated dir; never the right side to reattribute *from*.
        assert!(!is_systemd_enable_symlink_candidate(Path::new(
            "/run/systemd/system/foo.service"
        )));
        // Drop-in conf inside a unit's `.d` dir, not a unit-file itself.
        assert!(!is_systemd_enable_symlink_candidate(Path::new(
            "/etc/systemd/system/sshd.service.d/override.conf"
        )));
    }
}
