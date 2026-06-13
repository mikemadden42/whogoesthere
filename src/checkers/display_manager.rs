use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};
use crate::util::real_users;

pub struct DisplayManagerChecker;

/// Per-user X session entry-point dotfiles. Different display managers
/// source different subsets — `~/.xprofile` is the broadest (read by `GDM`,
/// `LightDM`, `SDDM`, and others); `~/.xsession` is read by DMs that allow a
/// "custom session"; `~/.xinitrc` and `~/.xsessionrc` are sourced by the
/// classic `startx`/`xinit` path. All four run at login if present; an
/// attacker with write access to any of them earns code execution at every
/// session start.
const USER_FILES: &[(&str, &str)] = &[
    (
        ".xprofile",
        "X profile — sourced at login by most display managers",
    ),
    (
        ".xsession",
        "X session script — runs at custom-session login",
    ),
    (".xinitrc", "startx/xinit user init script"),
    (".xsessionrc", "Debian-family X session resource script"),
];

/// System-wide X session / DM hook files. The `dm` column is the display
/// manager (or `xinit` for the startx path; `xsession` for the Debian DM-
/// agnostic Xsession infrastructure) that runs the file. `None` means the
/// scope is broader than a single DM.
const SYSTEM_SCRIPTS: &[(&str, &str, &str)] = &[
    (
        "/etc/X11/xinit/xinitrc",
        "system xinit script — runs on startx",
        "xinit",
    ),
    (
        "/etc/X11/Xsession",
        "Debian/Ubuntu X session entry point",
        "xsession",
    ),
    (
        "/etc/lightdm/Xsession",
        "LightDM X session script",
        "lightdm",
    ),
    (
        "/etc/gdm/PostLogin/Default",
        "GDM PostLogin hook — runs after login",
        "gdm",
    ),
    (
        "/etc/gdm/PreSession/Default",
        "GDM PreSession hook — runs before session start",
        "gdm",
    ),
];

/// Dirs whose every executable child runs at session start. `/etc/X11/
/// Xsession.d/` is the canonical Debian/Ubuntu sourced-fragment layout —
/// each `*.sh` here is sourced by `/etc/X11/Xsession` in lexical order
/// during session startup.
const SYSTEM_SCRIPT_DIRS: &[(&str, &str, &str)] = &[(
    "/etc/X11/Xsession.d",
    "Debian X session fragment — sourced by /etc/X11/Xsession",
    "xsession",
)];

impl Checker for DisplayManagerChecker {
    fn name(&self) -> &'static str {
        "display_manager"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (path, mech, dm) in SYSTEM_SCRIPTS {
            if let Some(f) = check_file(Path::new(path), mech, Some(dm), Scope::System) {
                findings.push(f);
            }
        }

        for (dir, mech, dm) in SYSTEM_SCRIPT_DIRS {
            findings.extend(scan_script_dir(Path::new(dir), mech, dm));
        }

        for user in real_users() {
            let scope = Scope::User {
                uid: user.uid,
                name: user.name,
            };
            for (rel, mech) in USER_FILES {
                let path = user.home.join(rel);
                if let Some(f) = check_file(&path, mech, None, scope.clone()) {
                    findings.push(f);
                }
            }
        }

        findings
    }
}

fn check_file(path: &Path, mech: &str, dm: Option<&str>, scope: Scope) -> Option<Finding> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() == 0 {
        return None;
    }
    let mode = meta.permissions().mode();
    let executable = mode & 0o111 != 0;

    let mut metadata: BTreeMap<String, String> = BTreeMap::new();
    metadata.insert("size_bytes".to_string(), meta.len().to_string());
    metadata.insert("executable".to_string(), executable.to_string());
    if let Some(d) = dm {
        metadata.insert("dm".to_string(), d.to_string());
    }
    if fs::File::open(path).is_err() {
        metadata.insert(
            "unreadable".to_string(),
            "rerun as root to inspect".to_string(),
        );
    }

    Some(Finding {
        category: "display_manager".to_string(),
        mechanism: mech.to_string(),
        source: path.to_path_buf(),
        target: None,
        scope,
        package: PackageOrigin::Unknown,
        metadata,
    })
}

fn scan_script_dir(dir: &Path, mech: &str, dm: &str) -> Vec<Finding> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
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
        // Editor backups and dotfiles aren't sourced.
        if name.starts_with('.') || name.ends_with('~') {
            continue;
        }
        if let Some(f) = check_file(&path, mech, Some(dm), Scope::System) {
            findings.push(f);
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, content: &str, executable: bool) {
        fs::write(path, content).unwrap();
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(if executable { 0o755 } else { 0o644 });
        fs::set_permissions(path, perms).unwrap();
    }

    fn fresh_tmpdir(test: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("whogoesthere-dm-{}-{test}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn check_file_emits_finding_with_size_exec_and_dm_metadata() {
        let dir = fresh_tmpdir("checkfile");
        let path = dir.join("xinitrc");
        write(&path, "#!/bin/sh\nexec startxfce4\n", true);

        let f = check_file(
            &path,
            "system xinit script — runs on startx",
            Some("xinit"),
            Scope::System,
        )
        .expect("has finding");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(f.category, "display_manager");
        assert!(f.mechanism.contains("xinit"));
        assert_eq!(f.metadata.get("dm").map(String::as_str), Some("xinit"));
        assert_eq!(
            f.metadata.get("executable").map(String::as_str),
            Some("true")
        );
        assert!(f.metadata.contains_key("size_bytes"));
    }

    #[test]
    fn check_file_omits_dm_when_none_given_for_per_user_dotfiles() {
        // Per-user dotfiles are read by multiple DMs; we deliberately don't
        // tag a single DM. The absence of the `dm` key is informative —
        // analysts see "this could fire under any DM".
        let dir = fresh_tmpdir("nodm");
        let path = dir.join(".xprofile");
        write(&path, "# stuff\n", false);

        let f = check_file(&path, "X profile", None, Scope::System).expect("has finding");
        let _ = fs::remove_dir_all(&dir);

        assert!(!f.metadata.contains_key("dm"));
        assert_eq!(
            f.metadata.get("executable").map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn check_file_returns_none_for_zero_byte_or_missing() {
        let dir = fresh_tmpdir("empty");
        let zero = dir.join("empty.xprofile");
        fs::write(&zero, "").unwrap();
        assert!(check_file(&zero, "x", None, Scope::System).is_none());
        assert!(check_file(&dir.join("nonexistent"), "x", None, Scope::System).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_script_dir_picks_up_real_scripts_and_skips_backups_and_dotfiles() {
        let dir = fresh_tmpdir("xsessiond");
        write(&dir.join("50-something"), "echo something\n", true);
        write(&dir.join("90-other"), "echo other\n", true);
        // Editor backup + dotfile — should be skipped.
        write(&dir.join("50-something~"), "stale\n", true);
        write(&dir.join(".hidden"), "stale\n", true);

        let findings = scan_script_dir(
            &dir,
            "Debian X session fragment — sourced by /etc/X11/Xsession",
            "xsession",
        );
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(findings.len(), 2);
        for f in &findings {
            assert_eq!(f.metadata.get("dm").map(String::as_str), Some("xsession"));
        }
    }

    #[test]
    fn scan_script_dir_missing_directory_is_a_noop() {
        let path = std::env::temp_dir().join("whogoesthere-dm-nonexistent");
        let _ = fs::remove_dir_all(&path);
        let findings = scan_script_dir(&path, "x", "xsession");
        assert!(findings.is_empty());
    }
}
