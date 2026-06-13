use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};

pub struct NetworkManagerChecker;

/// `NetworkManager` runs every executable in `/etc/NetworkManager/dispatcher.d/`
/// on every connectivity event. The phase sub-dirs scope to specific points
/// in the up/down lifecycle. Each sub-dir is its own persistence flavor; the
/// `mechanism` string makes the timing visible.
const DISPATCHER_DIR: &str = "/etc/NetworkManager/dispatcher.d";

/// Sub-dirs that `NetworkManager` treats specially. `None` for the main
/// `dispatcher.d/` body, which runs on every event (`connectivity-change`,
/// `hostname`, `dhcp4-change`, `up`, `down`, …).
const PHASE_DIRS: &[(Option<&str>, &str)] = &[
    (None, "runs on every network event"),
    (Some("pre-up.d"), "runs before an interface comes up"),
    (Some("pre-down.d"), "runs before an interface goes down"),
    (
        Some("no-wait.d"),
        "runs on every network event, in parallel",
    ),
];

impl Checker for NetworkManagerChecker {
    fn name(&self) -> &'static str {
        "network_manager"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (phase, when) in PHASE_DIRS {
            let dir = match phase {
                Some(sub) => format!("{DISPATCHER_DIR}/{sub}"),
                None => DISPATCHER_DIR.to_string(),
            };
            findings.extend(scan_dispatcher_dir(Path::new(&dir), *phase, when));
        }
        findings
    }
}

fn scan_dispatcher_dir(dir: &Path, phase: Option<&str>, when: &str) -> Vec<Finding> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            // The phase sub-dirs (pre-up.d, etc.) live as directories under
            // the main dir, so they'd show up here — skip non-files cleanly.
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Editor backups + dotfiles aren't dispatched even if present.
        if name.starts_with('.') || name.ends_with('~') {
            continue;
        }

        let mode = meta.permissions().mode();
        let executable = mode & 0o111 != 0;

        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        metadata.insert("size_bytes".to_string(), meta.len().to_string());
        metadata.insert("executable".to_string(), executable.to_string());
        if let Some(p) = phase {
            metadata.insert("phase".to_string(), p.to_string());
        }
        if !executable {
            // NM only dispatches executable scripts. A non-executable script
            // is dormant — present but not running today. Still a finding
            // (its mere presence is admin/attacker intent) but flag the gap.
            metadata.insert(
                "note".to_string(),
                "non-executable — present but won't run on dispatch".to_string(),
            );
        }
        if fs::File::open(&path).is_err() {
            metadata.insert(
                "unreadable".to_string(),
                "rerun as root to inspect".to_string(),
            );
        }

        let mechanism = match phase {
            Some(p) => format!("NetworkManager {p} dispatcher script — {when}"),
            None => format!("NetworkManager dispatcher script — {when}"),
        };

        findings.push(Finding {
            category: "network_manager".to_string(),
            mechanism,
            source: path,
            target: None,
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write(dir: &Path, name: &str, content: &str, executable: bool) {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        if executable {
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms).unwrap();
        } else {
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o644);
            fs::set_permissions(&path, perms).unwrap();
        }
    }

    /// Build a unique temp dir per test under /tmp. Using a process-id +
    /// test-name suffix avoids cross-test collisions without pulling in
    /// the `tempfile` crate.
    fn fresh_tmpdir(test: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("whogoesthere-nm-{}-{test}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn picks_up_executable_dispatcher_scripts_and_records_metadata() {
        let dir = fresh_tmpdir("basic");
        write(&dir, "10-foo", "#!/bin/sh\necho foo\n", true);
        write(&dir, "20-bar", "#!/bin/sh\necho bar\n", true);

        let findings = scan_dispatcher_dir(&dir, None, "runs on every network event");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(findings.len(), 2);
        let names: Vec<_> = findings
            .iter()
            .map(|f| f.source.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert!(names.contains(&"10-foo".to_string()));
        assert!(names.contains(&"20-bar".to_string()));
        // Each finding records the executable bit and the size.
        for f in &findings {
            assert_eq!(
                f.metadata.get("executable").map(String::as_str),
                Some("true")
            );
            assert!(f.metadata.contains_key("size_bytes"));
        }
    }

    #[test]
    fn flags_non_executable_scripts_with_note_but_still_surfaces_them() {
        // A non-executable script in the dispatcher dir is dormant — NM
        // won't run it — but its presence is still admin/attacker intent
        // and worth surfacing for triage.
        let dir = fresh_tmpdir("nonexec");
        write(&dir, "10-dormant", "#!/bin/sh\necho dormant\n", false);

        let findings = scan_dispatcher_dir(&dir, None, "runs on every network event");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].metadata.get("executable").map(String::as_str),
            Some("false")
        );
        assert!(
            findings[0].metadata.contains_key("note"),
            "non-executable script should have a 'note' explaining it won't run"
        );
    }

    #[test]
    fn skips_dotfiles_and_editor_backup_tilde_files() {
        // `.foo` (dotfile) and `foo~` (editor backup) are not dispatched by
        // NM and should not appear as findings.
        let dir = fresh_tmpdir("skips");
        write(&dir, ".hidden", "#!/bin/sh\n", true);
        write(&dir, "10-real", "#!/bin/sh\n", true);
        write(&dir, "10-real~", "#!/bin/sh\n", true);

        let findings = scan_dispatcher_dir(&dir, None, "runs on every network event");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].source.file_name().unwrap().to_str().unwrap(),
            "10-real"
        );
    }

    #[test]
    fn phase_sub_dir_surfaces_phase_metadata_and_distinct_mechanism() {
        // pre-up.d/ scripts are persistence-relevant in a different way than
        // the main dir: they run at interface-up time, not every event. The
        // mechanism string and the `phase` metadata must reflect that.
        let dir = fresh_tmpdir("phase");
        write(&dir, "10-preup", "#!/bin/sh\n", true);

        let findings =
            scan_dispatcher_dir(&dir, Some("pre-up.d"), "runs before an interface comes up");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(
            f.metadata.get("phase").map(String::as_str),
            Some("pre-up.d")
        );
        assert!(f.mechanism.contains("pre-up.d"));
        assert!(f.mechanism.contains("before an interface comes up"));
    }

    #[test]
    fn missing_directory_returns_no_findings_without_erroring() {
        // The phase sub-dirs may not exist on hosts that don't ship them —
        // `read_dir` returns Err and we should just yield nothing.
        let path = std::env::temp_dir().join("whogoesthere-nm-nonexistent-dir");
        let _ = fs::remove_dir_all(&path);
        let findings = scan_dispatcher_dir(&path, None, "runs on every network event");
        assert!(findings.is_empty());
    }
}
