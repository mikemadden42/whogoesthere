use std::collections::HashSet;

use serde::Serialize;

use crate::finding::{Finding, Scope};

/// Result of comparing two snapshots — findings present only in the new
/// snapshot are `added`, findings present only in the old snapshot are
/// `removed`. Order within each list matches the input order.
#[derive(Serialize)]
pub struct Diff {
    pub added: Vec<Finding>,
    pub removed: Vec<Finding>,
}

/// Compare two snapshots and partition findings into `added` (in `new` but
/// not `old`) and `removed` (in `old` but not `new`). Findings are matched
/// by a stable identity tuple — see `diff_key` for what's included and
/// what isn't.
pub fn diff_snapshots(old: Vec<Finding>, new: Vec<Finding>) -> Diff {
    let old_keys: HashSet<String> = old.iter().map(diff_key).collect();
    let new_keys: HashSet<String> = new.iter().map(diff_key).collect();
    let added: Vec<Finding> = new
        .into_iter()
        .filter(|f| !old_keys.contains(&diff_key(f)))
        .collect();
    let removed: Vec<Finding> = old
        .into_iter()
        .filter(|f| !new_keys.contains(&diff_key(f)))
        .collect();
    Diff { added, removed }
}

/// Stable identity for a finding across runs. Includes the fields that
/// uniquely name a persistence vector — `category`, `source`, `target`,
/// `mechanism`, `scope` — and deliberately excludes:
///
///   * `package` — `UNTRACKED → owned` (or vice versa) on the same source
///     means the host's package state changed, not that a new persistence
///     vector appeared. The user can rerun without `--diff` to see those.
///   * `metadata` — file-level edits change `line:` numbers cascading
///     downward; we don't want renumbered rules to appear as added/removed
///     in lockstep. Only genuinely new or removed rules should show up.
fn diff_key(f: &Finding) -> String {
    let scope = match &f.scope {
        Scope::System => "system".to_string(),
        Scope::User { uid, name } => format!("user:{uid}:{name}"),
    };
    format!(
        "{}|{}|{}|{}|{}",
        f.category,
        f.source.display(),
        f.target.as_deref().unwrap_or(""),
        f.mechanism,
        scope,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::PackageOrigin;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn finding(category: &str, source: &str, target: Option<&str>, mech: &str) -> Finding {
        Finding {
            category: category.to_string(),
            mechanism: mech.to_string(),
            source: PathBuf::from(source),
            target: target.map(str::to_string),
            scope: Scope::System,
            package: PackageOrigin::Untracked,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn identical_snapshots_produce_empty_diff() {
        let a = vec![
            finding(
                "systemd",
                "/etc/systemd/system/foo.service",
                Some("/usr/bin/foo"),
                "service",
            ),
            finding(
                "cron",
                "/etc/crontab",
                Some("@reboot /bin/bar"),
                "cron @reboot",
            ),
        ];
        let b = vec![
            finding(
                "systemd",
                "/etc/systemd/system/foo.service",
                Some("/usr/bin/foo"),
                "service",
            ),
            finding(
                "cron",
                "/etc/crontab",
                Some("@reboot /bin/bar"),
                "cron @reboot",
            ),
        ];
        let diff = diff_snapshots(a, b);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn added_finding_appears_only_in_added() {
        let old = vec![finding(
            "systemd",
            "/a.service",
            Some("/usr/bin/a"),
            "service",
        )];
        let new = vec![
            finding("systemd", "/a.service", Some("/usr/bin/a"), "service"),
            finding("systemd", "/evil.service", Some("/tmp/evil"), "service"),
        ];
        let diff = diff_snapshots(old, new);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].source, PathBuf::from("/evil.service"));
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn removed_finding_appears_only_in_removed() {
        let old = vec![
            finding(
                "ssh",
                "/home/u/.ssh/authorized_keys",
                Some("revoked@host"),
                "key",
            ),
            finding(
                "ssh",
                "/home/u/.ssh/authorized_keys",
                Some("kept@host"),
                "key",
            ),
        ];
        let new = vec![finding(
            "ssh",
            "/home/u/.ssh/authorized_keys",
            Some("kept@host"),
            "key",
        )];
        let diff = diff_snapshots(old, new);
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].target.as_deref(), Some("revoked@host"));
    }

    #[test]
    fn metadata_only_change_is_not_a_diff() {
        // Same persistence vector, different metadata (e.g. a `line:` number
        // shift cascade from inserting a rule above). Should NOT appear in
        // either added or removed — only the truly new rule should.
        let mut old_f = finding("pam", "/etc/pam.d/common-auth", Some("pam_unix.so"), "rule");
        old_f.metadata.insert("line".into(), "17".into());
        let mut new_f = finding("pam", "/etc/pam.d/common-auth", Some("pam_unix.so"), "rule");
        new_f.metadata.insert("line".into(), "18".into());
        let diff = diff_snapshots(vec![old_f], vec![new_f]);
        assert!(
            diff.added.is_empty(),
            "metadata-only delta must not register as added"
        );
        assert!(
            diff.removed.is_empty(),
            "metadata-only delta must not register as removed"
        );
    }

    #[test]
    fn package_status_change_is_not_a_diff() {
        // The host's package index may shift (a package gets reinstalled, a
        // user manually installs the previously-untracked file's source
        // package, etc.) without the persistence vector itself changing.
        // diff is about persistence vectors, not attribution status.
        let mut old_f = finding(
            "systemd",
            "/etc/systemd/system/foo.service",
            Some("/usr/bin/foo"),
            "service",
        );
        old_f.package = PackageOrigin::Untracked;
        let mut new_f = finding(
            "systemd",
            "/etc/systemd/system/foo.service",
            Some("/usr/bin/foo"),
            "service",
        );
        new_f.package = PackageOrigin::Owned {
            package: "foo-1.0".into(),
        };
        let diff = diff_snapshots(vec![old_f], vec![new_f]);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn scope_difference_separates_findings() {
        // Same source path but different user scope = different finding.
        // A new user's .bashrc is genuinely new.
        let old = vec![Finding {
            scope: Scope::User {
                uid: 1000,
                name: "alice".into(),
            },
            ..finding("shell", "/home/alice/.bashrc", None, "bash")
        }];
        let new = vec![
            Finding {
                scope: Scope::User {
                    uid: 1000,
                    name: "alice".into(),
                },
                ..finding("shell", "/home/alice/.bashrc", None, "bash")
            },
            Finding {
                scope: Scope::User {
                    uid: 1001,
                    name: "bob".into(),
                },
                ..finding("shell", "/home/bob/.bashrc", None, "bash")
            },
        ];
        let diff = diff_snapshots(old, new);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].source, PathBuf::from("/home/bob/.bashrc"));
    }
}
