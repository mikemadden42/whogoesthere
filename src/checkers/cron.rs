use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};

pub struct CronChecker;

const INTERVALS: &[&str] = &["hourly", "daily", "weekly", "monthly"];

// Per-user crontab spool. RHEL/Fedora drop files directly here;
// Debian/Ubuntu use the `crontabs/` subdirectory.
const USER_SPOOLS: &[&str] = &["/var/spool/cron", "/var/spool/cron/crontabs"];

impl Checker for CronChecker {
    fn name(&self) -> &'static str {
        "cron"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // System crontab — has a user field per row
        findings.extend(scan_system_crontab(Path::new("/etc/crontab")));

        // /etc/cron.d/* — same format as /etc/crontab
        if let Ok(entries) = fs::read_dir("/etc/cron.d") {
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = entry.metadata() else { continue };
                if meta.is_file() {
                    findings.extend(scan_system_crontab(&path));
                }
            }
        }

        // /etc/cron.{hourly,daily,weekly,monthly}/ — dirs of executable scripts
        for interval in INTERVALS {
            findings.extend(scan_interval_dir(interval));
        }

        // /etc/anacrontab
        findings.extend(scan_anacrontab());

        // Per-user crontabs
        for spool in USER_SPOOLS {
            findings.extend(scan_user_spool(Path::new(spool)));
        }

        // at jobs
        findings.extend(scan_at_jobs());

        findings
    }
}

// ─── line parser ─────────────────────────────────────────────────────────────

struct CronLine {
    schedule: String,
    user: Option<String>,
    command: String,
}

/// Parse one cron line. `has_user` is true for /etc/crontab and /etc/cron.d/*,
/// false for per-user crontabs (where the user is implicit from the filename).
fn parse_cron_line(line: &str, has_user: bool) -> Option<CronLine> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // env-var assignment line (SHELL=, PATH=, MAILTO=, HOME=, etc.)
    let first_tok = line.split_whitespace().next()?;
    if first_tok.contains('=') {
        return None;
    }

    let mut iter = line.split_whitespace();
    let first = iter.next()?;
    let schedule = if first.starts_with('@') {
        first.to_string()
    } else {
        let mut parts = vec![first.to_string()];
        for _ in 0..4 {
            parts.push(iter.next()?.to_string());
        }
        parts.join(" ")
    };

    let user = if has_user {
        Some(iter.next()?.to_string())
    } else {
        None
    };
    let command: Vec<&str> = iter.collect();
    if command.is_empty() {
        return None;
    }
    Some(CronLine {
        schedule,
        user,
        command: command.join(" "),
    })
}

fn mechanism_for(schedule: &str, prefix: &str) -> String {
    if schedule == "@reboot" {
        format!("{prefix}@reboot — runs at every boot")
    } else {
        format!("{prefix}schedule `{schedule}`")
    }
}

fn metadata_for(schedule: &str, user: Option<&str>, lineno: usize) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("schedule".to_string(), schedule.to_string());
    m.insert("line".to_string(), (lineno + 1).to_string());
    if let Some(u) = user {
        m.insert("run_as".to_string(), u.to_string());
    }
    if schedule == "@reboot" {
        m.insert(
            "persistence".to_string(),
            "runs at every boot — classic persistence vector".to_string(),
        );
    }
    m
}

// ─── system crontab + cron.d ─────────────────────────────────────────────────

fn scan_system_crontab(path: &Path) -> Vec<Finding> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        let Some(parsed) = parse_cron_line(line, true) else {
            continue;
        };
        let metadata = metadata_for(&parsed.schedule, parsed.user.as_deref(), lineno);
        findings.push(Finding {
            category: "cron",
            mechanism: mechanism_for(&parsed.schedule, "cron "),
            source: path.to_path_buf(),
            target: Some(parsed.command),
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata,
        });
    }
    findings
}

// ─── /etc/cron.{interval}/ ───────────────────────────────────────────────────

fn scan_interval_dir(interval: &str) -> Vec<Finding> {
    let dir = format!("/etc/cron.{interval}");
    let Ok(entries) = fs::read_dir(&dir) else {
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
        if name == "README" || name == "0anacron" || name.starts_with('.') {
            continue;
        }
        let mode = meta.permissions().mode();
        if mode & 0o111 == 0 {
            continue; // non-executable, run-parts ignores
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("interval".to_string(), interval.to_string());
        metadata.insert("size_bytes".to_string(), meta.len().to_string());

        findings.push(Finding {
            category: "cron",
            mechanism: format!("/etc/cron.{interval}/ — runs once {interval} via run-parts"),
            source: path,
            target: None,
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata,
        });
    }
    findings
}

// ─── anacrontab ──────────────────────────────────────────────────────────────

fn scan_anacrontab() -> Vec<Finding> {
    let path = Path::new("/etc/anacrontab");
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let first_tok = trimmed.split_whitespace().next();
        if first_tok.is_none_or(|t| t.contains('=')) {
            continue;
        }
        // Format: period delay job-id command...
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let period = parts[0];
        let delay_min = parts[1];
        let job_id = parts[2];
        let command = parts[3..].join(" ");

        let mut metadata = BTreeMap::new();
        metadata.insert("period_days".to_string(), period.to_string());
        metadata.insert("delay_min".to_string(), delay_min.to_string());
        metadata.insert("job_id".to_string(), job_id.to_string());
        metadata.insert("line".to_string(), (lineno + 1).to_string());

        let mech = if period.starts_with('@') {
            format!("anacron job `{job_id}` — {period}")
        } else {
            format!("anacron job `{job_id}` — runs every {period} days")
        };

        findings.push(Finding {
            category: "cron",
            mechanism: mech,
            source: path.to_path_buf(),
            target: Some(command),
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata,
        });
    }
    findings
}

// ─── per-user crontabs ───────────────────────────────────────────────────────

fn scan_user_spool(spool: &Path) -> Vec<Finding> {
    let Ok(entries) = fs::read_dir(spool) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Skip Debian "crontabs" subdir entries (handled by the other spool iteration)
        // and other spurious files
        if filename.starts_with('.') {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };

        let uid = uzers::get_user_by_name(filename).map_or(0, |u| u.uid());
        let scope = Scope::User {
            uid,
            name: filename.to_string(),
        };

        for (lineno, line) in content.lines().enumerate() {
            let Some(parsed) = parse_cron_line(line, false) else {
                continue;
            };
            let metadata = metadata_for(&parsed.schedule, None, lineno);
            findings.push(Finding {
                category: "cron",
                mechanism: mechanism_for(&parsed.schedule, "user crontab — "),
                source: path.clone(),
                target: Some(parsed.command),
                scope: scope.clone(),
                package: PackageOrigin::Unknown,
                metadata,
            });
        }
    }
    findings
}

// ─── at jobs ─────────────────────────────────────────────────────────────────

/// at spool files are job scripts; for v1, surface their existence rather than
/// trying to parse the embedded shell. Their presence + UNTRACKED ownership is
/// enough signal.
fn scan_at_jobs() -> Vec<Finding> {
    let dir = Path::new("/var/spool/at");
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Skip internal at files
        if name == ".SEQ" || name.starts_with('.') {
            continue;
        }
        let mut metadata = BTreeMap::new();
        metadata.insert("size_bytes".to_string(), meta.len().to_string());
        findings.push(Finding {
            category: "cron",
            mechanism: "at job (one-shot scheduled command)".to_string(),
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

    #[test]
    fn five_field_with_user_field() {
        let c = parse_cron_line("0 * * * * root /usr/bin/foo --arg", true).expect("parses");
        assert_eq!(c.schedule, "0 * * * *");
        assert_eq!(c.user.as_deref(), Some("root"));
        assert_eq!(c.command, "/usr/bin/foo --arg");
    }

    #[test]
    fn five_field_user_field_absent_for_user_crontab() {
        let c = parse_cron_line("*/5 * * * * /usr/bin/foo", false).expect("parses");
        assert_eq!(c.schedule, "*/5 * * * *");
        assert!(c.user.is_none());
        assert_eq!(c.command, "/usr/bin/foo");
    }

    #[test]
    fn at_reboot_schedule_single_token() {
        // @reboot is the persistence-relevant special schedule; it must not
        // consume four extra schedule tokens like a numeric schedule does.
        let c = parse_cron_line("@reboot root /usr/bin/persist", true).expect("parses");
        assert_eq!(c.schedule, "@reboot");
        assert_eq!(c.user.as_deref(), Some("root"));
        assert_eq!(c.command, "/usr/bin/persist");
    }

    #[test]
    fn skip_blank_and_comment_lines() {
        assert!(parse_cron_line("", true).is_none());
        assert!(parse_cron_line("   ", true).is_none());
        assert!(parse_cron_line("# comment", true).is_none());
        assert!(parse_cron_line("   # indented comment", true).is_none());
    }

    #[test]
    fn skip_env_var_assignment_lines() {
        // SHELL=, PATH=, MAILTO=, HOME=, etc. — the env-var convention is
        // "first whitespace token contains an `=`".
        assert!(parse_cron_line("SHELL=/bin/bash", true).is_none());
        assert!(parse_cron_line("PATH=/usr/bin:/bin", true).is_none());
        assert!(parse_cron_line("MAILTO=root", false).is_none());
    }

    #[test]
    fn require_complete_schedule_user_and_command() {
        // Truncated 5-field schedule (only 4 tokens before command).
        assert!(parse_cron_line("0 * * * /usr/bin/foo", false).is_none());
        // Schedule but no command.
        assert!(parse_cron_line("0 * * * *", false).is_none());
        // has_user=true but no command after the user.
        assert!(parse_cron_line("@reboot root", true).is_none());
    }
}
