use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};
use crate::util::{canonical_unique, fold_line_continuations};

pub struct UdevChecker;

const RULE_DIRS: &[&str] = &[
    "/etc/udev/rules.d",
    "/run/udev/rules.d",
    "/lib/udev/rules.d",
    "/usr/lib/udev/rules.d",
];

const RUN_PREFIXES: &[&str] = &[
    "RUN{program}+=",
    "RUN{program}:=",
    "RUN{program}=",
    "RUN+=",
    "RUN:=",
    "RUN=",
];

const IMPORT_PROGRAM_PREFIXES: &[&str] =
    &["IMPORT{program}+=", "IMPORT{program}:=", "IMPORT{program}="];

impl Checker for UdevChecker {
    fn name(&self) -> &'static str {
        "udev"
    }

    fn run(&self) -> Vec<Finding> {
        canonical_unique(RULE_DIRS)
            .iter()
            .flat_map(|d| scan_rules_dir(d))
            .collect()
    }
}

fn scan_rules_dir(dir: &Path) -> Vec<Finding> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rules") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        findings.extend(scan_rules_file(&content, &path));
    }
    findings
}

fn scan_rules_file(content: &str, source: &Path) -> Vec<Finding> {
    // udev rules use the same `\`-at-EOL line continuation as systemd units,
    // so fold first; then a multi-physical-line RUN+=/IMPORT{program}=
    // directive presents as one logical line and the existing per-line
    // tokenizer handles it correctly.
    let folded = fold_line_continuations(content);
    let mut findings = Vec::new();
    for (lineno, line) in folded.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for (directive, value) in extract_directives(line) {
            let mut metadata = BTreeMap::new();
            metadata.insert("directive".to_string(), directive.to_string());
            metadata.insert("line".to_string(), (lineno + 1).to_string());
            findings.push(Finding {
                category: "udev".to_string(),
                mechanism: format!("udev rule {directive} — runs command on matching device event"),
                source: source.to_path_buf(),
                target: Some(value),
                scope: Scope::System,
                package: PackageOrigin::Unknown,
                metadata,
            });
        }
    }
    findings
}

fn extract_directives(line: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    extract_with_prefixes(line, RUN_PREFIXES, "RUN", &mut out);
    extract_with_prefixes(line, IMPORT_PROGRAM_PREFIXES, "IMPORT{program}", &mut out);
    out
}

fn extract_with_prefixes(
    line: &str,
    prefixes: &[&str],
    canonical: &'static str,
    out: &mut Vec<(&'static str, String)>,
) {
    let mut pos = 0;
    while pos < line.len() {
        let mut best: Option<(usize, usize)> = None;
        for p in prefixes {
            if let Some(idx) = line[pos..].find(p) {
                let abs = pos + idx;
                if best.is_none_or(|(s, _)| abs < s) {
                    best = Some((abs, p.len()));
                }
            }
        }
        let Some((start, plen)) = best else { return };
        let after = start + plen;
        let bytes = line.as_bytes();
        if after >= bytes.len() || bytes[after] != b'"' {
            pos = after;
            continue;
        }
        let val_start = after + 1;
        let Some(close_offset) = line[val_start..].find('"') else {
            return;
        };
        let value = &line[val_start..val_start + close_offset];
        out.push((canonical, value.to_string()));
        pos = val_start + close_offset + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_run(line: &str) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        extract_with_prefixes(line, RUN_PREFIXES, "RUN", &mut out);
        out
    }

    fn extract_import(line: &str) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        extract_with_prefixes(line, IMPORT_PROGRAM_PREFIXES, "IMPORT{program}", &mut out);
        out
    }

    #[test]
    fn extracts_basic_run_directive() {
        assert_eq!(
            extract_run(r#"RUN+="/usr/bin/foo""#),
            vec![("RUN", "/usr/bin/foo".to_string())]
        );
    }

    #[test]
    fn extracts_each_assignment_operator_variant() {
        // +=, :=, = should all match — they're three legit udev assignment forms.
        assert_eq!(extract_run(r#"RUN+="/a""#), vec![("RUN", "/a".to_string())]);
        assert_eq!(extract_run(r#"RUN:="/b""#), vec![("RUN", "/b".to_string())]);
        assert_eq!(extract_run(r#"RUN="/c""#), vec![("RUN", "/c".to_string())]);
    }

    #[test]
    fn extracts_multiple_directives_on_the_same_line() {
        // Real udev lines comma-separate match keys and assignments.
        let r = extract_run(r#"KERNEL=="usb*", RUN+="/usr/bin/a", RUN+="/usr/bin/b""#);
        assert_eq!(
            r,
            vec![
                ("RUN", "/usr/bin/a".to_string()),
                ("RUN", "/usr/bin/b".to_string()),
            ]
        );
    }

    #[test]
    fn skips_directive_when_value_is_not_quoted() {
        // A `RUN+=` not followed by `"` is malformed for our purposes — skip,
        // don't try to guess. The next iteration advances past the bad match.
        assert!(extract_run("RUN+=/usr/bin/foo").is_empty());
    }

    #[test]
    fn does_not_false_positive_on_run_substring_inside_a_value() {
        // The string `RUN+=` appearing inside a quoted command body must not
        // produce a phantom second finding — `pos` advances past the closing
        // quote so the inner text is never re-scanned.
        let r = extract_run(r#"RUN+="echo RUN+=fake_inside_value""#);
        assert_eq!(r, vec![("RUN", "echo RUN+=fake_inside_value".to_string())]);
    }

    #[test]
    fn returns_early_on_unterminated_value_but_keeps_prior_extracts() {
        // No closing quote on the second value — we lose that one but the
        // first extract still lands.
        let r = extract_run(r#"RUN+="/usr/bin/foo", RUN+="unterminated"#);
        assert_eq!(r, vec![("RUN", "/usr/bin/foo".to_string())]);
    }

    #[test]
    fn import_program_only_matches_the_program_variant() {
        // IMPORT{file}=, IMPORT{db}=, IMPORT{cmdline}= etc. don't execute a
        // binary, so only IMPORT{program}* is a persistence vector.
        assert_eq!(
            extract_import(r#"IMPORT{program}+="/usr/bin/foo""#),
            vec![("IMPORT{program}", "/usr/bin/foo".to_string())]
        );
        assert!(extract_import(r#"IMPORT{file}="/etc/something""#).is_empty());
        assert!(extract_import(r#"IMPORT{db}="ID_FOO""#).is_empty());
    }
}
