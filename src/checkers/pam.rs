use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};

pub struct PamChecker;

const PAM_DIR: &str = "/etc/pam.d";

/// Recognized PAM rule types. The leading-dash forms (`-auth`, etc.) tell
/// PAM "silently skip if the module file isn't present" — same semantic
/// position in the rule chain, just with a missing-module tolerance.
const PAM_TYPES: &[&str] = &[
    "auth",
    "account",
    "password",
    "session",
    "-auth",
    "-account",
    "-password",
    "-session",
];

impl Checker for PamChecker {
    fn name(&self) -> &'static str {
        "pam"
    }

    fn run(&self) -> Vec<Finding> {
        let Ok(entries) = fs::read_dir(PAM_DIR) else {
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
            // Skip editor backups and dotfiles — they're not active PAM services.
            if name.starts_with('.') || name.ends_with('~') {
                continue;
            }
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            findings.extend(scan_pam_file(&content, &path));
        }
        findings
    }
}

fn scan_pam_file(content: &str, source: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let service = source.file_name().and_then(|n| n.to_str()).unwrap_or("?");
    for (lineno, raw) in content.lines().enumerate() {
        let Some(rule) = parse_pam_line(raw) else {
            continue;
        };
        let mut metadata = BTreeMap::new();
        metadata.insert("service".to_string(), service.to_string());
        metadata.insert("type".to_string(), rule.kind.to_string());
        metadata.insert("control".to_string(), rule.control.to_string());
        metadata.insert("line".to_string(), (lineno + 1).to_string());
        if !rule.args.is_empty() {
            metadata.insert("module_args".to_string(), rule.args.to_string());
        }
        findings.push(Finding {
            category: "pam".to_string(),
            mechanism: format!(
                "PAM rule ({service}/{}) — runs at authentication time",
                rule.kind
            ),
            source: source.to_path_buf(),
            target: Some(rule.module.to_string()),
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata,
        });
    }
    findings
}

struct PamRule<'a> {
    kind: &'a str,
    control: &'a str,
    module: &'a str,
    args: &'a str,
}

/// Parse one PAM line into `type control module-path [args...]`. Returns
/// `None` for blank/comment lines, lines that don't start with a recognized
/// PAM rule type (the `@include filename` legacy form is intentionally
/// unsupported — the standard `<type> include <filename>` shape covers the
/// common case), and lines that are syntactically truncated.
fn parse_pam_line(line: &str) -> Option<PamRule<'_>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let bytes = line.as_bytes();

    // Field 1: type
    let type_end = line.find(char::is_whitespace)?;
    let kind = &line[..type_end];
    if !PAM_TYPES.contains(&kind) {
        return None;
    }

    let mut pos = skip_whitespace(bytes, type_end);

    // Field 2: control — either a single token or a `[key=value ...]` expr.
    let control_end = if bytes.get(pos) == Some(&b'[') {
        let rel = line[pos..].find(']')?;
        pos + rel + 1
    } else {
        let rel = line[pos..].find(char::is_whitespace)?;
        pos + rel
    };
    let control = &line[pos..control_end];

    pos = skip_whitespace(bytes, control_end);
    if pos >= bytes.len() {
        return None;
    }

    // Field 3: module path
    let module_end = line[pos..]
        .find(char::is_whitespace)
        .map_or(line.len(), |i| pos + i);
    let module = &line[pos..module_end];

    // Field 4: args (rest of line, trimmed)
    let args = line.get(module_end..).unwrap_or("").trim();

    Some(PamRule {
        kind,
        control,
        module,
        args,
    })
}

fn skip_whitespace(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_unwrap(line: &str) -> PamRule<'_> {
        parse_pam_line(line).expect("parses")
    }

    #[test]
    fn parses_minimal_three_field_line() {
        let r = parse_unwrap("auth required pam_env.so");
        assert_eq!(r.kind, "auth");
        assert_eq!(r.control, "required");
        assert_eq!(r.module, "pam_env.so");
        assert_eq!(r.args, "");
    }

    #[test]
    fn parses_line_with_module_arguments() {
        let r = parse_unwrap("auth required pam_faillock.so preauth silent deny=4 unlock_time=120");
        assert_eq!(r.module, "pam_faillock.so");
        assert_eq!(r.args, "preauth silent deny=4 unlock_time=120");
    }

    #[test]
    fn parses_leading_dash_type_variant() {
        // -session means "silently skip if module is missing" — same semantic
        // slot as session, distinguish in metadata.
        let r = parse_unwrap("-session optional pam_systemd.so");
        assert_eq!(r.kind, "-session");
        assert_eq!(r.module, "pam_systemd.so");
    }

    #[test]
    fn parses_bracketed_complex_control() {
        let r = parse_unwrap(
            "auth [success=done new_authtok_reqd=done default=ignore] pam_unix.so try_first_pass",
        );
        assert_eq!(r.kind, "auth");
        // Control is the entire bracketed expression, brackets included.
        assert_eq!(
            r.control,
            "[success=done new_authtok_reqd=done default=ignore]"
        );
        assert_eq!(r.module, "pam_unix.so");
        assert_eq!(r.args, "try_first_pass");
    }

    #[test]
    fn parses_include_directive_with_sibling_file_as_module() {
        // `include` chains to another file in /etc/pam.d/; the "module" slot
        // names that file rather than a .so path. We don't try to validate.
        let r = parse_unwrap("account include password-auth");
        assert_eq!(r.control, "include");
        assert_eq!(r.module, "password-auth");
    }

    #[test]
    fn tolerates_tabs_and_runs_of_spaces() {
        // Real Fedora-shipped files use heavy alignment whitespace.
        let r = parse_unwrap("auth\trequired\t\t  \tpam_env.so");
        assert_eq!(r.kind, "auth");
        assert_eq!(r.control, "required");
        assert_eq!(r.module, "pam_env.so");
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        assert!(parse_pam_line("").is_none());
        assert!(parse_pam_line("   ").is_none());
        assert!(parse_pam_line("# generated by authselect").is_none());
        assert!(parse_pam_line("   # indented comment").is_none());
    }

    #[test]
    fn rejects_unknown_type_token() {
        // We don't recognize the legacy `@include` shape; better to skip than
        // to misclassify (a real `@include filename` line shouldn't yield a
        // finding with kind="@include").
        assert!(parse_pam_line("@include common-auth").is_none());
        assert!(parse_pam_line("garbage line").is_none());
    }

    #[test]
    fn rejects_truncated_lines() {
        // type only.
        assert!(parse_pam_line("auth").is_none());
        // type + control, but no module path.
        assert!(parse_pam_line("auth required").is_none());
        assert!(parse_pam_line("auth required ").is_none());
    }
}
