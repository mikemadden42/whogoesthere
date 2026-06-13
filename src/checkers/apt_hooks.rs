use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};

pub struct AptHooksChecker;

const APT_CONF_DIR: &str = "/etc/apt/apt.conf.d";
const APT_CONF_TOPLEVEL: &str = "/etc/apt/apt.conf";

/// Persistence-relevant apt-config directives. Each holds one or more shell
/// commands that apt runs at fixed points in its lifecycle. An attacker
/// dropping a `.conf` file in `apt.conf.d/` with one of these directives gets
/// code execution the next time the admin runs `apt install`, `apt update`,
/// or any other dpkg-invoking command.
const HOOK_DIRECTIVES: &[&str] = &[
    "DPkg::Pre-Install-Pkgs",
    "DPkg::Pre-Invoke",
    "DPkg::Post-Invoke",
    "DPkg::Post-Invoke-Success",
    "APT::Update::Pre-Invoke",
    "APT::Update::Post-Invoke",
    "APT::Update::Post-Invoke-Success",
];

impl Checker for AptHooksChecker {
    fn name(&self) -> &'static str {
        "apt_hooks"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_apt_conf_file(Path::new(APT_CONF_TOPLEVEL)));
        if let Ok(entries) = fs::read_dir(APT_CONF_DIR) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = entry.metadata() else { continue };
                if !meta.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                // Editor backups and dotfiles aren't read by apt.
                if name.starts_with('.') || name.ends_with('~') {
                    continue;
                }
                findings.extend(scan_apt_conf_file(&path));
            }
        }
        findings
    }
}

fn scan_apt_conf_file(path: &Path) -> Vec<Finding> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let stripped = strip_apt_conf_comments(&content);
    let mut findings = Vec::new();
    for directive in HOOK_DIRECTIVES {
        for cmd in extract_directive_values(&stripped, directive) {
            let mut metadata: BTreeMap<String, String> = BTreeMap::new();
            metadata.insert("directive".to_string(), (*directive).to_string());
            findings.push(Finding {
                category: "apt_hooks".to_string(),
                mechanism: format!("apt hook {directive} — runs on package operation"),
                source: path.to_path_buf(),
                target: Some(cmd),
                scope: Scope::System,
                package: PackageOrigin::Unknown,
                metadata,
            });
        }
    }
    findings
}

/// Strip apt.conf comments while leaving quoted strings intact. Recognizes
/// `//` line comments, `/* ... */` block comments, and `#` line comments
/// (apt accepts all three). Quoted strings copy through verbatim so a
/// `"//"` literal in a command body isn't truncated.
fn strip_apt_conf_comments(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut out = String::with_capacity(content.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            out.push('"');
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(bytes[i] as char);
                    out.push(bytes[i + 1] as char);
                    i += 2;
                } else {
                    out.push(bytes[i] as char);
                    i += 1;
                }
            }
            if i < bytes.len() {
                out.push('"');
                i += 1;
            }
        } else if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            if i + 1 < bytes.len() {
                i += 2;
            }
        } else if b == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else {
            out.push(b as char);
            i += 1;
        }
    }
    out
}

/// Extract every command-value associated with `directive` in `content`.
/// Handles three apt.conf forms:
///   * `<directive> "cmd";` — single value
///   * `<directive>:: "cmd";` — append-to-list (semantically equivalent to
///     single-value for our purposes)
///   * `<directive> { "cmd1"; "cmd2"; };` — block form with multiple values
///
/// Limitation: the hierarchical nested form
/// `DPkg { Pre-Invoke "cmd"; }` is not parsed. In practice every Ubuntu
/// `apt.conf.d/` file we have data for uses the flat directive form;
/// hierarchical nesting could be added if a real-world driver appears.
fn extract_directive_values(content: &str, directive: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = content.as_bytes();
    let mut start = 0;
    while let Some(rel) = content[start..].find(directive) {
        let abs = start + rel;
        start = abs + directive.len();

        // Boundary check: the directive must be a top-level identifier, not
        // a suffix or middle of another path. The previous byte must be
        // start-of-file, whitespace, `{`, `}`, or `;`.
        let prev_ok = abs == 0
            || matches!(
                bytes[abs - 1],
                b' ' | b'\t' | b'\n' | b'\r' | b'{' | b'}' | b';'
            );
        if !prev_ok {
            continue;
        }
        // The byte after the needle must not continue the identifier —
        // so `DPkg::Pre-Invoke-Foo` doesn't partial-match `DPkg::Pre-Invoke`.
        // `::` is special: it's either the append-list operator (followed by
        // whitespace or value sigil) or a namespace separator (followed by
        // another identifier chunk). Distinguish by what comes after the `::`.
        if let Some(&next) = bytes.get(start) {
            if next == b':' && bytes.get(start + 1) == Some(&b':') {
                if let Some(&after) = bytes.get(start + 2)
                    && (after.is_ascii_alphanumeric() || after == b'_' || after == b'-')
                {
                    // Namespace continuation like `DPkg::Pre-Invoke::Foo` —
                    // not our directive.
                    continue;
                }
                // Otherwise `::` is the append operator; fall through and let
                // the value-parser strip it.
            } else if next.is_ascii_alphanumeric() || next == b'_' || next == b'-' {
                continue;
            }
        }

        // Skip whitespace and the optional `::` append-list operator.
        let rest = content[start..].trim_start();
        let rest = rest.strip_prefix("::").unwrap_or(rest).trim_start();

        if let Some(after_quote) = rest.strip_prefix('"') {
            if let Some(end) = find_unescaped_quote(after_quote) {
                out.push(after_quote[..end].to_string());
            }
        } else if let Some(block_body) = rest.strip_prefix('{') {
            collect_quoted_in_block(block_body, &mut out);
        }
    }
    out
}

/// Walk a block body (the chars after `{`), pushing each quoted string into
/// `out`, until we hit the matching `}`. Tracks nested braces so a `{` in a
/// quoted body doesn't change depth.
fn collect_quoted_in_block(body: &str, out: &mut Vec<String>) {
    let bytes = body.as_bytes();
    let mut depth: i32 = 1;
    let mut i = 0;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'"' => {
                let body_start = i + 1;
                let inner = &body[body_start..];
                if let Some(end) = find_unescaped_quote(inner) {
                    out.push(inner[..end].to_string());
                    i = body_start + end + 1;
                    continue;
                }
                return;
            }
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
}

/// Find the next unescaped `"` in `s`, returning its byte offset (relative to
/// start of `s`). `\"` and `\\` are treated as escape sequences and don't
/// terminate. Returns `None` if no closing quote is found.
fn find_unescaped_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(content: &str, directive: &str) -> Vec<String> {
        let stripped = strip_apt_conf_comments(content);
        extract_directive_values(&stripped, directive)
    }

    #[test]
    fn single_value_form() {
        // `<directive> "cmd";`
        let c = r#"DPkg::Pre-Invoke "/usr/sbin/dpkg-preconfigure --apt || true";"#;
        assert_eq!(
            extract(c, "DPkg::Pre-Invoke"),
            vec!["/usr/sbin/dpkg-preconfigure --apt || true".to_string()]
        );
    }

    #[test]
    fn append_list_double_colon_form() {
        // `<directive>:: "cmd";` — equivalent to single-value for our needs.
        let c = r#"APT::Update::Post-Invoke-Success:: "/usr/lib/cnf-update-db";"#;
        assert_eq!(
            extract(c, "APT::Update::Post-Invoke-Success"),
            vec!["/usr/lib/cnf-update-db".to_string()]
        );
    }

    #[test]
    fn block_form_yields_one_value_per_string() {
        // The canonical Ubuntu vendor file shape — `{ "cmd"; "cmd"; };`
        let c = r#"DPkg::Post-Invoke {
            "/bin/touch /var/lib/foo/dirty";
            "/usr/bin/notify-foo || true";
        };"#;
        assert_eq!(
            extract(c, "DPkg::Post-Invoke"),
            vec![
                "/bin/touch /var/lib/foo/dirty".to_string(),
                "/usr/bin/notify-foo || true".to_string(),
            ]
        );
    }

    #[test]
    fn comments_do_not_shadow_directives() {
        // Both `//` and `/* */` and `#` should be stripped before matching.
        let c = r#"// a leading comment
/* and a block
   comment */
# and a hash one
DPkg::Pre-Invoke "/bin/echo hi";"#;
        assert_eq!(
            extract(c, "DPkg::Pre-Invoke"),
            vec!["/bin/echo hi".to_string()]
        );
    }

    #[test]
    fn comment_marker_inside_quoted_string_is_preserved() {
        // A literal `//` inside the command body must NOT be treated as the
        // start of a line comment — that would truncate the command.
        let c = r#"DPkg::Pre-Invoke "/bin/echo http://example.com/path";"#;
        assert_eq!(
            extract(c, "DPkg::Pre-Invoke"),
            vec!["/bin/echo http://example.com/path".to_string()]
        );
    }

    #[test]
    fn similar_named_directive_does_not_partial_match() {
        // Looking for `DPkg::Pre-Invoke` must NOT match `DPkg::Pre-Invoke-Foo`.
        let c = r#"DPkg::Pre-Invoke-Foo "decoy";"#;
        assert!(extract(c, "DPkg::Pre-Invoke").is_empty());
    }

    #[test]
    fn namespace_continuation_does_not_match() {
        // `DPkg::Pre-Invoke::SomeSub` is a *different* directive than
        // `DPkg::Pre-Invoke`. The `::` followed by more identifier chars
        // signals namespace continuation, not the append-list operator —
        // must not be claimed by the shorter needle.
        let c = r#"DPkg::Pre-Invoke::SomeSub "decoy";"#;
        assert!(extract(c, "DPkg::Pre-Invoke").is_empty());
        // But the longer directive itself does match normally.
        assert_eq!(
            extract(c, "DPkg::Pre-Invoke::SomeSub"),
            vec!["decoy".to_string()]
        );
    }

    #[test]
    fn escaped_quote_inside_value_does_not_terminate() {
        // `\"` in the command body is a literal quote, not the closing one.
        let c = r#"DPkg::Pre-Invoke "/bin/echo \"hello world\"";"#;
        assert_eq!(
            extract(c, "DPkg::Pre-Invoke"),
            vec![r#"/bin/echo \"hello world\""#.to_string()]
        );
    }

    #[test]
    fn nested_braces_in_value_do_not_terminate_block() {
        // A `{` inside a quoted command body must not push the brace-depth
        // counter, and a `}` inside one must not pop it.
        let c = r#"DPkg::Post-Invoke {
            "if [ -d /foo ]; then echo {nested}; fi";
            "/bin/true";
        };"#;
        let r = extract(c, "DPkg::Post-Invoke");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], "if [ -d /foo ]; then echo {nested}; fi");
        assert_eq!(r[1], "/bin/true");
    }

    #[test]
    fn directive_repeated_in_one_file_emits_each_occurrence() {
        // Real apt.conf.d/ files often append to the same directive name
        // multiple times in the same `.conf`. Every occurrence should yield
        // its value.
        let c = r#"DPkg::Pre-Invoke "/usr/bin/first";
DPkg::Pre-Invoke "/usr/bin/second";"#;
        let r = extract(c, "DPkg::Pre-Invoke");
        assert_eq!(
            r,
            vec!["/usr/bin/first".to_string(), "/usr/bin/second".to_string()]
        );
    }

    #[test]
    fn no_match_returns_empty() {
        let c = r#"APT::Architecture "amd64";
APT::Default-Release "stable";"#;
        assert!(extract(c, "DPkg::Pre-Invoke").is_empty());
        assert!(extract(c, "APT::Update::Pre-Invoke").is_empty());
    }
}
