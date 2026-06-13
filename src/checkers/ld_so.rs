use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};

pub struct LdSoChecker;

impl Checker for LdSoChecker {
    fn name(&self) -> &'static str {
        "ld_so"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(check_preload_file());
        findings.extend(check_environment_file());
        findings.extend(scan_conf_file(Path::new("/etc/ld.so.conf")));
        if let Ok(entries) = fs::read_dir("/etc/ld.so.conf.d") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("conf") {
                    findings.extend(scan_conf_file(&path));
                }
            }
        }
        findings
    }
}

fn check_preload_file() -> Vec<Finding> {
    let path = Path::new("/etc/ld.so.preload");
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| Finding {
            category: "ld_so".to_string(),
            mechanism: "ld.so preload (loaded into every dynamically-linked process)".into(),
            source: path.to_path_buf(),
            target: Some(line.to_string()),
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata: BTreeMap::new(),
        })
        .collect()
}

fn check_environment_file() -> Vec<Finding> {
    let path = Path::new("/etc/environment");
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("LD_PRELOAD="))
        .map(|value| Finding {
            category: "ld_so".to_string(),
            mechanism: "LD_PRELOAD set in /etc/environment".into(),
            source: path.to_path_buf(),
            target: Some(unquote_env_value(value).to_string()),
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata: BTreeMap::new(),
        })
        .collect()
}

/// Strip one matching pair of outer quotes from an `/etc/environment` value.
/// The previous implementation used `trim_matches` over a closure that
/// accepted *either* `"` or `'`, which would eat both layers of a value like
/// `"'mixed'"`. This is faithful instead: only strip if the value starts and
/// ends with the same quote char, and only strip one layer.
fn unquote_env_value(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// Walk one ld.so.conf-format file: blank/comment lines skipped, each bare
/// path emits a search-path finding, each `include <glob>...` emits one
/// finding per glob argument (typically just one). Used both for the
/// top-level `/etc/ld.so.conf` and each `/etc/ld.so.conf.d/*.conf`. The
/// malware signal here is an UNTRACKED `.conf` in `/etc/ld.so.conf.d/`
/// containing a path the attacker controls — the loader will then prefer
/// any `.so` planted there over the legitimate version (T1574.006).
fn scan_conf_file(path: &Path) -> Vec<Finding> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for (lineno, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        findings.extend(parse_conf_line(line, path, lineno));
    }
    findings
}

fn parse_conf_line(line: &str, source: &Path, lineno: usize) -> Vec<Finding> {
    let mut tokens = line.split_whitespace();
    let Some(first) = tokens.next() else {
        return Vec::new();
    };
    let (mechanism, targets): (&str, Vec<String>) = if first == "include" {
        // `include <glob>...` — the rest of the tokens are file patterns
        // pulled in. Surface each so an injected `include /tmp/evil.conf`
        // is itself a visible finding.
        (
            "ld.so include directive (pulls in additional search-path config)",
            tokens.map(str::to_string).collect(),
        )
    } else {
        // Bare path line. Treat the entire line as the path (paths don't
        // contain whitespace per the format spec; using `line` rather than
        // `first` preserves any unusual input verbatim for the finding).
        (
            "ld.so search-path entry (adds directory to library lookup)",
            vec![line.to_string()],
        )
    };
    targets
        .into_iter()
        .map(|target| {
            let mut metadata = BTreeMap::new();
            metadata.insert("line".to_string(), (lineno + 1).to_string());
            Finding {
                category: "ld_so".to_string(),
                mechanism: mechanism.to_string(),
                source: source.to_path_buf(),
                target: Some(target),
                scope: Scope::System,
                package: PackageOrigin::Unknown,
                metadata,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Vec<Finding> {
        parse_conf_line(line, Path::new("/etc/ld.so.conf.d/test.conf"), 0)
    }

    #[test]
    fn unquote_strips_one_matching_pair_of_outer_quotes() {
        // Plain double-quoted and single-quoted cases — strip the outer pair.
        assert_eq!(unquote_env_value(r#""/lib/foo.so""#), "/lib/foo.so");
        assert_eq!(unquote_env_value("'/lib/foo.so'"), "/lib/foo.so");
        // Mismatched quotes — the previous trim_matches impl would have eaten
        // BOTH layers; the correct behavior is to leave them entirely.
        assert_eq!(unquote_env_value(r#""'inner'""#), "'inner'");
        // Asymmetric (open with `"`, close with `'`) — don't strip.
        assert_eq!(unquote_env_value(r#""mismatched'"#), r#""mismatched'"#);
        // Unquoted — passthrough.
        assert_eq!(unquote_env_value("/lib/foo.so"), "/lib/foo.so");
        // Empty + single-char inputs — no quote pair, passthrough.
        assert_eq!(unquote_env_value(""), "");
        assert_eq!(unquote_env_value("\""), "\"");
    }

    #[test]
    fn bare_path_line_yields_one_search_path_finding() {
        let f = parse("/usr/lib64/llvm21/lib64");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].target.as_deref(), Some("/usr/lib64/llvm21/lib64"));
        assert!(f[0].mechanism.contains("search-path entry"));
    }

    #[test]
    fn include_directive_with_single_glob() {
        let f = parse("include ld.so.conf.d/*.conf");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].target.as_deref(), Some("ld.so.conf.d/*.conf"));
        assert!(f[0].mechanism.contains("include directive"));
    }

    #[test]
    fn include_directive_with_multiple_globs_emits_per_glob() {
        // The spec allows multiple file patterns per include line; surface
        // each so an injected extra arg is independently visible.
        let f = parse("include /etc/a.conf /etc/b.conf /etc/c.conf");
        assert_eq!(f.len(), 3);
        let targets: Vec<&str> = f.iter().filter_map(|x| x.target.as_deref()).collect();
        assert_eq!(targets, vec!["/etc/a.conf", "/etc/b.conf", "/etc/c.conf"]);
    }

    #[test]
    fn scan_conf_file_skips_blank_and_comment_lines() {
        // Write a synthetic temp file to exercise the full scan_conf_file path.
        let tmp = std::env::temp_dir().join("whogoesthere-ldso-test.conf");
        std::fs::write(
            &tmp,
            "# leading comment\n\
             \n\
             /opt/real/lib\n\
             # mid comment\n\
             /opt/another/lib\n",
        )
        .unwrap();
        let f = scan_conf_file(&tmp);
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].target.as_deref(), Some("/opt/real/lib"));
        assert_eq!(f[1].target.as_deref(), Some("/opt/another/lib"));
    }
}
