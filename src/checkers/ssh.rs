use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};
use crate::util::real_users;

pub struct SshChecker;

/// OpenSSH key types we recognize as valid `keytype` tokens in an
/// `authorized_keys` line. Used as the boundary that separates the optional
/// leading options field from the key itself. The `sk-*@openssh.com` forms
/// are FIDO/U2F-backed keys.
const KEY_TYPES: &[&str] = &[
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

impl Checker for SshChecker {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn run(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        findings.extend(scan_sshd_config(Path::new("/etc/ssh/sshd_config")));
        if let Ok(entries) = fs::read_dir("/etc/ssh/sshd_config.d") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("conf") {
                    findings.extend(scan_sshd_config(&path));
                }
            }
        }

        findings.extend(scan_login_script(
            Path::new("/etc/ssh/sshrc"),
            &Scope::System,
            "system",
        ));

        for user in real_users() {
            let scope = Scope::User {
                uid: user.uid,
                name: user.name,
            };
            findings.extend(scan_authorized_keys(
                &user.home.join(".ssh/authorized_keys"),
                &scope,
            ));
            findings.extend(scan_login_script(
                &user.home.join(".ssh/rc"),
                &scope,
                "user",
            ));
        }

        findings
    }
}

fn scan_sshd_config(path: &Path) -> Vec<Finding> {
    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    if !meta.is_file() {
        return Vec::new();
    }
    let Ok(content) = fs::read_to_string(path) else {
        // Likely mode 0600 root-owned; surface a marker so we don't appear to
        // have cleared this surface when we never read it.
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "unreadable".to_string(),
            "rerun as root to inspect".to_string(),
        );
        metadata.insert("size_bytes".to_string(), meta.len().to_string());
        return vec![Finding {
            category: "ssh".to_string(),
            mechanism: "sshd_config (unreadable — likely 0600 root)".to_string(),
            source: path.to_path_buf(),
            target: None,
            scope: Scope::System,
            package: PackageOrigin::Unknown,
            metadata,
        }];
    };
    let mut findings = Vec::new();
    let mut current_match: Option<String> = None;
    for (lineno, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = strip_directive(line, "Match") {
            current_match = Some(rest.to_string());
            continue;
        }
        for directive in &["ForceCommand", "AuthorizedKeysCommand"] {
            let Some(value) = strip_directive(line, directive) else {
                continue;
            };
            let mut metadata = BTreeMap::new();
            metadata.insert("directive".to_string(), (*directive).to_string());
            metadata.insert("line".to_string(), (lineno + 1).to_string());
            if let Some(m) = &current_match {
                metadata.insert("match_block".to_string(), m.clone());
            }
            findings.push(Finding {
                category: "ssh".to_string(),
                mechanism: format!("sshd_config {directive}= — runs on every SSH login"),
                source: path.to_path_buf(),
                target: Some(value.to_string()),
                scope: Scope::System,
                package: PackageOrigin::Unknown,
                metadata,
            });
            break;
        }
    }
    findings
}

/// If `line` starts with `key` followed by `=` or whitespace (case-insensitive),
/// return the trimmed value. Matches `sshd_config`'s `Key value` and `Key=value`
/// shapes.
fn strip_directive<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    if line.len() <= key.len() {
        return None;
    }
    if !line[..key.len()].eq_ignore_ascii_case(key) {
        return None;
    }
    let sep = line.as_bytes()[key.len()];
    if !sep.is_ascii_whitespace() && sep != b'=' {
        return None;
    }
    Some(line[key.len() + 1..].trim())
}

fn scan_authorized_keys(path: &Path, scope: &Scope) -> Vec<Finding> {
    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    if !meta.is_file() {
        return Vec::new();
    }
    let Ok(content) = fs::read_to_string(path) else {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "unreadable".to_string(),
            "rerun as root to inspect".to_string(),
        );
        metadata.insert("size_bytes".to_string(), meta.len().to_string());
        return vec![Finding {
            category: "ssh".to_string(),
            mechanism: "authorized_keys (unreadable to current user)".to_string(),
            source: path.to_path_buf(),
            target: None,
            scope: scope.clone(),
            package: PackageOrigin::Unknown,
            metadata,
        }];
    };
    let mut findings = Vec::new();
    for (lineno, raw) in content.lines().enumerate() {
        let Some(key) = parse_authorized_key(raw) else {
            continue;
        };
        let mut metadata = BTreeMap::new();
        metadata.insert("line".to_string(), (lineno + 1).to_string());
        metadata.insert("keytype".to_string(), key.keytype);
        if let Some(opts) = &key.options {
            metadata.insert("options".to_string(), opts.clone());
            if let Some(cmd) = extract_forced_command(opts) {
                metadata.insert("forced_command".to_string(), cmd);
            }
        }
        findings.push(Finding {
            category: "ssh".to_string(),
            mechanism: "authorized_keys entry — grants passwordless SSH login".to_string(),
            source: path.to_path_buf(),
            target: key.comment,
            scope: scope.clone(),
            package: PackageOrigin::Unknown,
            metadata,
        });
    }
    findings
}

fn scan_login_script(path: &Path, scope: &Scope, location: &str) -> Vec<Finding> {
    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    if !meta.is_file() || meta.len() == 0 {
        return Vec::new();
    }
    let mut metadata = BTreeMap::new();
    metadata.insert("size_bytes".to_string(), meta.len().to_string());
    metadata.insert("location".to_string(), location.to_string());
    if fs::File::open(path).is_err() {
        metadata.insert(
            "unreadable".to_string(),
            "rerun as root to inspect".to_string(),
        );
    }
    let mech = if location == "system" {
        "/etc/ssh/sshrc — runs on every SSH login, system-wide"
    } else {
        "~/.ssh/rc — runs on every SSH login as this user"
    };
    vec![Finding {
        category: "ssh".to_string(),
        mechanism: mech.to_string(),
        source: path.to_path_buf(),
        target: None,
        scope: scope.clone(),
        package: PackageOrigin::Unknown,
        metadata,
    }]
}

struct AuthKey {
    options: Option<String>,
    keytype: String,
    comment: Option<String>,
}

/// Parse one `authorized_keys` line into `[options] keytype keydata [comment]`.
/// Locates the first whole-word occurrence of a known key type token; anything
/// before it is options, the next token after it is the keydata, and the rest
/// is comment. Returns `None` for blank/comment lines and lines we can't
/// confidently classify (no recognized key type, or no keydata after the type).
///
/// Limitation: if `command="..."` in the options field literally contains a
/// recognized SSH key type token surrounded by spaces, the wrong split point
/// will win. That's a real edge case but vanishingly rare in practice and not
/// worth a quoted-string tokenizer for v1.
fn parse_authorized_key(line: &str) -> Option<AuthKey> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (type_pos, keytype) = KEY_TYPES
        .iter()
        .filter_map(|kt| find_whole_token(line, kt).map(|pos| (pos, *kt)))
        .min_by_key(|(pos, _)| *pos)?;
    let options = if type_pos == 0 {
        None
    } else {
        Some(line[..type_pos].trim_end().to_string())
    };
    let after = line[type_pos + keytype.len()..].trim_start();
    let mut iter = after.split_whitespace();
    iter.next()?; // keydata — required, ignored
    let comment_tokens: Vec<&str> = iter.collect();
    let comment = if comment_tokens.is_empty() {
        None
    } else {
        Some(comment_tokens.join(" "))
    };
    Some(AuthKey {
        options,
        keytype: keytype.to_string(),
        comment,
    })
}

/// Find `token` in `line` only where it's bounded by whitespace (or
/// start/end-of-string) on both sides — so a `ssh-rsa` substring inside a
/// non-whitespace span like `"someoldssh-rsakey"` won't match.
fn find_whole_token(line: &str, token: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let token_len = token.len();
    let mut start = 0;
    while let Some(rel) = line[start..].find(token) {
        let abs = start + rel;
        let prev_ok = abs == 0 || bytes[abs - 1].is_ascii_whitespace();
        let after = abs + token_len;
        let next_ok = after == bytes.len() || bytes[after].is_ascii_whitespace();
        if prev_ok && next_ok {
            return Some(abs);
        }
        start = abs + 1;
    }
    None
}

/// Extract the value of `command="..."` from an `authorized_keys` options field.
/// Case-insensitive on the key; respects `\"` escape inside the value.
fn extract_forced_command(options: &str) -> Option<String> {
    let lower = options.to_ascii_lowercase();
    let start = lower.find("command=\"")?;
    let val_start = start + "command=\"".len();
    let bytes = options.as_bytes();
    let mut i = val_start;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => i += 2,
            b'"' => return Some(options[val_start..i].to_string()),
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_without_options() {
        let line = "ssh-ed25519 AAAAC3Nzaaaa madden@host";
        let k = parse_authorized_key(line).expect("parses");
        assert!(k.options.is_none());
        assert_eq!(k.keytype, "ssh-ed25519");
        assert_eq!(k.comment.as_deref(), Some("madden@host"));
    }

    #[test]
    fn parse_key_with_options_including_forced_command() {
        let line = r#"command="/usr/bin/rsync --server",no-pty,no-port-forwarding ssh-rsa AAAAB3NzaC1yc2EAAAAB backup@host"#;
        let k = parse_authorized_key(line).expect("parses");
        let opts = k.options.as_deref().expect("has options");
        assert!(opts.starts_with(r#"command="/usr/bin/rsync --server""#));
        assert!(opts.ends_with("no-port-forwarding"));
        assert_eq!(k.keytype, "ssh-rsa");
        assert_eq!(k.comment.as_deref(), Some("backup@host"));
    }

    #[test]
    fn parse_key_no_comment() {
        let line = "ssh-rsa AAAA";
        let k = parse_authorized_key(line).expect("parses");
        assert!(k.options.is_none());
        assert!(k.comment.is_none());
    }

    #[test]
    fn parse_key_skips_blank_and_comment() {
        assert!(parse_authorized_key("").is_none());
        assert!(parse_authorized_key("   ").is_none());
        assert!(parse_authorized_key("# disabled key").is_none());
    }

    #[test]
    fn parse_key_rejects_unknown_keytype() {
        // No recognized key type → can't confidently classify, return None.
        // (A different parser might decide a single token before some base64
        // is the keytype; we deliberately don't guess.)
        assert!(parse_authorized_key("not-a-real-keytype AAAA comment").is_none());
    }

    #[test]
    fn parse_key_with_sk_fido_keytype() {
        let line = "sk-ssh-ed25519@openssh.com AAAA fido-key";
        let k = parse_authorized_key(line).expect("parses");
        assert_eq!(k.keytype, "sk-ssh-ed25519@openssh.com");
        assert_eq!(k.comment.as_deref(), Some("fido-key"));
    }

    #[test]
    fn extract_forced_command_basic() {
        let opts = r#"command="/tmp/evil",no-pty"#;
        assert_eq!(extract_forced_command(opts), Some("/tmp/evil".to_string()));
    }

    #[test]
    fn extract_forced_command_case_insensitive_key_and_quoted_escape() {
        // Real authorized_keys can use the COMMAND= spelling (case-insensitive
        // per the OpenSSH spec) and embed escaped quotes in the value.
        let opts = r#"COMMAND="echo \"hi\"",no-pty"#;
        assert_eq!(
            extract_forced_command(opts),
            Some(r#"echo \"hi\""#.to_string())
        );
    }

    #[test]
    fn extract_forced_command_none_when_absent() {
        assert!(extract_forced_command("no-pty,no-port-forwarding").is_none());
    }

    #[test]
    fn find_whole_token_rejects_substring_in_non_whitespace_span() {
        // The substring `ssh-rsa` inside a non-whitespace run should not match.
        assert!(find_whole_token("xxssh-rsayy AAAA", "ssh-rsa").is_none());
        // But preceded by whitespace and followed by whitespace, it does.
        assert_eq!(find_whole_token("opts ssh-rsa AAAA", "ssh-rsa"), Some(5));
    }

    #[test]
    fn strip_directive_handles_both_separator_forms() {
        assert_eq!(
            strip_directive("ForceCommand /tmp/evil", "ForceCommand"),
            Some("/tmp/evil")
        );
        assert_eq!(
            strip_directive("ForceCommand=/tmp/evil", "ForceCommand"),
            Some("/tmp/evil")
        );
        // Case-insensitive on the key.
        assert_eq!(
            strip_directive("forcecommand /tmp/evil", "ForceCommand"),
            Some("/tmp/evil")
        );
        // Different directive name → no match.
        assert_eq!(strip_directive("Port 22", "ForceCommand"), None);
        // Just the bare key with nothing after → no match.
        assert_eq!(strip_directive("ForceCommand", "ForceCommand"), None);
    }
}
