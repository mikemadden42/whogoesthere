use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use uzers::os::unix::UserExt;

/// One section of an INI-like document: keys map to a list of values,
/// preserving order of repeats. List-valued semantics are load-bearing for
/// systemd's `ExecStart=` directives (which may appear multiple times) and
/// any other key that the consumer wants to iterate.
pub type IniSection = BTreeMap<String, Vec<String>>;

/// An entire INI-like document: section name → section. Used by the systemd
/// unit-file parser and the D-Bus service-file parser. Both formats share the
/// same lexical shape: `[Section]` headers, `key = value` lines, `#`/`;`
/// full-line comments, and tolerance of repeated keys.
pub type IniDoc = BTreeMap<String, IniSection>;

/// Parse an INI-like document. Blank lines and `#`/`;` full-line comments
/// are skipped. `[name]` opens a section; subsequent `key = value` lines
/// land in it (trimmed). Repeated keys accumulate into the value list in
/// source order. Lines before any section, or `key=value` lines outside a
/// section, are silently ignored. Backslash-at-EOL line continuation is
/// folded before tokenizing — see `fold_line_continuations`.
pub fn parse_ini(content: &str) -> IniDoc {
    let folded = fold_line_continuations(content);
    let mut doc: IniDoc = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in folded.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current = Some(trimmed[1..trimmed.len() - 1].to_string());
            continue;
        }
        let Some(section) = &current else { continue };
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        doc.entry(section.clone())
            .or_default()
            .entry(key.trim().to_string())
            .or_default()
            .push(value.trim().to_string());
    }
    doc
}

/// Fold backslash-at-EOL line continuations into single logical lines.
/// systemd unit files and udev rules both use `\` at the end of a line to
/// mean "the value continues on the next line". The continuation is joined
/// with a single space — sufficient because every consumer treats internal
/// whitespace as a separator. Lines without a trailing `\` pass through
/// unchanged. A file ending with a continuation (no following line) is
/// tolerated — the dangling buffer flushes as the final line.
pub fn fold_line_continuations(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut buf = String::new();
    for line in content.lines() {
        let stripped_right = line.trim_end();
        if let Some(without_bs) = stripped_right.strip_suffix('\\') {
            // `trim_end` after stripping the backslash collapses any
            // whitespace that sat between content and the `\`, so we don't
            // end up with a doubled separator when we re-join.
            let body = without_bs.trim_end();
            if buf.is_empty() {
                buf.push_str(body);
            } else {
                buf.push(' ');
                buf.push_str(body.trim_start());
            }
            continue;
        }
        if buf.is_empty() {
            out.push_str(line);
        } else {
            out.push_str(&buf);
            out.push(' ');
            out.push_str(line.trim_start());
            buf.clear();
        }
        out.push('\n');
    }
    if !buf.is_empty() {
        out.push_str(&buf);
        out.push('\n');
    }
    out
}

/// Canonicalize each path (resolving symlinks like `/lib` → `/usr/lib`) and
/// return the unique set in input order. Paths that fail to canonicalize
/// (typically non-existent dirs) are kept as-is — they'll just yield nothing
/// when scanned.
pub fn canonical_unique<I, P>(paths: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        let p = p.as_ref();
        let key = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        if seen.insert(key.clone()) {
            out.push(key);
        }
    }
    out
}

pub struct RealUser {
    pub uid: u32,
    pub name: String,
    pub home: PathBuf,
}

/// Enumerate "real" users: root and UID 1000..65534, with a real login shell.
/// Skips daemons, nologin accounts, and system users.
///
/// The UID range is deliberate. The Debian/Ubuntu/Fedora convention reserves
/// 1–999 for system accounts (created by package postinst scripts for daemons
/// like `postgres`, `nginx`, etc.) and 1000–65533 for human users; 65534 is
/// `nobody`. Excluding 1–999 keeps us from enumerating daemon dotfiles —
/// daemons don't have meaningful `~/.bashrc` etc., and surfacing their
/// (mostly empty) homes would be noise. The trade-off: a system account
/// that legitimately *does* host persistence (e.g. an admin-installed
/// service user with a real login shell at UID 500) won't be surveyed.
/// That's an accepted limitation — admins who care can rerun targeting
/// the specific home dirs, and the typical malware-triage case doesn't
/// hit this.
pub fn real_users() -> Vec<RealUser> {
    // SAFETY: uzers::all_users wraps getpwent(), which is not thread-safe.
    // whogoesthere is single-threaded, so this is fine.
    let iter = unsafe { uzers::all_users() };
    iter.filter(|u| {
        let uid = u.uid();
        uid == 0 || (1000..65534).contains(&uid)
    })
    .filter(|u| {
        let shell = u.shell().to_string_lossy().to_string();
        !shell.is_empty() && !shell.contains("nologin") && !shell.contains("false")
    })
    .map(|u| RealUser {
        uid: u.uid(),
        name: u.name().to_string_lossy().to_string(),
        home: u.home_dir().to_path_buf(),
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_passes_uninterrupted_content_through_unchanged() {
        let c = "[Unit]\nDescription=Foo\n[Service]\nExecStart=/bin/foo\n";
        // Trailing newline matches what `content.lines()` collects + the
        // synthetic newline we add per output line.
        assert_eq!(fold_line_continuations(c), c);
    }

    #[test]
    fn fold_joins_a_single_continuation_pair() {
        // The systemd "long ExecStart" style — one trailing `\` and a
        // continuation line that's indented for readability.
        let c = "ExecStart=/bin/foo \\\n    --arg1 --arg2\n";
        // Continuation is joined with a single space, indentation stripped.
        assert_eq!(
            fold_line_continuations(c),
            "ExecStart=/bin/foo --arg1 --arg2\n"
        );
    }

    #[test]
    fn fold_joins_multiple_consecutive_continuations() {
        let c = "ExecStart=/bin/foo \\\n    --a \\\n    --b \\\n    --c\n";
        assert_eq!(
            fold_line_continuations(c),
            "ExecStart=/bin/foo --a --b --c\n"
        );
    }

    #[test]
    fn fold_tolerates_dangling_continuation_at_end_of_file() {
        // A file ending with `\` and no following line — the buffered
        // partial line should still flush so we don't silently drop it.
        let c = "ExecStart=/bin/foo \\";
        let r = fold_line_continuations(c);
        assert!(r.starts_with("ExecStart=/bin/foo"));
    }
}
