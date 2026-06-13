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
/// section, are silently ignored.
pub fn parse_ini(content: &str) -> IniDoc {
    let mut doc: IniDoc = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in content.lines() {
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
