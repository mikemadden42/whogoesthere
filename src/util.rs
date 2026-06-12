use std::collections::HashSet;
use std::path::{Path, PathBuf};

use uzers::os::unix::UserExt;

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
