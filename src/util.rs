use std::collections::HashSet;
use std::path::{Path, PathBuf};

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
