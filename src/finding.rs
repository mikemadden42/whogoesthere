use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub category: String,
    pub mechanism: String,
    pub source: PathBuf,
    pub target: Option<String>,
    pub scope: Scope,
    pub package: PackageOrigin,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scope {
    /// Runs system-wide and as root (or whichever `User=` the unit declares).
    System,
    /// Defined in a system-wide path but for *user* scope — applies to every
    /// user's session, runs as them, not as root. The unit lives under
    /// `/etc/systemd/user/`, `/usr/lib/systemd/user/`, etc. and is sourced
    /// by every user's session manager. Semantically distinct from `System`:
    /// a system-wide reach, but per-user execution.
    UserGlobal,
    /// Defined in a specific user's home and applies only to that user's
    /// session. Carries the user's identity.
    User { uid: u32, name: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PackageOrigin {
    Owned { package: String },
    Untracked,
    Unknown,
}
