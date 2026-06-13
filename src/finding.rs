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
    System,
    User { uid: u32, name: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PackageOrigin {
    Owned { package: String },
    Untracked,
    Unknown,
}
