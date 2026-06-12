use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Finding {
    pub category: &'static str,
    pub mechanism: String,
    pub source: PathBuf,
    pub target: Option<String>,
    pub scope: Scope,
    pub package: PackageOrigin,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scope {
    System,
    User { uid: u32, name: String },
}

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PackageOrigin {
    Owned { package: String },
    Untracked,
    Unknown,
}
