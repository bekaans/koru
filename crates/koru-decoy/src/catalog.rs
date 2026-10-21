//! The `DecoyCatalog` implementation (koru-event): the detection layer takes the watched
//! paths, decoy ids, and "is a breadcrumb" data from this type, without knowing koru-decoy.

use std::collections::BTreeMap;
use std::path::Path;

use koru_event::{DecoyCatalog, WatchedPath, WatchedPathKind};

use crate::error::InstallError;
use crate::install::list_entries;
use crate::record::RecordEntry;
use crate::template::DecoyKind;

/// The decoy catalog built from the integrity record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Catalog {
    paths: BTreeMap<String, WatchedPath>,
}

impl Catalog {
    /// Reads from the integrity record in the state directory.
    pub fn read(state: &Path) -> Result<Catalog, InstallError> {
        Ok(Catalog::from_entries(&list_entries(state)?))
    }

    /// Builds from record entries.
    pub fn from_entries(entries: &[RecordEntry]) -> Catalog {
        let paths = entries
            .iter()
            .map(|g| {
                let kind = match g.kind {
                    DecoyKind::Decoy => WatchedPathKind::Decoy,
                    DecoyKind::Breadcrumb => WatchedPathKind::Breadcrumb,
                };
                (
                    g.path.clone(),
                    WatchedPath { path: g.path.clone(), decoy_id: g.id.clone(), kind, class: g.class.clone() },
                )
            })
            .collect();
        Catalog { paths }
    }
}

impl DecoyCatalog for Catalog {
    fn watched_paths(&self) -> Vec<WatchedPath> {
        self.paths.values().cloned().collect()
    }

    fn find(&self, path: &str) -> Option<WatchedPath> {
        self.paths.get(path).cloned()
    }
}
