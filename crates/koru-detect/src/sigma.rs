//! Sigma export: gives a validated rule pack as Sigma YAML. Rules are
//! already in Sigma form; the export fully validates the pack first, then serves the source
//! files by name order, content unchanged.

use std::path::Path;

use crate::{RuleError, read_rule_pack};

/// For each rule in the pack: (file name, YAML content). An error if the pack fails validation.
pub fn export_sigma(source: &Path) -> Result<Vec<(String, String)>, RuleError> {
    read_rule_pack(source)?;
    let mut files = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(source)
        .map_err(|e| RuleError::Schema(format!("the rule directory could not be read: {e}")))?
        .filter_map(|g| g.ok())
        .filter(|g| g.file_name().to_string_lossy().ends_with(".yml"))
        .collect();
    entries.sort_by_key(|g| g.file_name());
    for input in entries {
        let name = input.file_name().to_string_lossy().into_owned();
        let content = std::fs::read_to_string(input.path())
            .map_err(|e| RuleError::Schema(format!("a rule file could not be read: {e}")))?;
        files.push((name, content));
    }
    if files.is_empty() {
        return Err(RuleError::Schema("no .yml file in the rule directory".to_string()));
    }
    Ok(files)
}
