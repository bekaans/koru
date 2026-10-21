//! A decoy package: the `*.toml` templates in a directory (`packages/decoys/`).
//!
//! Checked at the package level: at least one template; unique ids and target paths; the
//! targets of cross-references (`{{template:name}}`, `{{template:path}}`); no unused values; and
//! trial generations (each must pass the format and safety checks). A validated [`Package`]
//! always yields installable content.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::generation::generate;
use crate::placeholder::{self, Placeholder};
use crate::template::{self, TIME_FIELDS, Template, TemplateError, Value};

/// The number of trial generations in package validation. Different combinations of random
/// picks must also pass the format and safety checks.
const TRIAL_GENERATIONS: usize = 16;

/// A validated decoy package.
#[derive(Debug, Clone)]
pub struct Package {
    templates: Vec<Template>,
}

impl Package {
    /// The templates (in file-name order).
    pub fn templates(&self) -> &[Template] {
        &self.templates
    }

    /// A template by id.
    pub fn template(&self, id: &str) -> Option<&Template> {
        self.templates.iter().find(|s| s.id == id)
    }
}

/// When a package cannot be read or validated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackageError {
    /// A file or directory could not be read.
    #[error("{file}: could not be read: {reason}")]
    Read {
        /// The file.
        file: String,
        /// The reason.
        reason: String,
    },
    /// An invalid template.
    #[error("{file}: {error}")]
    Template {
        /// The file.
        file: String,
        /// The template error.
        error: TemplateError,
    },
    /// A package-level rule violation or a trial-generation error.
    #[error("{0}")]
    Package(String),
}

fn read_error(path: &Path, reason: impl ToString) -> PackageError {
    PackageError::Read { file: path.display().to_string(), reason: reason.to_string() }
}

/// The template files in a directory (`*.toml`, in file-name order). A symlink or a non-regular
/// file is rejected.
fn template_files(dir: &Path) -> Result<Vec<PathBuf>, PackageError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| read_error(dir, e))? {
        let path = entry.map_err(|e| read_error(dir, e))?.path();
        if path.extension().is_none_or(|u| u != "toml") {
            continue;
        }
        let m = fs::symlink_metadata(&path).map_err(|e| read_error(&path, e))?;
        if !m.file_type().is_file() {
            return Err(read_error(&path, "not a regular file (a symlink is not accepted)"));
        }
        files.push(path);
    }
    files.sort();
    Ok(files)
}

fn read_template_file(path: &Path) -> Result<Template, PackageError> {
    let m = fs::symlink_metadata(path).map_err(|e| read_error(path, e))?;
    if !m.file_type().is_file() {
        return Err(read_error(path, "not a regular file"));
    }
    if m.len() > template::MAX_TEMPLATE as u64 {
        return Err(read_error(path, "the file is too large"));
    }
    let text = fs::read_to_string(path).map_err(|e| read_error(path, e))?;
    let name = path.file_name().map_or_else(|| path.display().to_string(), |a| a.to_string_lossy().into_owned());
    template::parse_template(&text).map_err(|error| PackageError::Template { file: name, error })
}

/// Reads the templates in a directory and validates them as a package.
pub fn read_package(dir: &Path) -> Result<Package, PackageError> {
    let files = template_files(dir)?;
    let templates = files.iter().map(|d| read_template_file(d)).collect::<Result<Vec<_>, _>>()?;
    install_package(templates)
}

fn package_error(s: &Template, reason: impl std::fmt::Display) -> PackageError {
    PackageError::Package(format!("{}: {reason}", s.id))
}

/// The (template, value) pair a placeholder points to; also checks the cross-reference.
fn resolve_reference<'a>(
    templates: &'a [Template],
    own: &'a Template,
    y: &Placeholder,
    in_path: bool,
) -> Result<Option<(&'a str, String)>, String> {
    let Some(target_id) = y.template.as_deref() else {
        return Ok(Some((own.id.as_str(), y.name.clone())));
    };
    let target = templates
        .iter()
        .find(|s| s.id == target_id)
        .ok_or_else(|| format!("{{{{{target_id}:{}}}}}: the package has no template with id {target_id}", y.name))?;
    match y.name.as_str() {
        "path" if !in_path && y.child.is_none() => Ok(None),
        "path" => Err("another template's path can be used only in content, without a sub-field".into()),
        "file_time" => match y.child.as_deref() {
            Some(a) if TIME_FIELDS.contains(&a) => Ok(None),
            _ => Err(format!("file_time needs a sub-field: {}", TIME_FIELDS.join(", "))),
        },
        name => {
            let d = target.values.get(name).ok_or_else(|| format!("template {target_id} has no value {name}"))?;
            d.is_valid_subfield(y.child.as_deref())?;
            if in_path && !d.is_simple() {
                return Err(format!("a {} value cannot be used in a target path", d.kind_name()));
            }
            Ok(Some((target.id.as_str(), name.to_string())))
        }
    }
}

/// Validates templates as a package and runs trial generations.
pub(crate) fn install_package(templates: Vec<Template>) -> Result<Package, PackageError> {
    if templates.is_empty() {
        return Err(PackageError::Package("the package has no template".into()));
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for s in &templates {
        if !ids.insert(s.id.as_str()) {
            return Err(package_error(s, "a duplicate template id"));
        }
        if !paths.insert(s.target.path.as_str()) {
            return Err(package_error(s, format!("the same target path as another template: {}", s.target.path)));
        }
    }
    // Cross-references and used values.
    let mut used: BTreeSet<(&str, String)> = BTreeSet::new();
    for s in &templates {
        for (text, in_path) in [(&s.content, false), (&s.target.path, true)] {
            for y in placeholder::placeholders(text).map_err(|e| package_error(s, e))? {
                if let Some(c) = resolve_reference(&templates, s, &y, in_path).map_err(|e| package_error(s, e))? {
                    used.insert(c);
                }
            }
        }
        for (name, d) in &s.values {
            let inner_texts: Vec<&String> = match d {
                Value::SshEd25519 { comment } => vec![comment],
                Value::Repeat { template, .. } => vec![template],
                _ => Vec::new(),
            };
            for text in inner_texts {
                for y in placeholder::placeholders(text).map_err(|e| package_error(s, e))? {
                    used.insert((s.id.as_str(), y.name.clone()));
                }
            }
            if let Value::Repeat { template, values, .. } = d {
                let inner_used: BTreeSet<String> = placeholder::placeholders(template)
                    .map_err(|e| package_error(s, e))?
                    .into_iter()
                    .map(|y| y.name)
                    .collect();
                if let Some(unused) = values.keys().find(|a| !inner_used.contains(*a)) {
                    return Err(package_error(s, format!("{name}.values.{unused} is unused")));
                }
            }
        }
    }
    for s in &templates {
        if let Some(name) = s.values.keys().find(|a| !used.contains(&(s.id.as_str(), (*a).clone()))) {
            return Err(package_error(s, format!("values.{name} is used nowhere")));
        }
    }
    let package = Package { templates };
    for _ in 0..TRIAL_GENERATIONS {
        generate(&package).map_err(|e| PackageError::Package(format!("trial generation: {e}")))?;
    }
    Ok(package)
}

/// The validation result of one template file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResult {
    /// The file path.
    pub file: PathBuf,
    /// The template id (if it could be read).
    pub id: Option<String>,
    /// The error (absent means passed).
    pub error: Option<String>,
}

/// `koru decoy validate` report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    /// Per-file results.
    pub files: Vec<FileResult>,
    /// The package-level error (cross-reference, unused value, trial generation).
    pub package_error: Option<String>,
}

impl ValidationReport {
    /// Did every template and the package pass?
    pub fn succeeded(&self) -> bool {
        !self.files.is_empty() && self.files.iter().all(|d| d.error.is_none()) && self.package_error.is_none()
    }
}

/// Validates one template file, or every template in a directory.
pub fn validate_directory(path: &Path) -> ValidationReport {
    let files = match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => Ok(vec![path.to_path_buf()]),
        Ok(m) if m.file_type().is_dir() => template_files(path),
        Ok(_) => Err(read_error(path, "neither a file nor a directory")),
        Err(e) => Err(read_error(path, e)),
    };
    let files = match files {
        Ok(d) => d,
        Err(e) => return ValidationReport { files: Vec::new(), package_error: Some(e.to_string()) },
    };
    let mut results = Vec::new();
    let mut templates = Vec::new();
    for file in files {
        match read_template_file(&file) {
            Ok(s) => {
                results.push(FileResult { file, id: Some(s.id.clone()), error: None });
                templates.push(s);
            }
            Err(e) => {
                // The file name is already in the result; not repeated in the message.
                let message = match e {
                    PackageError::Template { error, .. } => error.to_string(),
                    PackageError::Read { reason, .. } => reason,
                    other => other.to_string(),
                };
                results.push(FileResult { file, id: None, error: Some(message) });
            }
        }
    }
    let package_error = if results.is_empty() {
        Some("no template (*.toml) found".to_string())
    } else if results.iter().all(|s| s.error.is_none()) {
        install_package(templates).err().map(|e| e.to_string())
    } else {
        None
    };
    ValidationReport { files: results, package_error }
}
