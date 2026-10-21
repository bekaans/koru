//! Decoy content generation from templates (at install time, in memory).
//!
//! All values are regenerated with the CSPRNG on every call; two installations share no
//! high-entropy value. If a generated path or content contains the string "koru" (it can arise
//! by chance inside random values) the whole package is regenerated. The format and safety
//! checks (`format`) run on every generation; content that fails them is not installed.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use koru_event::Timestamp;

use crate::format;
use crate::generator::{self, SshKey};
use crate::package::Package;
use crate::placeholder::{self, Part, Placeholder};
use crate::random::{Random, RandomError};
use crate::template::{self, DecoyKind, Format, Placement, Template, Value, contains_koru};

/// The maximum attempts to avoid the "koru" string.
const MAX_ATTEMPTS: u32 = 32;
/// The maximum size of generated content (bytes).
const MAX_GENERATION: usize = 1024 * 1024;

/// A decoy generated from a template, not yet written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    /// The template id.
    pub template: String,
    /// A decoy or a breadcrumb.
    pub kind: DecoyKind,
    /// The class tag.
    pub class: String,
    /// The content's format.
    pub format: Format,
    /// The target path: relative to the root, or absolute (under an allowed root).
    pub path: String,
    /// The content (the block to append at the end when the placement is `append`).
    pub content: String,
    /// The file mode.
    pub mode: u32,
    /// The placement form.
    pub placement: Placement,
    /// The file's natural modification time.
    pub mtime: Timestamp,
    /// The high-entropy generated values written into the content (keys, tokens, passwords,
    /// hashes, UUIDs). For uniqueness tests and evidence; not written to the output.
    pub unique_values: Vec<String>,
}

/// When generation fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenerationError {
    /// The CSPRNG could not be used.
    #[error(transparent)]
    Random(#[from] RandomError),
    /// The template could not be generated, or the generated content failed the checks.
    #[error("{template}: {reason}")]
    Template {
        /// The template id.
        template: String,
        /// Reason.
        reason: String,
    },
    /// The "koru" string arose on every attempt.
    #[error("a generation without the \"koru\" string was not found in {0} attempts")]
    KoruMarker(u32),
}

/// The string substituted for random values in the safety check. Patterns that arise by chance
/// inside random strings ("nc ", "curl", "://", digit-dot sequences) must not produce false
/// alarms, so the forbidden-pattern, address, and URL checks run on the masked content; the
/// masked values come from fixed alphabets and cannot carry a meaningful command or address.
const MASK_CHAR: &str = "x";

/// A generated value.
enum Generated {
    /// When `random` is true it is masked in the safety check.
    Text {
        value: String,
        random: bool,
        unique: bool,
    },
    Repeat {
        text: String,
        mask: String,
        unique: Vec<String>,
    },
    Ssh(SshKey),
    Timestamp(i128),
}

/// A placeholder's resolution: the real text, the masked text for the safety check, and the
/// high-entropy values it contains.
struct Resolution {
    text: String,
    mask: String,
    unique: Vec<String>,
}

fn plain(text: String) -> Resolution {
    Resolution { mask: text.clone(), text, unique: Vec::new() }
}

struct TemplateValues {
    values: BTreeMap<String, Generated>,
    file_time: i128,
}

/// For a random string to count as high-entropy: at least 16 characters and 64 bits.
fn is_random_unique(alphabet_len: usize, length: u32) -> bool {
    length >= 16 && f64::from(length) * (alphabet_len as f64).log2() >= 64.0
}

fn time_text(ns: i128, child: &str) -> Result<String, String> {
    let m = Timestamp::from_unix_nanos(ns).map_err(|e| e.to_string())?.text();
    Ok(match child {
        "date" => m[..10].to_string(),
        "time" => m[11..19].to_string(),
        "datetime" => format!("{} {}", &m[..10], &m[11..19]),
        "iso" => format!("{}Z", &m[..19]),
        "unix" => ns.div_euclid(1_000_000_000).to_string(),
        "year" => m[..4].to_string(),
        other => return Err(format!("unknown timestamp sub-field: {other}")),
    })
}

fn generated_text(u: &Generated, child: Option<&str>) -> Result<Resolution, String> {
    match (u, child) {
        (Generated::Text { value, random, unique }, None) => Ok(Resolution {
            text: value.clone(),
            mask: if *random { MASK_CHAR.to_string() } else { value.clone() },
            unique: if *unique { vec![value.clone()] } else { Vec::new() },
        }),
        (Generated::Repeat { text, mask, unique }, None) => {
            Ok(Resolution { text: text.clone(), mask: mask.clone(), unique: unique.clone() })
        }
        (Generated::Ssh(a), Some(child)) => {
            let d = match child {
                "private" => &a.private_key,
                "public" => &a.public_part,
                "public_key" => &a.public_key,
                other => return Err(format!("unknown ssh sub-field: {other}")),
            };
            Ok(Resolution { text: d.clone(), mask: MASK_CHAR.to_string(), unique: vec![d.clone()] })
        }
        (Generated::Timestamp(ns), Some(child)) => Ok(plain(time_text(*ns, child)?)),
        _ => Err("a sub-field that does not match the value kind".into()),
    }
}

/// Fills the placeholders in the text with the resolver; adds high-entropy values to `unique`.
/// Returns: (real text, masked text).
fn process(
    text: &str,
    unique: &mut Vec<String>,
    mut resolver: impl FnMut(&Placeholder) -> Result<Resolution, String>,
) -> Result<(String, String), String> {
    let mut output = String::with_capacity(text.len() * 2);
    let mut mask = String::with_capacity(text.len());
    for part in placeholder::parse_parts(text)? {
        match part {
            Part::Text(m) => {
                output.push_str(m);
                mask.push_str(m);
            }
            Part::Placeholder(y) => {
                let c = resolver(&y)?;
                match y.filter {
                    Some(s) => {
                        let d = s.apply(&c.text);
                        if !c.unique.is_empty() {
                            unique.push(d.clone());
                        }
                        output.push_str(&d);
                        mask.push_str(&s.apply(&c.mask));
                    }
                    None => {
                        unique.extend(c.unique);
                        output.push_str(&c.text);
                        mask.push_str(&c.mask);
                    }
                }
            }
        }
        if output.len() > MAX_GENERATION {
            return Err(format!("the generated text is larger than {MAX_GENERATION} bytes"));
        }
    }
    Ok((output, mask))
}

/// Generates a value set. `outer` is the outer values that values inside a repeat can reference.
fn generate_values(
    definitions: &BTreeMap<String, Value>,
    r: &mut Random,
    now: i128,
    outer: Option<&BTreeMap<String, Generated>>,
) -> Result<BTreeMap<String, Generated>, String> {
    let rerror = |e: RandomError| e.to_string();
    let mut result = BTreeMap::new();
    // Simple values first; SSH comments and repeats can reference them.
    for (name, d) in definitions {
        let u = match d {
            Value::Random { alphabet, length, prefix, suffix } => {
                let k = alphabet.characters();
                let body = r.string(k, *length as usize).map_err(rerror)?;
                Generated::Text {
                    value: format!("{prefix}{body}{suffix}"),
                    random: true,
                    unique: is_random_unique(k.len(), *length),
                }
            }
            Value::Choice { options } => {
                let i = r.index(options.len()).map_err(rerror)?;
                Generated::Text { value: options[i].clone(), random: false, unique: false }
            }
            Value::Number { min, max } => Generated::Text {
                value: r.range(*min, *max).map_err(rerror)?.to_string(),
                random: false,
                unique: false,
            },
            Value::Uuid4 {} => {
                Generated::Text { value: generator::uuid4(r).map_err(rerror)?, random: true, unique: true }
            }
            Value::Bcrypt { cost } => {
                Generated::Text { value: generator::bcrypt(r, *cost).map_err(rerror)?, random: true, unique: true }
            }
            Value::GithubToken {} => {
                Generated::Text { value: generator::github_token(r).map_err(rerror)?, random: true, unique: true }
            }
            Value::TestNetIpv4 {} => Generated::Text {
                value: generator::test_network_ipv4(r).map_err(rerror)?,
                random: false,
                unique: false,
            },
            Value::Timestamp { min_days, max_days } => {
                Generated::Timestamp(generator::natural_time(r, now, *min_days, *max_days).map_err(rerror)?)
            }
            Value::SshEd25519 { .. } | Value::Repeat { .. } => continue,
        };
        result.insert(name.clone(), u);
    }
    for (name, d) in definitions {
        if let Value::SshEd25519 { comment } = d {
            let mut no_systemd = Vec::new();
            let (comment, _) = process(comment, &mut no_systemd, |y| {
                let u = result.get(&y.name).ok_or_else(|| format!("undefined value in the comment: {}", y.name))?;
                generated_text(u, y.child.as_deref())
            })?;
            let key = generator::ssh_ed25519(r, &comment).map_err(rerror)?;
            result.insert(name.clone(), Generated::Ssh(key));
        }
    }
    for (name, d) in definitions {
        if let Value::Repeat { min, max, separator, template, values } = d {
            if outer.is_some() {
                return Err("a repeat cannot be nested".into());
            }
            let count = r.range(u64::from(*min), u64::from(*max)).map_err(rerror)?;
            let mut parts = Vec::new();
            let mut unique = Vec::new();
            for i in 1..=count {
                let inner = generate_values(values, r, now, Some(&result))?;
                let part = process(template, &mut unique, |y| {
                    if y.name == "index" && y.template.is_none() && y.child.is_none() && !inner.contains_key("index") {
                        return Ok(plain(i.to_string()));
                    }
                    let u = inner
                        .get(&y.name)
                        .or_else(|| result.get(&y.name))
                        .ok_or_else(|| format!("undefined value: {}", y.name))?;
                    generated_text(u, y.child.as_deref())
                })?;
                parts.push(part);
            }
            let text = parts.iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>().join(separator);
            let mask = parts.iter().map(|(_, m)| m.as_str()).collect::<Vec<_>>().join(separator);
            result.insert(name.clone(), Generated::Repeat { text, mask, unique });
        }
    }
    Ok(result)
}

fn now_ns() -> i128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as i128)
}

/// Finds a placeholder's value. Without `paths` (when generating `target.path`) there is no `path` reference.
fn parse(
    own: &str,
    y: &Placeholder,
    all_values: &BTreeMap<&str, TemplateValues>,
    paths: Option<&BTreeMap<&str, String>>,
) -> Result<Resolution, String> {
    let target = y.template.as_deref().unwrap_or(own);
    let values = all_values.get(target).ok_or_else(|| format!("undefined template: {target}"))?;
    match (y.name.as_str(), y.template.is_some()) {
        ("path", true) => {
            let paths = paths.ok_or("another template path cannot be used in a target path")?;
            let path = paths.get(target).ok_or_else(|| format!("undefined template path: {target}"))?;
            Ok(plain(path.clone()))
        }
        ("file_time", _) => {
            let child = y.child.as_deref().ok_or("file_time needs a sub-field")?;
            Ok(plain(time_text(values.file_time, child)?))
        }
        (name, _) => {
            let u = values.values.get(name).ok_or_else(|| format!("undefined value: {target}:{name}"))?;
            generated_text(u, y.child.as_deref())
        }
    }
}

fn template_error(s: &Template, reason: impl Into<String>) -> GenerationError {
    GenerationError::Template { template: s.id.clone(), reason: reason.into() }
}

/// One attempt. `Ok(None)`: the "koru" string arose, retry.
fn one_attempt(package: &Package, r: &mut Random, now: i128) -> Result<Option<Vec<Generation>>, GenerationError> {
    let mut all_values: BTreeMap<&str, TemplateValues> = BTreeMap::new();
    for s in package.templates() {
        let values = generate_values(&s.values, r, now, None).map_err(|e| template_error(s, e))?;
        let file_time = generator::natural_time(r, now, s.timestamp.min_days, s.timestamp.max_days)?;
        all_values.insert(s.id.as_str(), TemplateValues { values, file_time });
    }
    let mut paths: BTreeMap<&str, String> = BTreeMap::new();
    let mut seen_paths = BTreeSet::new();
    for s in package.templates() {
        let mut no_systemd = Vec::new();
        let (path, _) = process(&s.target.path, &mut no_systemd, |y| parse(&s.id, y, &all_values, None))
            .map_err(|e| template_error(s, e))?;
        template::path_components(&path)
            .map_err(|e| template_error(s, format!("the generated target path is invalid: {e}")))?;
        if contains_koru(&path) {
            return Ok(None);
        }
        if !seen_paths.insert(path.clone()) {
            return Err(template_error(s, format!("the same target path as another template: {path}")));
        }
        paths.insert(s.id.as_str(), path);
    }
    let reference_paths: BTreeMap<&str, String> =
        paths.iter().map(|(k, y)| (*k, if y.starts_with('/') { y.clone() } else { format!("~/{y}") })).collect();
    let mut result = Vec::with_capacity(package.templates().len());
    for s in package.templates() {
        let mut unique = Vec::new();
        let (content, mask) =
            process(&s.content, &mut unique, |y| parse(&s.id, y, &all_values, Some(&reference_paths)))
                .map_err(|e| template_error(s, e))?;
        if contains_koru(&content) {
            return Ok(None);
        }
        if s.target.placement == Placement::Append && !content.ends_with('\n') {
            return Err(template_error(s, "the to-append block must end with a newline"));
        }
        format::check_content(s.format, &content, &mask)
            .map_err(|e| template_error(s, format!("the generated content failed the {:?} checks: {e}", s.format)))?;
        let mut seen = BTreeSet::new();
        unique.retain(|d| seen.insert(d.clone()));
        let mtime = Timestamp::from_unix_nanos(all_values[s.id.as_str()].file_time)
            .map_err(|e| template_error(s, e.to_string()))?;
        result.push(Generation {
            template: s.id.clone(),
            kind: s.kind,
            class: s.class.clone(),
            format: s.format,
            path: paths[s.id.as_str()].clone(),
            content,
            mode: s.target.mode,
            placement: s.target.placement,
            mtime,
            unique_values: unique,
        });
    }
    Ok(Some(result))
}

/// Generates decoy content from every template in the package. Values are regenerated with the
/// CSPRNG on every call; the result is not written to disk.
pub fn generate(package: &Package) -> Result<Vec<Generation>, GenerationError> {
    let now = now_ns();
    let mut r = Random::new();
    for _ in 0..MAX_ATTEMPTS {
        if let Some(u) = one_attempt(package, &mut r, now)? {
            return Ok(u);
        }
    }
    Err(GenerationError::KoruMarker(MAX_ATTEMPTS))
}
