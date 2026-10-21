//! The placeholder language (ADR-0004 "Template format").
//!
//! Template texts consist of plain text and `{{ … }}` placeholders. There is no logic, loop, or
//! condition; a placeholder is only replaced with a value generated at install time. Grammar:
//!
//! ```text
//! placeholder := "{{" [template ":"] name ["." child] ["|" filter] "}}"
//! template    := [a-z0-9][a-z0-9-]*        another template's id (cross-reference)
//! name        := [a-z][a-z0-9_]*           a value name or a reserved name (path, file_time, index)
//! child         := [a-z][a-z0-9_]*           the field of a multi-output value (e.g. key.private)
//! filter      := "lower" | "upper"
//! ```
//!
//! No whitespace is accepted; `{{` always starts a placeholder.

/// A placeholder's filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Filter {
    /// Converts to lowercase.
    Lower,
    /// Converts to uppercase.
    Upper,
}

impl Filter {
    pub(crate) fn apply(self, text: &str) -> String {
        match self {
            Filter::Lower => text.to_lowercase(),
            Filter::Upper => text.to_uppercase(),
        }
    }
}

/// A parsed placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Placeholder {
    /// The target template's id in a cross-reference.
    pub(crate) template: Option<String>,
    /// The value name.
    pub(crate) name: String,
    /// Sub-field.
    pub(crate) child: Option<String>,
    /// The filter.
    pub(crate) filter: Option<Filter>,
}

/// A part of the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Part<'a> {
    /// Plain text.
    Text(&'a str),
    /// A placeholder.
    Placeholder(Placeholder),
}

fn is_name(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|i| i.is_ascii_lowercase())
        && c.all(|k| k.is_ascii_lowercase() || k.is_ascii_digit() || k == '_')
        && s.len() <= 48
}

pub(crate) fn is_template_id(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|i| i.is_ascii_lowercase() || i.is_ascii_digit())
        && c.all(|k| k.is_ascii_lowercase() || k.is_ascii_digit() || k == '-')
        && s.len() <= 64
}

fn parse_inner(inner: &str) -> Result<Placeholder, String> {
    let (body, filter) = match inner.split_once('|') {
        Some((g, "lower")) => (g, Some(Filter::Lower)),
        Some((g, "upper")) => (g, Some(Filter::Upper)),
        Some((_, s)) => return Err(format!("unknown filter: {s:?} (lower or upper)")),
        None => (inner, None),
    };
    let (template, body) = match body.split_once(':') {
        Some((s, g)) if is_template_id(s) => (Some(s.to_string()), g),
        Some((s, _)) => return Err(format!("invalid template id: {s:?}")),
        None => (None, body),
    };
    let (name, child) = match body.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (body, None),
    };
    if !is_name(name) {
        return Err(format!("invalid value name: {name:?} (lowercase letters, digits, and _; starts with a letter)"));
    }
    if let Some(b) = child
        && !is_name(b)
    {
        return Err(format!("invalid sub-field: {b:?}"));
    }
    Ok(Placeholder { template, name: name.to_string(), child: child.map(str::to_string), filter })
}

/// Splits the text into plain-text and placeholder parts.
pub(crate) fn parse_parts(text: &str) -> Result<Vec<Part<'_>>, String> {
    let mut parts = Vec::new();
    let mut remaining = text;
    while let Some(start) = remaining.find("{{") {
        if start > 0 {
            parts.push(Part::Text(&remaining[..start]));
        }
        let remainder = &remaining[start + 2..];
        let last = remainder.find("}}").ok_or_else(|| "unclosed placeholder: '{{' without '}}'".to_string())?;
        let inner = &remainder[..last];
        if inner.contains('{') {
            return Err(format!("nested placeholder: {{{{{inner}}}}}"));
        }
        parts.push(Part::Placeholder(parse_inner(inner).map_err(|e| format!("{{{{{inner}}}}}: {e}"))?));
        remaining = &remainder[last + 2..];
    }
    if !remaining.is_empty() {
        parts.push(Part::Text(remaining));
    }
    Ok(parts)
}

/// Only the placeholders.
pub(crate) fn placeholders(text: &str) -> Result<Vec<Placeholder>, String> {
    Ok(parse_parts(text)?
        .into_iter()
        .filter_map(|p| match p {
            Part::Placeholder(y) => Some(y),
            Part::Text(_) => None,
        })
        .collect())
}

/// The join of only the plain-text parts (placeholders are separated by a space).
pub(crate) fn plain_text(text: &str) -> Result<String, String> {
    Ok(parse_parts(text)?
        .into_iter()
        .map(|p| match p {
            Part::Text(m) => m,
            Part::Placeholder(_) => " ",
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar() {
        let p = parse_parts("a {{x}} b {{s-1:y.z|lower}}").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(
            p[3],
            Part::Placeholder(Placeholder {
                template: Some("s-1".into()),
                name: "y".into(),
                child: Some("z".into()),
                filter: Some(Filter::Lower)
            })
        );
        for bad in ["{{", "{{ x }}", "{{X}}", "{{x|reverse}}", "{{Ab:x}}", "{{x.}}", "{{:x}}", "{{x{{y}}}}", "{{1x}}"] {
            assert!(parse_parts(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_parts("}} alone").unwrap(), vec![Part::Text("}} alone")]);
        assert_eq!(plain_text("a{{x}}b").unwrap(), "a b");
    }
}
