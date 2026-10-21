//! A shell (fnmatch) pattern: `*`, `?`, `[abc]`, `[a-z]`, `[!x]`, and `\` escapes. systemd
//! unit-name globs and `service`/`systemctl` targets are written with these.
//!
//! There is no regex engine; matching is the two-pointer, last-`*`-rewinding linear bounded
//! algorithm like `pattern.rs` (KT-12). An unclosed `[` is a literal (POSIX fnmatch).

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Letters(char),
    One,
    Star,
    Class { negated: bool, ranges: Vec<(char, char)> },
}

/// A compiled shell pattern (case sensitive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Shell {
    parts: Vec<Part>,
}

impl Shell {
    pub(crate) fn compile_pattern(text: &str) -> Shell {
        let k: Vec<char> = text.chars().collect();
        let mut parts = Vec::new();
        let mut i = 0;
        while i < k.len() {
            match k[i] {
                '*' => parts.push(Part::Star),
                '?' => parts.push(Part::One),
                '\\' if i + 1 < k.len() => {
                    i += 1;
                    parts.push(Part::Letters(k[i]));
                }
                '[' => match read_class(&k, i) {
                    Some((part, next)) => {
                        parts.push(part);
                        i = next;
                        continue;
                    }
                    None => parts.push(Part::Letters('[')),
                },
                c => parts.push(Part::Letters(c)),
            }
            i += 1;
        }
        Shell { parts }
    }

    /// Whether the pattern holds a special character (`*`, `?`, `[`).
    pub(crate) fn is_special(text: &str) -> bool {
        text.contains(['*', '?', '['])
    }

    pub(crate) fn matches_pattern(&self, value: &str) -> bool {
        let text: Vec<char> = value.chars().collect();
        let pattern = &self.parts;
        let (mut d, mut m) = (0usize, 0usize);
        let mut star: Option<(usize, usize)> = None;
        while m < text.len() {
            let matched = match pattern.get(d) {
                Some(Part::Star) => {
                    d += 1;
                    star = Some((d, m));
                    continue;
                }
                Some(Part::One) => true,
                Some(Part::Letters(c)) => *c == text[m],
                Some(Part::Class { negated, ranges }) => {
                    ranges.iter().any(|(a, b)| *a <= text[m] && text[m] <= *b) != *negated
                }
                None => false,
            };
            if matched {
                d += 1;
                m += 1;
            } else if let Some((star_d, star_m)) = star {
                d = star_d;
                m = star_m + 1;
                star = Some((star_d, star_m + 1));
            } else {
                return false;
            }
        }
        pattern[d..].iter().all(|p| *p == Part::Star)
    }
}

/// Reads the class starting at the `[` at `k[start]`; `None` if unclosed. The returned
/// position is past the closing `]`.
fn read_class(k: &[char], start: usize) -> Option<(Part, usize)> {
    let mut i = start + 1;
    let negated = matches!(k.get(i), Some('!' | '^'));
    if negated {
        i += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    loop {
        let c = *k.get(i)?;
        if c == ']' && !first {
            return Some((Part::Class { negated, ranges }, i + 1));
        }
        first = false;
        let child = if c == '\\' {
            i += 1;
            *k.get(i)?
        } else {
            c
        };
        // An `a-z` range: unless the dash is right before the closing bracket.
        if k.get(i + 1) == Some(&'-') && k.get(i + 2).is_some_and(|x| *x != ']') {
            let upper = *k.get(i + 2)?;
            ranges.push((child, upper));
            i += 3;
        } else {
            ranges.push((child, child));
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(pattern: &str, value: &str) -> bool {
        Shell::compile_pattern(pattern).matches_pattern(value)
    }

    #[test]
    fn wildcards_and_classes() {
        assert!(e("kor[u]", "koru"));
        assert!(e("[kK]oru", "Koru"));
        assert!(e("kor[a-z]", "koru"));
        assert!(!e("kor[a-t]", "koru"));
        assert!(e("k[!x]ru", "koru"));
        assert!(!e("k[!o]ru", "koru"));
        assert!(e("k*u", "koru"));
        assert!(e("k?ru", "koru"));
        assert!(!e("k?ru", "kru"));
    }

    #[test]
    fn unclosed_and_empty_class_is_literal() {
        assert!(e("[", "["));
        assert!(e("[]koru", "[]koru"));
        assert!(!e("[]koru", "koru"));
        assert!(e("[]]", "]"));
        assert!(e("a[", "a["));
    }

    #[test]
    fn escape_and_dash() {
        assert!(e("a\\*", "a*"));
        assert!(!e("a\\*", "ab"));
        assert!(e("[a-]", "-"));
        assert!(e("[\\]]", "]"));
    }
}
