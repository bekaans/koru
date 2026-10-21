//! Wildcard pattern matching (`*` and `?`) without a regex engine.
//!
//! Sigma values and AI-agent signatures use this matcher. The algorithm is a two-pointer
//! match rewinding to the last `*`: at worst `pattern length × value length` steps (linear
//! bounded); there is no exponential backtracking like regex (KT-12). Pattern length is
//! bounded by the rule-file limit (1 MiB).

/// One part of a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// Exactly this character (folded when insensitive).
    Letters(char),
    /// `?`: exactly one character.
    One,
    /// `*`: zero or more characters.
    Star,
}

/// A compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pattern {
    parts: Vec<Part>,
    case_sensitive: bool,
}

/// Case folding: a fast path for ASCII, otherwise the first character of the Unicode
/// lowercase mapping. Pattern and value pass through the same function; character count
/// never changes.
fn fold(c: char) -> char {
    if c.is_ascii() { c.to_ascii_lowercase() } else { c.to_lowercase().next().unwrap_or(c) }
}

impl Pattern {
    /// Compiles from pattern text with Sigma escape rules: `\*`, `\?`, and `\\` escape
    /// (the next character is a literal); a backslash not before a wildcard stays as is.
    pub(crate) fn sigma(text: &str, case_sensitive: bool) -> Pattern {
        let mut parts = Vec::new();
        let mut characters = text.chars().peekable();
        while let Some(c) = characters.next() {
            match c {
                '*' => parts.push(Part::Star),
                '?' => parts.push(Part::One),
                '\\' => match characters.peek().copied() {
                    Some(next @ ('*' | '?' | '\\')) => {
                        characters.next();
                        parts.push(Part::Letters(next));
                    }
                    _ => parts.push(Part::Letters('\\')),
                },
                other => parts.push(Part::Letters(other)),
            }
        }
        Pattern::build_pattern(parts, case_sensitive)
    }

    /// No escapes: only `*` and `?` are special (AI-agent signatures and `1 of name_*` patterns).
    pub(crate) fn simple_token(text: &str, case_sensitive: bool) -> Pattern {
        let parts = text
            .chars()
            .map(|c| match c {
                '*' => Part::Star,
                '?' => Part::One,
                other => Part::Letters(other),
            })
            .collect();
        Pattern::build_pattern(parts, case_sensitive)
    }

    fn build_pattern(mut parts: Vec<Part>, case_sensitive: bool) -> Pattern {
        if !case_sensitive {
            for p in &mut parts {
                if let Part::Letters(c) = p {
                    *c = fold(*c);
                }
            }
        }
        Pattern { parts, case_sensitive }
    }

    /// Adds `*` to both ends (`contains`).
    pub(crate) fn containing(mut self) -> Pattern {
        self.parts.insert(0, Part::Star);
        self.parts.push(Part::Star);
        self
    }

    /// Appends `*` to the end (`startswith`).
    pub(crate) fn starting_with(mut self) -> Pattern {
        self.parts.push(Part::Star);
        self
    }

    /// Adds `*` to the front (`endswith`).
    pub(crate) fn ending_with(mut self) -> Pattern {
        self.parts.insert(0, Part::Star);
        self
    }

    /// The count of non-wildcard (literal) characters.
    pub(crate) fn literal_char_count(&self) -> usize {
        self.parts.iter().filter(|p| matches!(p, Part::Letters(_))).count()
    }

    /// Whether the pattern matches the whole value.
    pub(crate) fn matches_pattern(&self, value: &str) -> bool {
        let text: Vec<char> =
            if self.case_sensitive { value.chars().collect() } else { value.chars().map(fold).collect() };
        let pattern = &self.parts;
        let (mut d, mut m) = (0usize, 0usize);
        // The last `*` seen: (pattern position after it, end of text it has consumed so far).
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
                None => false,
            };
            if matched {
                d += 1;
                m += 1;
            } else if let Some((star_d, star_m)) = star {
                // Let the last `*` swallow one more character.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_matches() {
        assert!(Pattern::sigma("a*c", true).matches_pattern("abbbc"));
        assert!(Pattern::sigma("a?c", true).matches_pattern("abc"));
        assert!(!Pattern::sigma("a?c", true).matches_pattern("ac"));
        assert!(Pattern::sigma("*", true).matches_pattern(""));
        assert!(Pattern::sigma("", true).matches_pattern(""));
        assert!(!Pattern::sigma("", true).matches_pattern("a"));
        assert!(Pattern::sigma("ABC", false).matches_pattern("aBc"));
        assert!(!Pattern::sigma("ABC", true).matches_pattern("aBc"));
    }

    #[test]
    fn escape_and_context_suffixes() {
        assert!(Pattern::sigma("a\\*", true).matches_pattern("a*"));
        assert!(!Pattern::sigma("a\\*", true).matches_pattern("ab"));
        assert!(Pattern::sigma("x", true).containing().matches_pattern("axb"));
        assert!(Pattern::sigma("x", true).starting_with().matches_pattern("xb"));
        assert!(Pattern::sigma("x", true).ending_with().matches_pattern("ax"));
        assert!(!Pattern::sigma("x", true).ending_with().matches_pattern("xa"));
    }

    #[test]
    fn turkish_letters() {
        assert!(Pattern::sigma("\u{c9}TE", false).matches_pattern("\u{e9}te"));
        assert!(!Pattern::sigma("\u{c9}TE", true).matches_pattern("\u{e9}te"));
        assert!(Pattern::sigma("\u{e9}?r", false).matches_pattern("\u{c9}\u{130}R"));
    }
}
