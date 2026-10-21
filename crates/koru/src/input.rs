//! Parsing of the command line and JSONL input (CLI input and JSONL
//! import are fuzzed). The `koru` binary and the `fuzz/` targets share this code.

use std::collections::BTreeMap;
use std::io::{BufRead, Read};

use koru_store::MAX_EVENT_BYTES;

/// An option parsing error (usage error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionsError(pub String);

/// Reads options of the form `--name value`. An option outside `repeatable` is given once;
/// the value may not start with `--`.
pub fn options(
    args: &[String],
    allowed: &[&str],
    repeatable: &[&str],
) -> Result<BTreeMap<String, Vec<String>>, OptionsError> {
    let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let name = args[i].as_str();
        if !allowed.contains(&name) && !repeatable.contains(&name) {
            return Err(OptionsError(format!("unknown argument: {name}")));
        }
        let value = args
            .get(i + 1)
            .filter(|d| !d.starts_with("--"))
            .ok_or_else(|| OptionsError(format!("{name} needs a value")))?;
        let values = result.entry(name.to_string()).or_default();
        if !values.is_empty() && !repeatable.contains(&name) {
            return Err(OptionsError(format!("{name} may be given only once")));
        }
        values.push(value.clone());
        i += 2;
    }
    Ok(result)
}

/// Splits out a flag that takes no value (e.g. `--mask`): whether present, and the remaining arguments.
pub fn split_flags(args: &[String], flag: &str) -> (bool, Vec<String>) {
    let present = args.iter().any(|a| a == flag);
    (present, args.iter().filter(|a| *a != flag).cloned().collect())
}

/// The outcome of reading one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputLine {
    /// UTF-8 text (the line ending stripped).
    Text(String),
    /// A non-UTF-8 line.
    Invalid,
    /// A line longer than `MAX_EVENT_BYTES` (the remainder was skipped).
    TooLarge,
}

/// Reads one line keeping at most `MAX_EVENT_BYTES` bytes; the remainder of a longer line is skipped.
pub fn read_line(input: &mut impl BufRead) -> std::io::Result<Option<InputLine>> {
    let limit = MAX_EVENT_BYTES as u64 + 2;
    let mut buffer = Vec::new();
    let n = input.by_ref().take(limit).read_until(b'\n', &mut buffer)?;
    if n == 0 {
        return Ok(None);
    }
    if buffer.last() != Some(&b'\n') && n as u64 >= limit {
        let mut discarded = Vec::new();
        loop {
            discarded.clear();
            let k = input.by_ref().take(1 << 16).read_until(b'\n', &mut discarded)?;
            if k == 0 || discarded.last() == Some(&b'\n') {
                break;
            }
        }
        return Ok(Some(InputLine::TooLarge));
    }
    while matches!(buffer.last(), Some(b'\n' | b'\r')) {
        buffer.pop();
    }
    Ok(Some(match String::from_utf8(buffer) {
        Ok(m) => InputLine::Text(m),
        Err(_) => InputLine::Invalid,
    }))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn options_with_values_repeated_and_invalid() {
        let s = options(&v(&["--a", "1", "--b", "2", "--b", "3"]), &["--a"], &["--b"]).unwrap();
        assert_eq!(s["--a"], ["1"]);
        assert_eq!(s["--b"], ["2", "3"]);
        assert!(options(&v(&["--a", "1", "--a", "2"]), &["--a"], &[]).is_err());
        assert!(options(&v(&["--x", "1"]), &["--a"], &[]).is_err());
        assert!(options(&v(&["--a"]), &["--a"], &[]).is_err());
        assert!(options(&v(&["--a", "--b"]), &["--a", "--b"], &[]).is_err(), "a value may not start with --");
    }

    #[test]
    fn flag_splitting() {
        assert_eq!(split_flags(&v(&["a", "--m", "b"]), "--m"), (true, v(&["a", "b"])));
        assert_eq!(split_flags(&v(&["a"]), "--m"), (false, v(&["a"])));
    }

    #[test]
    fn line_read_classes() {
        let mut g = Cursor::new(b"abc\r\n\xff\xfe\ntail".to_vec());
        assert_eq!(read_line(&mut g).unwrap(), Some(InputLine::Text("abc".into())));
        assert_eq!(read_line(&mut g).unwrap(), Some(InputLine::Invalid));
        assert_eq!(read_line(&mut g).unwrap(), Some(InputLine::Text("tail".into())));
        assert_eq!(read_line(&mut g).unwrap(), None);
        let mut long_v = vec![b'x'; MAX_EVENT_BYTES + 100];
        long_v.extend_from_slice(b"\nnext\n");
        let mut g = Cursor::new(long_v);
        assert_eq!(read_line(&mut g).unwrap(), Some(InputLine::TooLarge));
        assert_eq!(read_line(&mut g).unwrap(), Some(InputLine::Text("next".into())));
    }
}
