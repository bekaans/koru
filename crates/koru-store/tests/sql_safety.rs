//! SQL safety (protected set): all queries are
//! parameterized; no SQL is built by string concatenation. The source scan is a heuristic and
//! only catches violations of this principle; the behavior tests live in `store_basic.rs`.

use std::fs;
use std::path::PathBuf;

fn references() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut result = Vec::new();
    for g in fs::read_dir(&dir).expect("src must be readable") {
        let path = g.unwrap().path();
        if path.extension().is_some_and(|u| u == "rs") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            result.push((name, fs::read_to_string(&path).unwrap()));
        }
    }
    assert!(result.len() >= 8, "src files were not found");
    result
}

const SQL_KEYWORDS: &[&str] =
    &["SELECT ", "INSERT ", "UPDATE ", "DELETE ", "PRAGMA ", "CREATE ", "DROP ", "ALTER ", "VACUUM"];

fn sql_present(line: &str) -> bool {
    SQL_KEYWORDS.iter().any(|k| line.contains(k))
}

#[test]
fn sql_is_not_built_by_concatenation() {
    for (name, source) in references() {
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            let concatenates = ["format!(", "concat!(", "push_str(", "write!(", "writeln!(", ".replace(", ".join("]
                .iter()
                .any(|b| t.contains(b));
            if !concatenates {
                continue;
            }
            let window = lines[i..(i + 4).min(lines.len())].join("\n");
            assert!(
                !sql_present(&window),
                "{name}:{}: SQL text may be built by formatting or concatenation:\n{window}",
                i + 1
            );
        }
    }
}

#[test]
fn sql_runs_with_constant_text_and_parameters() {
    // The text on every line containing an SQL keyword is either a fixed string literal or
    // uses a parameter via `params!`/`?N`; concatenations like `+ &`, `+ format` are forbidden.
    for (name, source) in references() {
        for (i, line) in source.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") || !sql_present(line) {
                continue;
            }
            assert!(
                !(t.contains("\" +") || t.contains("+ \"") || t.contains("+ &") || t.contains("+ format")),
                "{name}:{}: string concatenation on an SQL line: {t}",
                i + 1
            );
        }
    }
}

#[test]
fn rusqlite_queries_take_only_constant_text() {
    // `prepare(&...)`, `execute(&...)`, and `query_row(&...)` calls cannot take variable text:
    // it must be a fixed literal or a constant named with `const`.
    for (name, source) in references() {
        for (i, line) in source.lines().enumerate() {
            for call in [".prepare(", ".prepare_cached(", ".execute(", ".query_row(", ".execute_batch("] {
                if let Some(position) = line.find(call) {
                    let arg = line[position + call.len()..].trim_start();
                    let constant = arg.starts_with('"')
                        || arg.starts_with("r#\"")
                        || arg.starts_with("r\"")
                        || arg.starts_with(|c: char| c.is_ascii_uppercase())
                        || arg.is_empty();
                    assert!(
                        constant,
                        "{name}:{}: SQL is called with a non-constant expression: {}",
                        i + 1,
                        line.trim()
                    );
                }
            }
        }
    }
}
