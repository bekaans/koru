//! Lexical path normalization (a security-review below-threshold note): before `exe` and
//! target-path comparisons, `//`, `/./`, and `..` tricks are removed.

use koru_detect::normalize_path;

#[test]
fn normalization_examples() {
    let examples: &[(&str, Option<&str>)] = &[
        ("/usr/bin/cat", Some("/usr/bin/cat")),
        ("/usr//bin/./cat", Some("/usr/bin/cat")),
        ("/usr/bin/../bin/cat", Some("/usr/bin/cat")),
        ("/usr/local/bin/../../bin//./cat", Some("/usr/bin/cat")),
        ("/../../etc/passwd", Some("/etc/passwd")),
        ("/a/b/..", Some("/a")),
        ("/a/b/../..", Some("/")),
        ("/usr/bin/", Some("/usr/bin")),
        ("/", Some("/")),
        ("//", Some("/")),
        ("/./.", Some("/")),
        ("/home/devops/.aws//credentials", Some("/home/devops/.aws/credentials")),
        ("/home/devops/...", Some("/home/devops/...")),
        ("/home/devops/..secret", Some("/home/devops/..secret")),
        ("usr/bin/cat", None),
        ("./cat", None),
        ("", None),
        ("/usr/bin/c\0at", None),
    ];
    for (input, expected) in examples {
        assert_eq!(normalize_path(input).as_deref(), *expected, "{input:?}");
    }
}
