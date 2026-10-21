//! CLI input. The input is a NUL-separated
//! argument list; it is parsed against each command's option set, and the
//! name/path/tag validators run too.
//! Expected: no crash; a successful result contains only the allowed options.
#![no_main]

use koru::input::{split_flags, options};
use koru::config::{valid_name, source_tag_from_str};
use koru_event::is_valid_host;
use koru_detect::normalize_path;
use libfuzzer_sys::fuzz_target;

const SETS: [(&[&str], &[&str]); 5] = [
    (&["--package", "--root", "--state", "--owner"], &["--allowed-root"]),
    (&["--store", "--input"], &[]),
    (&["--store", "--format", "--source", "--output"], &[]),
    (
        &["--version-dir", "--config", "--name", "--source-tag", "--decoy-root", "--decoy-owner", "--environment", "--public-key"],
        &[],
    ),
    (&["--config", "--name"], &[]),
];

fuzz_target!(|data: &[u8]| {
    let args: Vec<String> = data.split(|b| *b == 0).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
    for (allowed, repeatable) in SETS {
        if let Ok(s) = options(&args, allowed, repeatable) {
            for name in s.keys() {
                assert!(allowed.contains(&name.as_str()) || repeatable.contains(&name.as_str()), "disallowed option {name}");
            }
        }
    }
    for flag in ["--mask", "--no-systemd", "--show-plan", "--keep-data"] {
        let (present, remaining) = split_flags(&args, flag);
        assert_eq!(present, args.iter().any(|a| a == flag));
        assert!(remaining.iter().all(|a| a != flag));
    }
    for a in &args {
        let _ = valid_name(a, 15);
        let _ = source_tag_from_str(a);
        let _ = is_valid_host(a);
        let _ = normalize_path(a);
    }
});
