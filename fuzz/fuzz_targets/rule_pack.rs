//! Rule package and neighboring data files (KT-54). The first byte selects the parser: 0 Sigma rule YAML, 1 AI-agent signature (TOML),
//! 2 thresholds (TOML), 3 allowlist (TOML). Expected: no crash or hang; producing an error
//! message never panics.
#![no_main]

use koru_detect::{parse_agent_signature, parse_thresholds, parse_allowlist, parse_rule};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, body)) = data.split_first() else { return };
    let Ok(text) = std::str::from_utf8(body) else { return };
    match selector % 4 {
        0 => {
            if let Err(e) = parse_rule(text) {
                let _ = e.to_string();
            }
        }
        1 => {
            if let Err(e) = parse_agent_signature(text) {
                let _ = e.to_string();
            }
        }
        2 => {
            if let Err(e) = parse_thresholds(text) {
                let _ = e.to_string();
            }
        }
        _ => {
            if let Err(e) = parse_allowlist(text) {
                let _ = e.to_string();
            }
        }
    }
});
