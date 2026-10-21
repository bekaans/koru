//! Decoy template (TOML; packages/decoys/*.toml). Expected: no
//! crash; a parsed template passes its own validation and producing an error message never panics.
#![no_main]

use koru_decoy::parse_template;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    match parse_template(text) {
        Ok(s) => {
            s.validate().expect("a parsed template must validate");
            let _ = format!("{s:?}");
        }
        Err(e) => {
            let _ = e.to_string();
        }
    }
});
