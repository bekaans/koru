//! JSONL import (`koru event ingest`). The input is split
//! into lines (the same line reader as the CLI) and each line passes the store's entry
//! validation. Expected: no crash; an accepted event serialized again is accepted again
//! (stability) and passes `Event::validate` and the `host`/`sensor.*` format check (KT-66).
#![no_main]

use std::io::Cursor;

use koru::input::{InputLine, read_line};
use koru_store::validate_line;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut input = Cursor::new(data);
    while let Ok(Some(line)) = read_line(&mut input) {
        let InputLine::Text(text) = line else { continue };
        let Ok(event) = validate_line(&text) else { continue };
        event.validate().expect("an accepted event must validate");
        event.check_identity_fields().expect("an accepted event's identity fields must be valid");
        let written = serde_json::to_string(&event).expect("the event must serialize to JSON");
        let again = validate_line(&written).expect("a re-serialized event must be accepted");
        assert_eq!(event, again, "round-trip unstable");
    }
});
