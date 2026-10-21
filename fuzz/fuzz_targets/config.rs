//! Configuration file (TOML; ADR-0008 section 3). Expected: no crash; a configuration
//! accepted as valid reads back identically from its `toml()` output (round-trip) and does
//! not change the systemd unit's line count (no line/key injection from values into the unit).
#![no_main]

use koru::distribution::render_unit;
use koru::config::{DEFAULT_NAME, Config};
use koru_event::SourceTag;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(y) = Config::parse(text) else { return };
    let written = y.toml();
    let back = Config::parse(&written).expect("the toml() output must read back");
    assert_eq!(y, back, "round-trip mismatch");
    let unit = render_unit(&y);
    let base = render_unit(
        &Config::defaults(DEFAULT_NAME, SourceTag::Real, std::path::Path::new("/root")).unwrap(),
    );
    assert_eq!(unit.lines().count(), base.lines().count(), "a line was injected into the unit:\n{unit}");
    assert!(!unit.contains('\0') && !unit.contains('\r'));
    for line in unit.lines() {
        assert!(line.is_empty() || line.starts_with('[') || line.contains('='), "{line:?}");
    }
});
