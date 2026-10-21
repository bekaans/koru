//! Pulsar event translation.
//!
//! Input: `<Pulsar event JSON>` `0xFF` `<NUL-separated command line>`. If the JSON resolves
//! to Pulsar's `Event` type it is translated into a Koru event. Expected: no crash; every
//! translated event passes `Event::validate` and serializes to JSON. Meaningful only on Linux.
#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(target_os = "linux")]
fuzz_target!(|data: &[u8]| {
    use koru_event::{SourceTag, SensorInfo};
    use koru_pulsar::{Translation, TranslationContext, ProcessAttachment, translate};
    use pulsar_core::event::Event;

    let (json, cmd) = match data.iter().position(|b| *b == 0xFF) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let Ok(event) = serde_json::from_slice::<Event>(json) else { return };
    let context = TranslationContext {
        source_tag: SourceTag::Synthetic,
        host: "fuzz-host".to_string(),
        timestamp_trusted: true,
        sensor: SensorInfo { name: "pulsar".into(), version: "0.11.0".into(), platform: "linux-aarch64".into() },
    };
    let attachment = ProcessAttachment {
        command_line: Some(cmd.split(|b| *b == 0).map(|p| String::from_utf8_lossy(p).into_owned()).collect()),
        ..ProcessAttachment::default()
    };
    if let Ok(Translation::Event(o)) = translate(&event, &attachment, &context) {
        o.validate().expect("a translated event must match the schema");
        serde_json::to_string(&*o).expect("a translated event must serialize to JSON");
    }
});

#[cfg(not(target_os = "linux"))]
fuzz_target!(|_data: &[u8]| {});
