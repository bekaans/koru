//! Translation counters (protected set). The bridge module used to drop translation errors
//! silently; a rejection must be "rejected and counted".
//! A translation rejection is now counted and (in the composition, in the `koru` crate) forwarded to
//! the data-quality report. These tests are platform-independent (they run on Mac too); the Pulsar-dependent part is Linux-only.

use std::sync::Arc;

use koru_event::{Event, ValidationError};
use koru_pulsar::{SkipReason, Translation, TranslationCounters, TranslationError, count_translation};

fn event() -> Event {
    let mut v: serde_json::Value =
        serde_json::from_str(include_str!("../../koru-event/tests/data/valid/file-opened.json")).unwrap();
    v["event_id"] = serde_json::json!(koru_event::EventId::new().to_string());
    serde_json::from_value(v).unwrap()
}

fn invalid_field() -> TranslationError {
    TranslationError::InvalidField { field: "pid", reason: "negative".to_string() }
}

fn validation() -> TranslationError {
    TranslationError::Validation(ValidationError::Empty { field: "host" })
}

#[test]
fn all_zero_at_the_start() {
    let s = TranslationCounters::default();
    let g = s.snapshot();
    assert_eq!(
        g.translated
            + g.rejected_invalid_field
            + g.rejected_validation
            + g.skipped_threat_duplicate
            + g.skipped_unsupported_kind,
        0
    );
    assert_eq!(g.rejected_total(), 0);
}

#[test]
fn the_translated_event_is_returned_and_counted() {
    let s = TranslationCounters::default();
    let o = event();
    let output = count_translation(Ok(Translation::Event(Box::new(o.clone()))), &s).expect("an event must be returned");
    assert_eq!(*output, o);
    let g = s.snapshot();
    assert_eq!((g.translated, g.rejected_total()), (1, 0));
}

#[test]
fn translation_errors_are_counted_not_dropped_silently() {
    let s = TranslationCounters::default();
    assert!(count_translation(Err(invalid_field()), &s).is_none());
    assert!(count_translation(Err(invalid_field()), &s).is_none());
    assert!(count_translation(Err(validation()), &s).is_none());
    let g = s.snapshot();
    assert_eq!(g.rejected_invalid_field, 2);
    assert_eq!(g.rejected_validation, 1);
    assert_eq!(g.rejected_total(), 3);
    assert_eq!(g.translated, 0);
}

#[test]
fn deliberately_skipped_ones_are_not_rejections() {
    let s = TranslationCounters::default();
    assert!(
        count_translation(Ok(Translation::Skipped(SkipReason::ThreatDuplicate { koru_originated: true })), &s)
            .is_none()
    );
    assert!(
        count_translation(Ok(Translation::Skipped(SkipReason::ThreatDuplicate { koru_originated: false })), &s)
            .is_none()
    );
    assert!(
        count_translation(Ok(Translation::Skipped(SkipReason::UnsupportedKind { kind: "DnsQuery".into() })), &s)
            .is_none()
    );
    let g = s.snapshot();
    assert_eq!(g.skipped_threat_duplicate, 2);
    assert_eq!(g.skipped_unsupported_kind, 1);
    assert_eq!(g.rejected_total(), 0, "skipped events do not count toward data_dir quality rejects");
}

#[test]
fn counters_are_shared_between_threads() {
    let s = Arc::new(TranslationCounters::default());
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                for _ in 0..500 {
                    count_translation(Err(invalid_field()), &s);
                    count_translation(Err(validation()), &s);
                }
            })
        })
        .collect();
    for i in workers {
        i.join().unwrap();
    }
    let g = s.snapshot();
    assert_eq!((g.rejected_invalid_field, g.rejected_validation), (2000, 2000));
}
