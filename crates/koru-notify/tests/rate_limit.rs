//! Rate limiting, summarization and backoff (protected set). Time
//! is given from outside (ms); the tests never depend on the wall clock or on sleeps.

mod common;

use common::*;
use koru_event::Severity;
use koru_notify::{BackoffSettings, NotifyError, RateSettings, Summarizer, TokenBucket};

fn settings(capacity: u32, refill_ms: u64) -> RateSettings {
    RateSettings::new(capacity, refill_ms, 60_000).unwrap()
}

#[test]
fn the_bucket_starts_full_and_yields_its_capacity() {
    let a = settings(3, 1_000);
    let mut k = TokenBucket::new(&a, 10_000);
    assert_eq!(k.token(10_000), 3);
    assert!(k.try_take(10_000) && k.try_take(10_000) && k.try_take(10_000));
    assert!(!k.try_take(10_000), "the fourth must be denied");
    assert_eq!(k.token(10_000), 0);
}

#[test]
fn tokens_refill_over_time_without_exceeding_capacity() {
    let a = settings(3, 1_000);
    let mut k = TokenBucket::new(&a, 0);
    for _ in 0..3 {
        assert!(k.try_take(0));
    }
    assert!(!k.try_take(999), "no token before it refills");
    assert!(k.try_take(1_000), "one token after 1 s");
    assert!(!k.try_take(1_000));
    assert_eq!(k.token(3_500), 2, "2 full tokens after 2.5 s");
    assert_eq!(k.token(1_000_000), 3, "never exceeds the capacity");
}

#[test]
fn a_partial_refill_is_not_lost() {
    let a = settings(2, 1_000);
    let mut k = TokenBucket::new(&a, 0);
    assert!(k.try_take(0) && k.try_take(0));
    assert!(!k.try_take(600));
    assert!(k.try_take(1_000), "0,6 + 0,4 sn = 1 token");
}

#[test]
fn backwards_time_adds_and_removes_no_tokens() {
    let a = settings(2, 1_000);
    let mut k = TokenBucket::new(&a, 50_000);
    assert!(k.try_take(50_000) && k.try_take(50_000));
    assert!(!k.try_take(10_000), "a clock going backwards must not hand out free tokens");
    assert!(!k.try_take(50_000));
    assert!(k.try_take(51_000));
}

#[test]
fn channels_use_independent_buckets() {
    let a = settings(1, 60_000);
    let mut ntfy = TokenBucket::new(&a, 0);
    let mut telegram = TokenBucket::new(&a, 0);
    assert!(ntfy.try_take(0));
    assert!(!ntfy.try_take(0));
    assert!(telegram.try_take(0), "an exhausted ntfy bucket must not affect telegram");
}

#[test]
fn zero_settings_are_rejected_and_defaults_are_sane() {
    assert!(matches!(RateSettings::new(0, 1_000, 60_000), Err(NotifyError::Settings(_))));
    assert!(RateSettings::new(5, 0, 60_000).is_err());
    assert!(RateSettings::new(5, 1_000, 0).is_err());
    let v = RateSettings::default();
    assert!(v.capacity >= 1 && v.refill_ms >= 1 && v.summary_window_ms >= 1);
    assert_eq!(v.summary_window_ms, 60_000);
}

#[test]
fn the_summarizer_is_not_ready_until_the_window_fills() {
    let mut o = Summarizer::new(60_000);
    assert!(!o.is_ready(0) && o.pending() == 0);
    assert!(o.take_summary(0).is_none());
    o.suppressed(&notification(Severity::Warning, "a", "b"), 1_000);
    o.suppressed(&notification(Severity::Warning, "a", "b"), 2_000);
    assert_eq!(o.pending(), 2);
    assert!(!o.is_ready(60_999), "the window is 60 s from the first suppression (1000)");
    assert!(o.is_ready(61_000));
}

#[test]
fn the_summary_notification_text_and_severity() {
    let mut o = Summarizer::new(60_000);
    for i in 0..37 {
        let severity = if i == 5 { Severity::Critical } else { Severity::Info };
        o.suppressed(&notification(severity, "x", "y"), 1_000 + i);
    }
    let last = notification(Severity::Warning, "last", "g");
    o.suppressed(&last, 1_100);
    assert!(o.is_ready(61_000));
    let b = o.take_summary(61_000).expect("summary");
    assert!(b.body.contains("In the last 60 s, 38 more findings"), "{}", b.body);
    assert!(b.title.contains("38"), "{}", b.title);
    assert_eq!(b.severity, Severity::Critical, "the highest of the suppressed");
    assert_eq!(b.event_id, last.event_id, "the last suppressed event");
    assert_eq!(o.pending(), 0, "the summary resets the counter");
    assert!(!o.is_ready(1_000_000));
    assert!(o.take_summary(1_000_000).is_none());
}

#[test]
fn the_summary_window_is_configurable() {
    let mut o = Summarizer::new(300_000);
    o.suppressed(&notification(Severity::Warning, "a", "b"), 0);
    assert!(!o.is_ready(299_999) && o.is_ready(300_000));
    assert!(o.take_summary(300_000).unwrap().body.contains("In the last 300 s, 1 more findings"));
}

#[test]
fn the_summarizer_opens_a_new_window() {
    let mut o = Summarizer::new(10_000);
    o.suppressed(&notification(Severity::Warning, "a", "b"), 0);
    assert!(o.take_summary(10_000).is_some());
    o.suppressed(&notification(Severity::Warning, "a", "b"), 50_000);
    assert!(!o.is_ready(55_000) && o.is_ready(60_000), "the new window starts at the second suppression");
}

#[test]
fn the_summary_text_carries_no_attacker_data() {
    let mut o = Summarizer::new(1_000);
    o.suppressed(&notification(Severity::Warning, "\u{1b}[31mATTACKER", "x\r\nBcc: evil"), 0);
    let b = o.take_summary(1_000).unwrap();
    assert!(!b.title.contains("ATTACKER") && !b.body.contains("ATTACKER") && !b.body.contains("Bcc"));
}

// --- backoff ---

#[test]
fn the_backoff_grows_exponentially_and_caps() {
    let g = BackoffSettings { base_ms: 1_000, max_ms: 60_000, max_attempts: 10 };
    // The top end without jitter: random = u64::MAX -> d.
    let delays: Vec<u64> = (0..10).map(|n| g.wait_ms(n, u64::MAX)).collect();
    assert_eq!(delays[..6], [1_000, 2_000, 4_000, 8_000, 16_000, 32_000]);
    assert!(delays[6..].iter().all(|&d| d == 60_000), "{delays:?}");
    // The bottom end: random = 0 -> d/2.
    assert_eq!(g.wait_ms(0, 0), 500);
    assert_eq!(g.wait_ms(3, 0), 4_000);
    assert_eq!(g.wait_ms(50, 0), 30_000);
}

#[test]
fn the_backoff_jitter_range_and_spread() {
    let g = BackoffSettings { base_ms: 1_000, max_ms: 600_000, max_attempts: 48 };
    let mut seen = std::collections::BTreeSet::new();
    let mut r = 0x9E37_79B9_7F4A_7C15_u64;
    for _ in 0..500 {
        r = r.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let d = g.wait_ms(4, r);
        assert!((8_000..=16_000).contains(&d), "{d}");
        seen.insert(d);
    }
    assert!(seen.len() > 100, "the jitter must really spread: {} distinct values", seen.len());
}

#[test]
fn the_backoff_does_not_overflow() {
    let g = BackoffSettings { base_ms: u64::MAX / 2, max_ms: u64::MAX, max_attempts: 100 };
    for n in [0, 1, 2, 63, 64, 65, 1_000, u32::MAX] {
        let _ = g.wait_ms(n, u64::MAX);
        let _ = g.wait_ms(n, 0);
    }
    let d = BackoffSettings::default();
    assert!(d.base_ms >= 1 && d.max_ms >= d.base_ms && d.max_attempts >= 1);
}

#[test]
fn random_u64_varies() {
    let a = koru_notify::backoff::random_u64();
    let b = koru_notify::backoff::random_u64();
    let c = koru_notify::backoff::random_u64();
    assert!(a != b || b != c, "the CSPRNG must not give the same value three times");
}
