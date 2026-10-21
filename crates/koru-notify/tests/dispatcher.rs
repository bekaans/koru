//! The dispatcher (protected set): rate limiting + summaries, a
//! persistent queue, retries with exponential backoff, the queue surviving a process restart and
//! an end-to-end network outage against a fake server. Time is given from outside (unix ms).

mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::*;
use koru_event::Severity;
use koru_notify::{
    BackoffSettings, ChannelSettings, Dispatcher, HttpsAddress, NotifyError, NtfyChannel, NtfySettings,
    PersistentQueue, RateSettings,
};

const T0: u64 = 1_800_000_000_000;

fn settings() -> ChannelSettings {
    ChannelSettings {
        rate: RateSettings { capacity: 3, refill_ms: 10_000, summary_window_ms: 60_000 },
        backoff: BackoffSettings { base_ms: 1_000, max_ms: 8_000, max_attempts: 5 },
        queue_capacity: 100,
    }
}

fn dir(t: &tempfile::TempDir) -> PathBuf {
    canonicalized(t).join("queue")
}

fn build_dispatcher(t: &tempfile::TempDir, channel: &FakeChannel, a: ChannelSettings) -> Dispatcher {
    let mut d = Dispatcher::new(dir(t));
    d.add_channel(Box::new(channel.clone()), a, T0).unwrap();
    d
}

fn b(i: usize) -> koru_event::Notification {
    notification(Severity::Warning, &format!("title {i}"), &format!("body {i}"))
}

#[test]
fn a_healthy_channel_delivers_directly() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut d = build_dispatcher(&t, &k, settings());
    d.notify(&b(1), T0);
    assert_eq!(k.sent_items().len(), 1);
    let s = d.stats("ntfy").unwrap();
    assert_eq!((s.sent, s.in_queue, s.suppressed_count, s.queued), (1, 0, 0, 0));
    assert!(d.stats("unknown").is_none());
}

#[test]
fn a_notification_reaches_every_channel_with_separate_buckets() {
    let t = is_transient();
    let (a, c) = (FakeChannel::new("ntfy"), FakeChannel::new("telegram"));
    let mut d = Dispatcher::new(dir(&t));
    d.add_channel(Box::new(a.clone()), settings(), T0).unwrap();
    d.add_channel(Box::new(c.clone()), settings(), T0).unwrap();
    for i in 0..3 {
        d.notify(&b(i), T0);
    }
    assert_eq!((a.sent_items().len(), c.sent_items().len()), (3, 3));
    // ntfy runs out; telegram's bucket is separate.
    d.notify(&b(3), T0);
    assert_eq!(a.sent_items().len(), 3);
    assert_eq!(d.stats("ntfy").unwrap().suppressed_count, 1);
    assert_eq!(d.stats("telegram").unwrap().suppressed_count, 1);
}

#[test]
fn a_second_channel_with_the_same_name_is_rejected() {
    let t = is_transient();
    let mut d = Dispatcher::new(dir(&t));
    d.add_channel(Box::new(FakeChannel::new("ntfy")), settings(), T0).unwrap();
    let error = d.add_channel(Box::new(FakeChannel::new("ntfy")), settings(), T0).unwrap_err();
    assert!(matches!(error, NotifyError::Settings(_)));
}

#[test]
fn an_event_flood_hits_the_rate_limit_and_is_summarized() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut d = build_dispatcher(&t, &k, settings());
    for i in 0..50 {
        d.notify(&b(i), T0 + i as u64 * 100);
    }
    // Capacity 3: only the first three go out; 47 are suppressed.
    assert_eq!(k.sent_items().len(), 3);
    let s = d.stats("ntfy").unwrap();
    assert_eq!((s.sent, s.suppressed_count, s.in_queue), (3, 47, 0));
    // No summary before the window fills.
    d.process(T0 + 30_000);
    assert_eq!(k.sent_items().len(), 3);
    // When the window (60 s from the first suppression) fills, one summary goes out.
    d.process(T0 + 300 + 60_000);
    let g = k.sent_items();
    assert_eq!(g.len(), 4, "a single summary notification");
    assert!(g[3].body.contains("In the last 60 s, 47 more findings"), "{}", g[3].body);
    let s = d.stats("ntfy").unwrap();
    assert_eq!((s.summaries_sent, s.sent), (1, 4));
    // The summary goes out once.
    d.process(T0 + 400_000);
    assert_eq!(k.sent_items().len(), 4);
}

#[test]
fn the_rate_limit_is_configurable_and_refills() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut a = settings();
    a.rate = RateSettings { capacity: 1, refill_ms: 5_000, summary_window_ms: 1_000_000 };
    let mut d = build_dispatcher(&t, &k, a);
    d.notify(&b(0), T0);
    d.notify(&b(1), T0 + 1_000);
    assert_eq!(k.sent_items().len(), 1);
    d.notify(&b(2), T0 + 5_000);
    assert_eq!(k.sent_items().len(), 2, "token bucket is full");
}

#[test]
fn a_transient_error_queues_and_delivery_resumes() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut d = build_dispatcher(&t, &k, settings());
    k.set_a_transient_failure(true);
    d.notify(&b(1), T0);
    let s = d.stats("ntfy").unwrap();
    assert_eq!((s.sent, s.queued, s.in_queue), (0, 1, 1));
    k.set_a_transient_failure(false);
    d.process(T0 + 2_000);
    assert_eq!(k.sent_items().len(), 1);
    assert_eq!(k.sent_items()[0].title, "title 1");
    let s = d.stats("ntfy").unwrap();
    assert_eq!((s.sent, s.in_queue), (1, 0));
}

#[test]
fn a_retry_is_not_attempted_before_its_backoff() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut a = settings();
    a.rate.capacity = 1_000;
    let mut d = build_dispatcher(&t, &k, a);
    k.set_a_transient_failure(true);
    d.notify(&b(1), T0);
    assert_eq!(k.attempts_count(), 1);
    // The first backoff delay is at most base_ms (1 s) and at least base_ms/2.
    d.process(T0 + 400);
    assert_eq!(k.attempts_count(), 1, "must not retry before it is due");
    d.process(T0 + 1_000);
    assert_eq!(k.attempts_count(), 2, "it retries once the base delay passes");
    // After the second failure the backoff delay doubles: [1000, 2000] ms.
    d.process(T0 + 1_000 + 900);
    assert_eq!(k.attempts_count(), 2);
    d.process(T0 + 1_000 + 2_000);
    assert_eq!(k.attempts_count(), 3);
    // After the third, [2000, 4000]; each network failure makes exactly ONE retry.
    d.process(T0 + 3_000 + 4_000);
    assert_eq!(k.attempts_count(), 4);
    // The retry count in the record reaches disk too (backoff survives a restart).
    let reopened = PersistentQueue::open(&dir(&t), "ntfy", 100).expect("the queue must open");
    assert_eq!(reopened.records()[0].attempts, 3, "the first direct send does not count; three retries happened");
}

#[test]
fn one_process_call_does_not_drain_the_queue_on_a_network_error() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut a = settings();
    a.rate.capacity = 1_000;
    let mut d = build_dispatcher(&t, &k, a);
    k.set_a_transient_failure(true);
    for i in 0..10 {
        d.notify(&b(i), T0);
    }
    assert_eq!(k.attempts_count(), 10);
    d.process(T0 + 100_000);
    assert_eq!(
        k.attempts_count(),
        11,
        "with the network down it stops at the first failure; it must not hammer all of them"
    );
}

#[test]
fn the_queue_delivers_oldest_first() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut a = settings();
    a.rate.capacity = 1_000;
    let mut d = build_dispatcher(&t, &k, a);
    k.set_a_transient_failure(true);
    for i in 0..4 {
        d.notify(&b(i), T0 + i as u64);
    }
    k.set_a_transient_failure(false);
    d.process(T0 + 60_000);
    let headers: Vec<_> = k.sent_items().iter().map(|x| x.title.clone()).collect();
    assert_eq!(headers, ["title 0", "title 1", "title 2", "title 3"]);
}

#[test]
fn a_record_past_the_attempt_limit_drops_and_counts() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut a = settings();
    a.rate.capacity = 1_000;
    a.backoff = BackoffSettings { base_ms: 10, max_ms: 20, max_attempts: 3 };
    let mut d = build_dispatcher(&t, &k, a);
    k.set_a_transient_failure(true);
    d.notify(&b(1), T0);
    for step in 1..=20 {
        d.process(T0 + step * 1_000);
    }
    let s = d.stats("ntfy").unwrap();
    assert_eq!((s.in_queue, s.dropped_retries, s.sent), (0, 1, 0));
    assert!(k.attempts_count() <= 1 + 3, "at most 3 retries: {}", k.attempts_count());
    // Even when the network returns later, a dropped record never comes back.
    k.set_a_transient_failure(false);
    d.process(T0 + 100_000);
    assert!(k.sent_items().is_empty());
}

#[test]
fn a_permanent_error_is_never_queued_and_counts() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut d = build_dispatcher(&t, &k, settings());
    k.set_a_permanent_failure(true);
    d.notify(&b(1), T0);
    let s = d.stats("ntfy").unwrap();
    assert_eq!((s.permanent_errors, s.in_queue, s.queued), (1, 0, 0));
    k.set_a_permanent_failure(false);
    d.process(T0 + 100_000);
    assert!(k.sent_items().is_empty(), "a permanent error is never retried");
}

#[test]
fn an_overflowing_queue_drops_and_counts_the_oldest() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut a = settings();
    a.rate.capacity = 1_000;
    a.queue_capacity = 3;
    let mut d = build_dispatcher(&t, &k, a);
    k.set_a_transient_failure(true);
    for i in 0..5 {
        d.notify(&b(i), T0);
    }
    let s = d.stats("ntfy").unwrap();
    assert_eq!((s.in_queue, s.dropped_overflow, s.queued), (3, 2, 5));
    k.set_a_transient_failure(false);
    d.process(T0 + 60_000);
    let headers: Vec<_> = k.sent_items().iter().map(|x| x.title.clone()).collect();
    assert_eq!(headers, ["title 2", "title 3", "title 4"]);
}

#[test]
fn the_queue_survives_a_process_restart() {
    let t = is_transient();
    {
        let k = FakeChannel::new("ntfy");
        let mut a = settings();
        a.rate.capacity = 1_000;
        let mut d = build_dispatcher(&t, &k, a);
        k.set_a_transient_failure(true);
        d.notify(&b(1), T0);
        d.notify(&b(2), T0);
        assert_eq!(d.stats("ntfy").unwrap().in_queue, 2);
    } // the process dies (kill -9 style: no shutdown calls)
    let k2 = FakeChannel::new("ntfy");
    let mut d2 = build_dispatcher(&t, &k2, settings());
    assert_eq!(d2.stats("ntfy").unwrap().in_queue, 2, "the queue loaded from disk");
    d2.process(T0 + 60_000);
    let headers: Vec<_> = k2.sent_items().iter().map(|x| x.title.clone()).collect();
    assert_eq!(headers, ["title 1", "title 2"]);
    assert_eq!(d2.stats("ntfy").unwrap().in_queue, 0);
    // Delivered ones never come back after a restart.
    let k3 = FakeChannel::new("ntfy");
    let d3 = build_dispatcher(&t, &k3, settings());
    assert_eq!(d3.stats("ntfy").unwrap().in_queue, 0);
}

#[test]
fn the_queue_file_is_0600_in_a_0700_dir() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut d = build_dispatcher(&t, &k, settings());
    k.set_a_transient_failure(true);
    d.notify(&b(1), T0);
    assert_eq!(file_mode(&dir(&t)), 0o700);
    assert_eq!(file_mode(&dir(&t).join("ntfy.queue")), 0o600);
}

#[test]
fn a_failed_summary_send_queues_the_summary() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut a = settings();
    a.rate = RateSettings { capacity: 1, refill_ms: 1_000, summary_window_ms: 10_000 };
    let mut d = build_dispatcher(&t, &k, a);
    d.notify(&b(0), T0);
    for i in 1..6 {
        d.notify(&b(i), T0 + 10);
    }
    assert_eq!(d.stats("ntfy").unwrap().suppressed_count, 5);
    k.set_a_transient_failure(true);
    d.process(T0 + 20_000);
    let s = d.stats("ntfy").unwrap();
    assert_eq!(s.in_queue, 1, "the summary must not vanish; it must be queued");
    k.set_a_transient_failure(false);
    d.process(T0 + 60_000);
    let last = k.sent_items().pop().unwrap();
    assert!(last.body.contains("5 more findings"), "{}", last.body);
}

// --- end to end against a fake HTTP server ---

#[test]
fn an_outage_queues_and_delivery_resumes_to_the_ntfy_server() {
    let t = is_transient();
    let s = FakeHttp::start_answering(FakeReply::DropConnection);
    let mut ntfy = NtfySettings::new(HttpsAddress::parse_parts(&s.url("/topic")).unwrap());
    ntfy.timeout = Duration::from_millis(800);
    let mut d = Dispatcher::new(dir(&t));
    let mut a = settings();
    a.rate.capacity = 1_000;
    d.add_channel(Box::new(NtfyChannel::new(ntfy)), a, T0).unwrap();

    d.notify(&notification(Severity::Critical, "Decoy read", "detail"), T0);
    assert_eq!(d.stats("ntfy").unwrap().in_queue, 1, "it must be queued when the network drops");

    s.set_defaults(FakeReply::WithStatus(200));
    d.process(T0 + 2_000);
    assert_eq!(d.stats("ntfy").unwrap().in_queue, 0);
    let requests = s.requests();
    assert_eq!(requests.last().unwrap().title("Title"), Some("Decoy read"));
    assert_eq!(requests.last().unwrap().body_text(), "detail");
}

#[test]
fn a_channel_to_an_unreachable_address_queues() {
    let t = is_transient();
    let mut ntfy =
        NtfySettings::new(HttpsAddress::parse_parts(&format!("http://127.0.0.1:{}/topic", a_free_port())).unwrap());
    ntfy.timeout = Duration::from_millis(500);
    let mut d = Dispatcher::new(dir(&t));
    d.add_channel(Box::new(NtfyChannel::new(ntfy)), settings(), T0).unwrap();
    d.notify(&plain_notification(), T0);
    let s = d.stats("ntfy").unwrap();
    assert_eq!((s.sent, s.in_queue), (0, 1));
}
