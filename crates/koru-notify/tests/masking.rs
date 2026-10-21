//! IP masking in notifications (protected set): IPs in notifications are masked by default (IPv4 /24, IPv6 /48); masking can be
//! turned off in settings; the full IP stays only in the local store, never in the queue file or a channel (ADR-0007 §8, KT-71).

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use common::*;
use koru_event::Severity;
use koru_notify::{
    ChannelSet, ChannelSettings, Dispatcher, HttpsAddress, NotifyError, NtfyChannel, NtfySettings, PersistentQueue,
    mask_notification,
};

const T0: u64 = 1_800_000_000_000;
const BODY_SAMPLE: &str = "connection from 203.0.113.77; source:10.1.2.3 and [2001:db8:abcd:1234::5]:22";

fn masked_body() -> &'static str {
    "connection from 203.0.113.0; source:10.1.2.0 and [2001:db8:abcd::]:22"
}

fn settings() -> ChannelSettings {
    ChannelSettings::default()
}

#[test]
fn masking_covers_title_and_body_and_keeps_identity_and_severity() {
    let b = notification(Severity::Critical, "Attacker 198.51.100.23", BODY_SAMPLE);
    let m = mask_notification(&b);
    assert_eq!(m.title, "Attacker 198.51.100.0");
    assert_eq!(m.body, masked_body());
    assert_eq!((m.severity, m.event_id), (b.severity, b.event_id));
    assert_eq!(mask_notification(&m), m, "idempotent");
}

#[test]
fn masking_leaves_non_address_text_alone() {
    let b = notification(
        Severity::Warning,
        "Decoy was read",
        "The process opened /root/.ssh/id_ed25519 (version 1.2.3, at 10:15:30)",
    );
    assert_eq!(mask_notification(&b), b);
}

#[test]
fn the_dispatcher_masks_by_default() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut d = Dispatcher::new(canonicalized(&t).join("queue"));
    d.add_channel(Box::new(k.clone()), settings(), T0).unwrap();
    assert!(d.masking_enabled(), "the default: masked");
    d.notify(&notification(Severity::Critical, "Attacker 198.51.100.23", BODY_SAMPLE), T0);
    let g = k.sent_items();
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].title, "Attacker 198.51.100.0");
    assert_eq!(g[0].body, masked_body());
    assert!(!format!("{:?}", g[0]).contains("198.51.100.23"));
}

#[test]
fn masking_can_be_disabled_and_the_full_ip_goes() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    let mut d = Dispatcher::new(canonicalized(&t).join("queue"));
    d.add_channel(Box::new(k.clone()), settings(), T0).unwrap();
    d.set_masking(false);
    assert!(!d.masking_enabled());
    d.notify(&notification(Severity::Critical, "Attacker 198.51.100.23", BODY_SAMPLE), T0);
    assert_eq!(k.sent_items()[0].body, BODY_SAMPLE);
    d.set_masking(true);
    d.notify(&notification(Severity::Critical, "x", "10.9.8.7"), T0 + 1);
    assert_eq!(k.sent_items()[1].body, "10.9.8.0", "masked again when re-enabled");
}

#[test]
fn no_full_ip_enters_the_queue_file() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    k.set_a_transient_failure(true);
    let queue_dir = canonicalized(&t).join("queue");
    let mut d = Dispatcher::new(&queue_dir);
    d.add_channel(Box::new(k.clone()), settings(), T0).unwrap();
    d.notify(&notification(Severity::Critical, "Attacker 198.51.100.23", BODY_SAMPLE), T0);
    assert_eq!(d.stats("ntfy").unwrap().in_queue, 1);
    let file = fs::read_to_string(queue_dir.join("ntfy.queue")).unwrap();
    for full in ["198.51.100.23", "203.0.113.77", "10.1.2.3", "2001:db8:abcd:1234"] {
        assert!(!file.contains(full), "the queue file holds a full IP: {full}");
    }
    let again_v = PersistentQueue::open(&queue_dir, "ntfy", 10).unwrap();
    assert_eq!(again_v.records()[0].body, masked_body());
    // What leaves the queue when the network returns is masked too.
    k.set_a_transient_failure(false);
    d.process(T0 + 60_000);
    assert_eq!(k.sent_items()[0].body, masked_body());
}

#[test]
fn with_masking_off_the_queue_holds_the_full_ip_locally() {
    let t = is_transient();
    let k = FakeChannel::new("ntfy");
    k.set_a_transient_failure(true);
    let queue_dir = canonicalized(&t).join("queue");
    let mut d = Dispatcher::new(&queue_dir);
    d.add_channel(Box::new(k.clone()), settings(), T0).unwrap();
    d.set_masking(false);
    d.notify(&notification(Severity::Critical, "b", "198.51.100.23"), T0);
    assert!(fs::read_to_string(queue_dir.join("ntfy.queue")).unwrap().contains("198.51.100.23"));
}

#[test]
fn the_real_ntfy_channel_sends_a_masked_body() {
    let t = is_transient();
    let s = FakeHttp::start();
    let mut ntfy = NtfySettings::new(HttpsAddress::parse_parts(&s.url("/topic")).unwrap());
    ntfy.timeout = Duration::from_millis(800);
    let mut d = Dispatcher::new(canonicalized(&t).join("queue"));
    d.add_channel(Box::new(NtfyChannel::new(ntfy)), settings(), T0).unwrap();
    d.notify(&notification(Severity::Critical, "Attacker 198.51.100.23", BODY_SAMPLE), T0);
    let i = s.one_request();
    assert_eq!(i.body_text(), masked_body());
    assert!(i.title("Title").is_some_and(|t| !t.contains("198.51.100.23")));
    assert!(!String::from_utf8_lossy(&i.raw).contains("198.51.100.23"));
}

// --- settings ---

fn read(o: &BTreeMap<String, String>) -> Result<ChannelSet, NotifyError> {
    ChannelSet::from_env(&|name| o.get(name).cloned())
}

fn environment(value: Option<&str>) -> BTreeMap<String, String> {
    let mut o = BTreeMap::new();
    if let Some(d) = value {
        o.insert("KORU_NOTIFY_MASK_IP".to_string(), d.to_string());
    }
    o
}

#[test]
fn masking_is_the_default_in_settings() {
    assert!(read(&environment(None)).unwrap().mask_ip, "masked when the variable is absent");
    assert!(read(&environment(Some(""))).unwrap().mask_ip, "an empty value is ignored");
    assert!(ChannelSet::default().mask_ip, "Default must be masked too");
}

#[test]
fn masking_can_be_toggled_in_settings() {
    for off in ["false", "0", "no", "NO", "False", " false "] {
        assert!(!read(&environment(Some(off))).unwrap().mask_ip, "{off:?}");
    }
    for on in ["true", "1", "yes", "YES", "True"] {
        assert!(read(&environment(Some(on))).unwrap().mask_ip, "{on:?}");
    }
}

#[test]
fn an_invalid_value_is_rejected_without_printing_it() {
    let error = read(&environment(Some("maybe-VERY-SECRET"))).unwrap_err().to_string();
    assert!(error.contains("KORU_NOTIFY_MASK_IP"), "{error}");
    assert!(!error.contains("VERY-SECRET") && !error.contains("maybe"), "{error}");
}
