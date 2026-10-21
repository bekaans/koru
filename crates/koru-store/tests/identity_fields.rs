//! KT-66: in imported events the `host` and `sensor.*` fields pass a
//! strict format check. The host name must match RFC 1123; IP-like values, free text, spaces,
//! control, and direction characters are rejected. The rejection counts under the `validation`
//! reason (the `RejectReason` set does not change). The locked `masking.rs` test is untouched:
//! it does not write to the store.

mod common;

use common::*;
use koru_store::{IngestOutcome, RejectReason};
use serde_json::{Value, json};

fn record_with(field: &str, value: Value) -> String {
    let mut v = event_json_value("file_opened", 1);
    set_field(&mut v, field, value);
    v.to_string()
}

fn validation_count(d: &koru_store::Store) -> u64 {
    d.rejected().unwrap().into_iter().find(|(n, _)| *n == RejectReason::Validation).map_or(0, |(_, s)| s)
}

#[test]
fn valid_identity_fields_are_accepted() {
    let t = temp();
    let mut d = open_store(&t);
    let primary_hosts = [
        "lab-server",
        "koru-lab",
        "lima-koru-lab",
        "web01.sample.example",
        "SRV-01",
        "a",
        "ip-10-0-0-5",
        "db1.int.sample.example",
        "x1.y2.z3.com",
    ];
    for (i, name) in primary_hosts.iter().enumerate() {
        let mut v = event_json_value("file_opened", i as u32 + 1);
        set_field(&mut v, "/host", json!(name));
        assert_eq!(d.store_json(&v.to_string()).unwrap(), IngestOutcome::Stored, "{name}");
    }
    let sensors = [
        ("pulsar", "0.11.0-alpha.1+0bb7bc20", "linux-aarch64"),
        ("pulsar", "0.10.1", "linux-x86_64"),
        ("koru-sensor", "1.2.3", "linux-riscv64"),
        ("sensor_2", "2.0.0-rc.1", "freebsd-amd64"),
    ];
    for (i, (name, version, platform)) in sensors.iter().enumerate() {
        let mut v = event_json_value("file_opened", i as u32 + 50);
        set_field(&mut v, "/sensor", json!({"name": name, "version": version, "platform": platform}));
        assert_eq!(d.store_json(&v.to_string()).unwrap(), IngestOutcome::Stored, "{name} {version} {platform}");
    }
    assert_eq!(validation_count(&d), 0);
}

#[test]
fn invalid_host_rejected_and_counted() {
    let t = temp();
    let mut d = open_store(&t);
    let long_tag = "a".repeat(64);
    let long_name = vec!["abcdefghi"; 30].join("."); // 299 characters
    let invalid = [
        "10.9.8.7",
        "192.168.1.1",
        "0.0.0.0",
        "1.2.3",
        "123",
        "::1",
        "2001:db8::1",
        "[2001:db8::1]",
        "primary host",
        "password=secret123",
        "user@server",
        "http://sample.example",
        "sample.example/path",
        "secret_host",
        "-leading",
        "biter-",
        "a..b",
        ".leading",
        "biter.",
        "web01.sample.123",
        "\u{fc}nicode-name",
        "new\nline",
        "tab\there",
        "direction\u{202e}char",
        "zero\u{0}byte",
        &long_tag,
        &long_name,
        "   ",
    ];
    for (i, name) in invalid.iter().enumerate() {
        let r = d.store_json(&record_with("/host", json!(name))).unwrap();
        assert_eq!(r, IngestOutcome::Rejected(RejectReason::Validation), "{name:?}");
        assert_eq!(validation_count(&d), i as u64 + 1, "{name:?} must be counted");
    }
}

#[test]
fn invalid_sensor_fields_rejected_and_counted() {
    let t = temp();
    let mut d = open_store(&t);
    let mut number = 0u64;
    let long = "s".repeat(65);
    let bad_names = [
        "sensor-10.9.8.7",
        "Sens\u{f6}r N\u{131}me",
        "a b",
        "-pulsar",
        "pulsar\n",
        "name=val\u{11f}e",
        "10.9.8.7",
        &long,
        "../x",
    ];
    for name in bad_names {
        let r = d.store_json(&record_with("/sensor/name", json!(name))).unwrap();
        assert_eq!(r, IngestOutcome::Rejected(RejectReason::Validation), "sensor.name {name:?}");
        number += 1;
        assert_eq!(validation_count(&d), number);
    }
    let bad_versions = ["10.9.8.7", "v1 final", "1.2", "v\u{fc}rsion", "1.0.0 ; rm -rf", "1.0.0\n", "0.1.0-", &long];
    for version in bad_versions {
        let r = d.store_json(&record_with("/sensor/version", json!(version))).unwrap();
        assert_eq!(r, IngestOutcome::Rejected(RejectReason::Validation), "sensor.version {version:?}");
        number += 1;
        assert_eq!(validation_count(&d), number);
    }
    let bad_platforms = [
        "linux aarch64",
        "10.1.1.1",
        "Linux-x86_64",
        "linux/arm64",
        "secret:password",
        "linux\u{202e}",
        &long,
        "linux-",
    ];
    for p in bad_platforms {
        let r = d.store_json(&record_with("/sensor/platform", json!(p))).unwrap();
        assert_eq!(r, IngestOutcome::Rejected(RejectReason::Validation), "sensor.platform {p:?}");
        number += 1;
        assert_eq!(validation_count(&d), number);
    }
}

#[test]
fn store_event_path_applies_the_same_checks() {
    let t = temp();
    let mut d = open_store(&t);
    let mut o = event("file_opened", 3);
    o.host = "10.9.8.7".to_string();
    assert_eq!(d.store_event(&o).unwrap(), IngestOutcome::Rejected(RejectReason::Validation));
    let mut o = event("file_opened", 4);
    o.sensor.name = "sensor-10.9.8.7".to_string();
    assert_eq!(d.store_event(&o).unwrap(), IngestOutcome::Rejected(RejectReason::Validation));
    assert_eq!(validation_count(&d), 2);
    assert_eq!(d.store_event(&event("file_opened", 5)).unwrap(), IngestOutcome::Stored);
}

#[test]
fn rejected_event_does_not_enter_store_or_spoil_quality_report() {
    let t = temp();
    let mut d = open_store(&t);
    assert_eq!(
        d.store_json(&record_with("/host", json!("10.9.8.7"))).unwrap(),
        IngestOutcome::Rejected(RejectReason::Validation)
    );
    let r = d.quality_report().unwrap();
    assert!(r.is_clean(), "{}", r.text());
    assert!(r.text().contains("rejected 1"), "{}", r.text());
}
