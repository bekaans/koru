//! IP masking: adjacent and embedded addresses (a security-review finding, MEDIUM; test-first
//! commit; protected set). `masking.rs` is locked and does not change; this file only
//! adds to it.
//!
//! Contract (ADR-0006 §7): the text is scanned with a linear scanner for ASCII and non-ASCII
//! bytes. Every possible IPv4 (4 octets, 1-3 digits, octet ≤ 255, leading zeros allowed; no digit
//! or further dotted-number part at either boundary) and every IPv6 (the longest valid match, no
//! letter/digit/underscore adjacent) is found; in IPv4 the last octet becomes `0` and the first
//! three octets stay as written (including leading zeros; octets are not normalized), and in IPv6
//! the first 48 bits are kept. Clock, version, MAC, and date strings are not addresses.

mod common;

use std::time::{Duration, Instant};

use common::*;
use koru_event::Event;
use koru_store::{ExportFormat, ExportOptions, mask_event, mask_ip_in_text as m, ocsf_event};
use serde_json::json;

#[test]
fn four_adjacent_forms() {
    assert_eq!(m("ssh -L 8080:10.0.0.5:22 x"), "ssh -L 8080:10.0.0.0:22 x");
    assert_eq!(m("curl --resolve sample.com:443:203.0.113.9"), "curl --resolve sample.com:443:203.0.113.0");
    assert_eq!(m("src:192.0.2.7"), "src:192.0.2.0");
    assert_eq!(m("from:2001:db8:1:2::5"), "from:2001:db8:1::");
}

#[test]
fn side_by_side_and_multiple_addresses() {
    assert_eq!(m("10.0.0.5:22->203.0.113.9:443"), "10.0.0.0:22->203.0.113.0:443");
    assert_eq!(m("a=10.1.1.1;b=10.2.2.2|c=10.3.3.3"), "a=10.1.1.0;b=10.2.2.0|c=10.3.3.0");
    assert_eq!(m("(2001:db8::1) and (192.0.2.55)"), "(2001:db8::) and (192.0.2.0)");
    assert_eq!(m("addr=fe80::1%eth0 gw=192.0.2.1"), "addr=fe80::%eth0 gw=192.0.2.0");
    assert_eq!(m("x:y:2001:db8:1:2::5"), "x:y:2001:db8:1::");
    assert_eq!(
        m("LOG[2026-10-09] src:192.0.2.7, dst:198.51.100.8."),
        "LOG[2026-10-09] src:192.0.2.0, dst:198.51.100.0."
    );
}

#[test]
fn ipv6_contract_edges_and_trailing_colons() {
    assert_eq!(m("2001:db8:1:2::5:"), "2001:db8:1:::");
    assert_eq!(m("2001:db8:1:2::5."), "2001:db8:1::.");
    assert_eq!(m("::ffff:192.0.2.1 and ::1"), "::ffff:192.0.2.0 and ::");
    assert_eq!(m("64:ff9b::192.0.2.33"), "64:ff9b::");
}

#[test]
fn ipv4_with_leading_zeros() {
    assert_eq!(m("010.000.000.001"), "010.000.000.0");
    assert_eq!(m("ip 192.168.001.010 x"), "ip 192.168.001.0 x");
    assert_eq!(m("src:001.002.003.004"), "src:001.002.003.0");
    assert_eq!(m(&m("010.000.000.001")), "010.000.000.0", "idempotent");
}

#[test]
fn invalid_ipv4_unchanged() {
    for s in [
        "0001.2.3.4",
        "1.2.3.4.5",
        "256.1.1.1",
        "1.2.3.256",
        "1.2.3",
        "1..2.3",
        "1.2.3.",
        ".1.2.3.4.5",
        "10.0.0",
        "1.2.3.4567",
    ] {
        assert_eq!(m(s), s, "{s:?} is not an address");
    }
}

#[test]
fn clock_version_mac_and_date_are_not_addresses() {
    for s in [
        "time 12:30:45",
        "12:30:45.123",
        "v\u{e9}rsion v1.2.3 and 10.15.7",
        "00:1a:2b:3c:4d:5e",
        "00-1a-2b-3c-4d-5e",
        "aa:bb:cc:dd:ee:ff",
        "2026-10-15T08:15:40.540189619Z",
        "2026.10.15",
        "build 2026.10.15.1234",
        "ratio 1:2:3",
        "std::fs::File and core::result::Result",
        "file-1.2.3-rc1.tar.gz",
        "sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8",
        "deadbeef:cafe",
    ] {
        assert_eq!(m(s), s, "{s:?} is not an address; it must not change");
    }
}

#[test]
fn eui64_looks_like_ipv6_and_is_masked() {
    // Eight hex groups = a valid IPv6 text; indistinguishable from an EUI-64 MAC. Decision
    // (ADR-0006 §7): a 48-bit MAC (6 groups) is not masked; the 8-group form counts as IPv6 and
    // is masked (conservative).
    assert_eq!(m("00:1a:2b:ff:fe:3c:4d:5e"), "0:1a:2b::");
}

#[test]
fn ipv6_start_glued_to_word_is_no_false_positive() {
    for s in ["abc::1x", "xdead::beef", "src_a::1", "Result::Ok", "ab1::cd2g"] {
        assert_eq!(m(s), s, "{s:?}");
    }
}

#[test]
fn non_ascii_and_mixed_text() {
    assert_eq!(
        m("caf\u{e9}_run\u{2192}src:192.0.2.7\u{2713} and 10.1.2.3:22"),
        "caf\u{e9}_run\u{2192}src:192.0.2.0\u{2713} and 10.1.2.0:22"
    );
    assert_eq!(m("Z\u{fc}rich 2001:db8::1 Paris"), "Z\u{fc}rich 2001:db8:: Paris");
}

#[test]
fn pathological_inputs_processed_in_linear_time() {
    let limit = Duration::from_secs(10);
    let entries = [
        "a:".repeat(500_000),
        ":".repeat(1_000_000),
        "1.".repeat(500_000),
        "1:".repeat(500_000),
        "ff:".repeat(300_000),
        "255.".repeat(250_000),
        "::1".repeat(300_000),
    ];
    for g in &entries {
        let start = Instant::now();
        let _ = m(g);
        assert!(
            start.elapsed() < limit,
            "the input ({} bytes) must be processed within {limit:?}: {:?}",
            g.len(),
            start.elapsed()
        );
    }
}

fn event_json(mutate: impl FnOnce(&mut serde_json::Value)) -> Event {
    let mut v = event_json_value("file_opened", 1);
    mutate(&mut v);
    let o: Event = serde_json::from_value(v).unwrap();
    o.validate().unwrap();
    o
}

#[test]
fn embedded_addresses_in_event_free_text_fields() {
    let o = event_json(|v| {
        set_field(v, "/process/command_line", json!(["ssh", "-L", "8080:10.0.0.5:22", "x"]));
        set_field(v, "/target/path", json!("/srv/curl --resolve sample.com:443:203.0.113.9"));
        set_field(
            v,
            "/actor",
            json!({"kind": "human", "rationale": ["src:192.0.2.7", "from:2001:db8:1:2::5"], "confidence": 0.5}),
        );
        set_field(v, "/tags/intent", json!("discovery src:198.51.100.4"));
        set_field(v, "/session_id", json!("session:203.0.113.77"));
    });
    let k = mask_event(&o);
    k.validate().expect("a masked event stays valid");
    assert_eq!(k.process.command_line.untrusted_value(), &["ssh", "-L", "8080:10.0.0.0:22", "x"]);
    assert_eq!(k.target.path.as_ref().unwrap().untrusted_value(), "/srv/curl --resolve sample.com:443:203.0.113.0");
    assert_eq!(k.actor.rationale, ["src:192.0.2.0", "from:2001:db8:1::"]);
    assert_eq!(k.tags.intent.as_deref(), Some("discovery src:198.51.100.0"));
    assert_eq!(k.session_id.as_deref(), Some("session:203.0.113.0"));
}

#[test]
fn detection_rule_and_decoy_id_masked_including_ocsf_header_and_message() {
    let o = event_json(|v| {
        set_field(
            v,
            "/detection",
            json!({
                "rule": "koru.test.source:198.51.100.9",
                "decoy_id": "decoy-203.0.113.9",
                "threat_class": "decoy_access",
                "attack": ["T1552.004"]
            }),
        );
        set_field(v, "/tags/mitre_techniques", json!(["T1552.004"]));
    });
    let k = mask_event(&o);
    let t = k.detection.as_ref().unwrap();
    assert_eq!(t.rule, "koru.test.source:198.51.100.0");
    assert_eq!(t.decoy_id.as_deref(), Some("decoy-203.0.113.0"));
    let ocsf = ocsf_event(&k);
    assert_eq!(ocsf["finding_info"]["title"], "koru.test.source:198.51.100.0");
    assert_eq!(ocsf["finding_info"]["analytic"]["name"], "koru.test.source:198.51.100.0");
    assert!(ocsf["message"].as_str().unwrap().contains("198.51.100.0"));
    let text = ocsf.to_string();
    assert!(!text.contains("198.51.100.9") && !text.contains("203.0.113.9"), "{text}");
}

#[test]
fn adjacent_addresses_masked_in_export() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let mut v = event_json_value("process_executed", 1);
    set_field(
        &mut v,
        "/process/command_line",
        json!([
            "ssh",
            "-L",
            "8080:10.0.0.5:22",
            "x",
            "--resolve",
            "sample.com:443:203.0.113.9",
            "src:192.0.2.7",
            "from:2001:db8:1:2::5"
        ]),
    );
    set_field(&mut v, "/target/path", json!("/usr/bin/ssh"));
    store_inst.store_json(&v.to_string()).unwrap();
    for format in [ExportFormat::Jsonl, ExportFormat::Ocsf] {
        let mut sec = ExportOptions::new(format);
        sec.mask = true;
        let mut output = Vec::new();
        store_inst.export(&sec, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        for raw in ["10.0.0.5", "203.0.113.9", "192.0.2.7", "2001:db8:1:2::5"] {
            assert!(!text.contains(raw), "{format:?}: {raw} must be masked:\n{text}");
        }
        for masked in ["10.0.0.0:22", "203.0.113.0", "src:192.0.2.0", "from:2001:db8:1::"] {
            assert!(text.contains(masked), "{format:?}: {masked} must appear:\n{text}");
        }
    }
}
