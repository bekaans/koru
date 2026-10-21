//! IP masking (protected set; privacy law, ADR-0006 "Masking"):
//! The last octet is zeroed in IPv4 (/24); the first 48 bits are kept in IPv6 (/48); in an
//! IPv4-mapped IPv6 the last octet of the IPv4 part is zeroed. A masked event stays valid.

mod common;

use common::*;
use koru_event::Event;
use koru_store::{mask_event, mask_ip_in_text as m};
use serde_json::{Value, json};

#[test]
fn ipv4_last_octet_is_zeroed() {
    assert_eq!(m("203.0.113.77"), "203.0.113.0");
    assert_eq!(m("10.0.0.5"), "10.0.0.0");
    assert_eq!(m("127.0.0.1"), "127.0.0.0");
    assert_eq!(m("255.255.255.255"), "255.255.255.0");
    assert_eq!(m("0.0.0.0"), "0.0.0.0");
}

#[test]
fn ipv6_first_48_bits_are_kept() {
    assert_eq!(m("2001:db8:abcd:12::99"), "2001:db8:abcd::");
    assert_eq!(m("2001:0db8:0001:0002:0003:0004:0005:0006"), "2001:db8:1::");
    assert_eq!(m("fe80::1"), "fe80::");
    assert_eq!(m("::1"), "::");
    assert_eq!(m("2001:db8::"), "2001:db8::");
    assert_eq!(m("2A02:6B8:FFFF:1:2:3:4:5"), "2a02:6b8:ffff::");
}

#[test]
fn ipv4_mapped_ipv6() {
    assert_eq!(m("::ffff:192.0.2.1"), "::ffff:192.0.2.0");
}

#[test]
fn addresses_inside_text_are_masked() {
    assert_eq!(m("curl http://203.0.113.9:8080/upload.sh"), "curl http://203.0.113.0:8080/upload.sh");
    assert_eq!(m("ssh user@198.51.100.7"), "ssh user@198.51.100.0");
    assert_eq!(m("conn\u{e9}ction 10.1.2.3:443 and 10.9.8.7."), "conn\u{e9}ction 10.1.2.0:443 and 10.9.8.0.");
    assert_eq!(m("ip=192.0.2.200,port=22"), "ip=192.0.2.0,port=22");
    assert_eq!(m("[2001:db8:1:2::5]:443"), "[2001:db8:1::]:443");
    assert_eq!(m("v6=2001:db8:1:2::5 v4=192.0.2.1"), "v6=2001:db8:1:: v4=192.0.2.0");
    assert_eq!(m("10.0.0.5/24"), "10.0.0.0/24");
    assert_eq!(m("a 1.2.3.4 b 5.6.7.8 c"), "a 1.2.3.0 b 5.6.7.0 c");
    assert_eq!(m("sat1\n198.51.100.1\tsat2"), "sat1\n198.51.100.0\tsat2");
}

#[test]
fn non_address_text_is_untouched() {
    for s in [
        "",
        "hello w\u{fc}rld",
        "std::fs::File",
        "/usr/lib/python3.12/site-packages",
        "v\u{fc}rsion 1.2.3",
        "1.2.3.4.5",
        "256.1.1.1",
        "300.300.300.300",
        "deadbeef",
        "abcd:ef01",
        "12:34:56",
        "/var/log/app-2026.10.09.log",
        "x.y.z.w",
        "O_RDONLY",
        "sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8",
    ] {
        assert_eq!(m(s), s, "{s:?} is not an address; it must not change");
    }
}

#[test]
fn masking_is_idempotent_and_preserves_unicode() {
    for s in [
        "203.0.113.77",
        "2001:db8:abcd:12::99",
        "caf\u{e9}_run: 10.20.30.40 \u{2713} \u{11f}\u{fc}\u{15f}i\u{f6}\u{e7}",
    ] {
        let one = m(s);
        assert_eq!(m(&one), one, "must be idempotent: {s}");
    }
    assert_eq!(m("caf\u{e9}_run: 10.20.30.40 \u{2713}"), "caf\u{e9}_run: 10.20.30.0 \u{2713}");
}

fn masked_ips(v: &Value) -> Vec<String> {
    let mut result = Vec::new();
    fn walk(v: &Value, result: &mut Vec<String>) {
        match v {
            Value::String(s) => result.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|x| walk(x, result)),
            Value::Object(o) => o.values().for_each(|x| walk(x, result)),
            _ => {}
        }
    }
    walk(v, &mut result);
    result
}

#[test]
fn endpoints_and_texts_in_event_are_masked_and_event_stays_valid() {
    let mut v = event_json_value("network_connection", 1);
    set_field(&mut v, "/process/command_line", json!(["nc", "198.51.100.23", "9001"]));
    set_field(&mut v, "/process/exe", json!("/tmp/203.0.113.5/nc"));
    set_field(&mut v, "/process/lineage/0/command_line", json!(["ssh", "u@192.0.2.44"]));
    set_field(&mut v, "/container/name", json!("gw-198.51.100.99"));
    set_field(
        &mut v,
        "/actor",
        json!({"kind": "human", "rationale": ["conn\u{e9}ction 203.0.113.250 sourc\u{131}d"], "confidence": 0.5}),
    );
    let o: Event = serde_json::from_value(v).unwrap();
    let masked = mask_event(&o);
    masked.validate().expect("a masked event must stay valid");
    let text = serde_json::to_string(&masked).unwrap();
    let back: Event = serde_json::from_str(&text).expect("a masked event must match the schema");
    assert_eq!(back, masked);
    let remote = masked.target.remote.unwrap();
    assert_eq!(remote.ip.to_string(), "203.0.113.0");
    assert_eq!(remote.port, 443, "port is preserved");
    assert_eq!(masked.target.local.unwrap().ip.to_string(), "10.0.0.0");
    assert_eq!(masked.process.command_line.untrusted_value(), &["nc", "198.51.100.0", "9001"]);
    assert_eq!(masked.process.exe.untrusted_value(), "/tmp/203.0.113.0/nc");
    assert_eq!(masked.process.lineage[0].command_line.untrusted_value(), &["ssh", "u@192.0.2.0"]);
    assert_eq!(masked.container.name.as_ref().unwrap().untrusted_value(), "gw-198.51.100.0");
    assert_eq!(masked.actor.rationale, ["conn\u{e9}ction 203.0.113.0 sourc\u{131}d"]);
    // Everything else stays the same.
    assert_eq!(masked.event_id, o.event_id);
    assert_eq!(masked.timestamp, o.timestamp);
    assert_eq!(masked.source_tag, o.source_tag);
    assert_eq!(masked.process.pid, o.process.pid);
    assert!(masked_ips(&serde_json::to_value(&masked).unwrap()).iter().all(|s| !s.contains("198.51.100.23")));
}

#[test]
fn ipv6_endpoint_is_masked() {
    let o = event("network_connection_v6", 1);
    let masked = mask_event(&o);
    masked.validate().unwrap();
    assert_eq!(masked.target.remote.unwrap().ip.to_string(), "2001:db8:abcd::");
}

#[test]
fn host_and_sensor_not_masked() {
    let mut v = event_json_value("file_opened", 1);
    set_field(&mut v, "/host", json!("10.9.8.7"));
    set_field(&mut v, "/sensor/name", json!("sensor-10.9.8.7"));
    let o: Event = serde_json::from_value(v).unwrap();
    let masked = mask_event(&o);
    assert_eq!(masked.host, "10.9.8.7");
    assert_eq!(masked.sensor.name, "sensor-10.9.8.7");
}

#[test]
fn event_without_address_stays_same() {
    let o = event("file_opened", 1);
    assert_eq!(mask_event(&o), o);
}

#[test]
fn every_template_stays_valid_when_masked() {
    for (i, s) in ALL_TEMPLATES.iter().enumerate() {
        let masked = mask_event(&event(s, i as u32));
        masked.validate().unwrap_or_else(|e| panic!("{s}: {e}"));
    }
}
