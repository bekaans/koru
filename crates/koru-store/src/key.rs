//! The event key (deduplication; ADR-0006 "Event key").
//!
//! The key is the SHA-256 digest of the fields that define the event's observed fact. `event_id`
//! (UUIDv7) is excluded because it changes on every production; enrichment and estimate fields
//! (command line, lineage, actor, tags, sensor version) are excluded because they may differ on
//! redelivery.
//!
//! Encoding (an independent implementation is in `tests/dedup.rs`):
//! - Field: `None` -> `0x00`; `Some(m)` -> `0x01`, the byte length of `m` (u32, big-endian), `m`.
//! - List: the item count (u32, big-endian), then each item as `Some`.
//! - Network endpoint: `None` -> `0x00`; `Some` -> `0x01`, the `ip` field, the `port` field.
//! - Order: label, schema_version, source_tag, host, timestamp, event_type, process.pid,
//!   process.start_time, target.path, target.new_path, target.flags (sorted as text),
//!   target.hard_link, target.protocol, target.local, target.remote, target.exit_code,
//!   detection.rule, detection.decoy_id.

use koru_event::{Event, NetworkEndpoint, NetworkProtocol, SourceTag};
use sha2::{Digest, Sha256};

const LABEL: &str = "koru-event-key-v1";

fn field(b: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => b.push(0),
        Some(m) => {
            b.push(1);
            // The event size is bounded by MAX_EVENT_BYTES; it fits in a u32.
            b.extend_from_slice(&u32::try_from(m.len()).unwrap_or(u32::MAX).to_be_bytes());
            b.extend_from_slice(m.as_bytes());
        }
    }
}

fn uc(b: &mut Vec<u8>, ag: Option<&NetworkEndpoint>) {
    match ag {
        None => b.push(0),
        Some(u) => {
            b.push(1);
            field(b, Some(&u.ip.to_string()));
            field(b, Some(&u.port.to_string()));
        }
    }
}

fn source_name(k: SourceTag) -> &'static str {
    match k {
        SourceTag::Synthetic => "synthetic",
        SourceTag::Legitimate => "legitimate",
        SourceTag::Real => "real",
    }
}

fn protocol_name(p: NetworkProtocol) -> &'static str {
    match p {
        NetworkProtocol::Tcp => "tcp",
        NetworkProtocol::Udp => "udp",
    }
}

/// The event key: SHA-256, 64 lowercase hex digits. The fields are in ADR-0006.
pub fn event_key(event: &Event) -> String {
    let mut b = Vec::with_capacity(256);
    field(&mut b, Some(LABEL));
    field(&mut b, Some(&u32::from(event.schema_version).to_string()));
    field(&mut b, Some(source_name(event.source_tag)));
    field(&mut b, Some(&event.host));
    field(&mut b, Some(&event.timestamp.text()));
    field(&mut b, Some(&event.event_type.to_string()));
    field(&mut b, Some(&event.process.pid.to_string()));
    field(&mut b, event.process.start_time.map(|z| z.text()).as_deref());
    let h = &event.target;
    field(&mut b, h.path.as_ref().map(|y| y.untrusted_value().as_str()));
    field(&mut b, h.new_path.as_ref().map(|y| y.untrusted_value().as_str()));
    let mut flags: Vec<String> = h
        .flags
        .iter()
        .map(|f| serde_json::to_value(f).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default())
        .collect();
    flags.sort();
    b.extend_from_slice(&u32::try_from(flags.len()).unwrap_or(u32::MAX).to_be_bytes());
    for f in &flags {
        field(&mut b, Some(f));
    }
    field(&mut b, h.hard_link.map(|s| if s { "true" } else { "false" }));
    field(&mut b, h.protocol.map(protocol_name));
    uc(&mut b, h.local.as_ref());
    uc(&mut b, h.remote.as_ref());
    field(&mut b, h.exit_code.map(|k| k.to_string()).as_deref());
    field(&mut b, event.detection.as_ref().map(|t| t.rule.as_str()));
    field(&mut b, event.detection.as_ref().and_then(|t| t.decoy_id.as_deref()));
    Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect()
}
