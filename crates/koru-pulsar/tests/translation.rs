//! koru-pulsar translation tests (protected set).
//!
//! Recorded real Pulsar events (`tests/data/pulsar/`, source: `tests/data/README.md`) are
//! translated into Koru events and compared with the expected outputs (`tests/data/expected/`).
//! Also: Koru's own THREAT events are not processed (KT-30), the source tag comes from the install
//! context not from event input, and the container and namespace mapping (KT-20).
//!
//! Pulsar compiles only on Linux (ADR-0003); these tests run on Linux (lab VM and CI).
#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;

use koru_event::{AncestorProcess, Event as KoruEvent, EventType, Namespaces, SensorInfo, SourceTag, Untrusted};
use koru_pulsar::{KORU_MODULE_NAME, ProcessAttachment, SkipReason, Translation, TranslationContext, translate};
use pulsar_core::event::Event;
use serde_json::Value;

const TRANSLATED_SAMPLES: [&str; 15] = [
    "network-connection-tcp",
    "network-connection-udp",
    "network-accepted",
    "directory-created",
    "directory-deleted",
    "file-opened-read",
    "file-opened-write",
    "file-link-symlink",
    "file-link-hard",
    "file-created",
    "file-deleted",
    "file-renamed",
    "container-file-opened",
    "process-executed",
    "process-exited",
];

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn pulsar_event(name: &str) -> Event {
    let path = data_dir().join("pulsar").join(format!("{name}.json"));
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: the Pulsar event could not be parsed: {e}"))
}

fn expected(name: &str) -> Value {
    let path = data_dir().join("expected").join(format!("{name}.json"));
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

fn context(source_tag: SourceTag) -> TranslationContext {
    TranslationContext {
        source_tag,
        host: "koru-lab".to_string(),
        timestamp_trusted: true,
        sensor: SensorInfo {
            name: "pulsar".to_string(),
            version: "0.10.1".to_string(),
            platform: "linux-aarch64".to_string(),
        },
    }
}

fn host_ns() -> Namespaces {
    Namespaces {
        uts: 4026531838,
        ipc: 4026531839,
        mnt: 4026531841,
        pid: 4026531836,
        net: 4026531840,
        time: 4026531834,
        cgroup: 4026531835,
    }
}

fn container_ns() -> Namespaces {
    Namespaces {
        uts: 4026532417,
        ipc: 4026532419,
        mnt: 4026532418,
        pid: 4026532421,
        net: 4026532346,
        time: 4026531834,
        cgroup: 4026532422,
    }
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn attachment(ns: Namespaces) -> ProcessAttachment {
    ProcessAttachment {
        command_line: Some(strings(&["sh", "-c", "sample command"])),
        namespaces: Some(ns),
        lineage: vec![
            AncestorProcess {
                pid: 5390,
                exe: Untrusted::new("/usr/bin/bash".to_string()),
                command_line: Untrusted::new(strings(&[
                    "bash",
                    "/koru/lab/scripts/pulsar-collect-samples.sh",
                    "/tmp/koru-samples.jsonl",
                ])),
            },
            AncestorProcess {
                pid: 1,
                exe: Untrusted::new("/usr/lib/systemd/systemd".to_string()),
                command_line: Untrusted::new(strings(&["/sbin/init"])),
            },
        ],
    }
}

fn sample_attachment(name: &str) -> ProcessAttachment {
    if name.starts_with("container") { attachment(container_ns()) } else { attachment(host_ns()) }
}

fn to_event(name: &str, attachment: &ProcessAttachment, b: &TranslationContext) -> KoruEvent {
    match translate(&pulsar_event(name), attachment, b) {
        Ok(Translation::Event(event)) => *event,
        Ok(Translation::Skipped(reason)) => panic!("{name}: skipped where a translation was expected: {reason:?}"),
        Err(e) => panic!("{name}: translation error: {e}"),
    }
}

fn without_id(event: &KoruEvent) -> (Value, String) {
    let mut value = serde_json::to_value(event).unwrap();
    let id = value.as_object_mut().unwrap().remove("event_id").expect("event_id is present");
    (value, id.as_str().unwrap().to_string())
}

#[test]
fn recorded_samples_translate_to_the_expected_koru_events() {
    let b = context(SourceTag::Synthetic);
    for name in TRANSLATED_SAMPLES {
        let event = to_event(name, &sample_attachment(name), &b);
        event.validate().unwrap_or_else(|e| panic!("{name}: the translated event failed validation: {e}"));
        let (value, id) = without_id(&event);
        assert_eq!(&id[14..15], "7", "{name}: event_id must be UUIDv7: {id}");
        assert_eq!(value, expected(name), "{name}: must match the expected Koru event");
    }
}

#[test]
fn a_new_event_id_for_every_translation() {
    let b = context(SourceTag::Synthetic);
    let attachment = sample_attachment("file-opened-read");
    let a = to_event("file-opened-read", &attachment, &b);
    let c = to_event("file-opened-read", &attachment, &b);
    assert_ne!(a.event_id, c.event_id);
}

#[test]
fn the_translated_event_reads_back_with_the_koru_schema() {
    let b = context(SourceTag::Synthetic);
    for name in TRANSLATED_SAMPLES {
        let event = to_event(name, &sample_attachment(name), &b);
        let text = serde_json::to_string(&event).unwrap();
        let back: KoruEvent =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: could not be read back: {e}"));
        back.validate().unwrap();
        assert_eq!(back, event, "{name}");
    }
}

#[test]
fn threat_duplicates_are_not_processed_kt30() {
    // Pulsar's rule engine THREAT: the original event is also on the bus; the copy is not translated.
    let b = context(SourceTag::Synthetic);
    let attachment = sample_attachment("threat-rules-engine");
    match translate(&pulsar_event("threat-rules-engine"), &attachment, &b).unwrap() {
        Translation::Skipped(SkipReason::ThreatDuplicate { koru_originated }) => assert!(!koru_originated),
        other => panic!("the rules-engine THREAT should have been skipped: {other:?}"),
    }
    // Koru's own THREAT: re-processing it would form a bus feedback loop (ADR-0001 consequence 4).
    let koru = pulsar_event("derived-threat-koru-originated");
    assert_eq!(koru.header().threat.as_ref().map(|t| t.source.to_string()), Some(KORU_MODULE_NAME.to_string()));
    match translate(&koru, &attachment, &b).unwrap() {
        Translation::Skipped(SkipReason::ThreatDuplicate { koru_originated }) => assert!(koru_originated),
        other => panic!("the Koru-originated THREAT should have been skipped: {other:?}"),
    }
}

#[test]
fn an_unsupported_type_is_skipped() {
    let b = context(SourceTag::Synthetic);
    match translate(&pulsar_event("unsupported-dns-query"), &sample_attachment("x"), &b).unwrap() {
        Translation::Skipped(SkipReason::UnsupportedKind { kind }) => assert_eq!(kind, "DnsQuery"),
        other => panic!("DnsQuery should have been skipped: {other:?}"),
    }
}

#[test]
fn the_source_tag_and_time_flag_come_from_the_context() {
    for tag in [SourceTag::Synthetic, SourceTag::Legitimate, SourceTag::Real] {
        let mut b = context(tag);
        b.timestamp_trusted = false;
        let event = to_event("file-opened-read", &sample_attachment("x"), &b);
        assert_eq!(event.source_tag, tag);
        assert!(!event.timestamp_trusted);
        assert_eq!(event.host, "koru-lab");
    }
}

#[test]
fn the_container_id_and_namespaces_map_kt20() {
    let b = context(SourceTag::Synthetic);
    let event = to_event("container-file-opened", &sample_attachment("container-file-opened"), &b);
    let k = &event.container;
    assert_eq!(
        k.id.as_ref().map(|v| v.untrusted_value().as_str()),
        Some("ac723a96d4435aa4f5e400cafd7a9152b565e49c810a74f0b6485e2cef06506f")
    );
    assert_eq!(k.image.as_ref().map(|v| v.untrusted_value().as_str()), Some("docker.io/library/alpine:3.22"));
    assert_eq!(k.namespaces, Some(container_ns()));
    let host_event = to_event("file-opened-read", &sample_attachment("x"), &b);
    assert!(host_event.container.id.is_none());
    assert_eq!(host_event.container.namespaces, Some(host_ns()));
}

#[test]
fn translates_with_an_empty_process_attachment() {
    let b = context(SourceTag::Synthetic);
    let empty = ProcessAttachment::default();
    let event = to_event("file-opened-read", &empty, &b);
    assert!(event.process.command_line.untrusted_value().is_empty());
    assert!(event.process.lineage.is_empty());
    assert!(event.container.namespaces.is_none());
    event.validate().unwrap();
    // In an Exec event the command line comes from the event's own argv, not from the attachment.
    let exec = to_event("process-executed", &empty, &b);
    assert_eq!(exec.process.command_line.untrusted_value(), &strings(&["cat", "/tmp/koru-sample/decoy.txt"]));
}

#[test]
fn in_an_exec_event_the_process_is_the_new_binary() {
    let b = context(SourceTag::Synthetic);
    let raw = pulsar_event("process-executed");
    assert_eq!(raw.header().image, "/usr/bin/setpriv", "in the record the header shows the pre-exec binary");
    let event = to_event("process-executed", &sample_attachment("x"), &b);
    assert_eq!(event.event_type, EventType::ProcessExecuted);
    assert_eq!(event.process.exe.untrusted_value(), "/usr/bin/cat");
    assert_eq!(event.target.path.as_ref().map(|y| y.untrusted_value().as_str()), Some("/usr/bin/cat"));
}

#[test]
fn attacker_controlled_fields_have_the_untrusted_type() {
    let b = context(SourceTag::Synthetic);
    let event = to_event("file-renamed", &sample_attachment("x"), &b);
    let _: &Untrusted<String> = &event.process.exe;
    let _: &Untrusted<Vec<String>> = &event.process.command_line;
    let _: &Option<Untrusted<String>> = &event.target.path;
    let _: &Option<Untrusted<String>> = &event.target.new_path;
    assert_eq!(
        event.target.new_path.as_ref().map(|y| y.untrusted_value().as_str()),
        Some("/tmp/koru-sample/decoy2.txt")
    );
}

#[test]
fn a_pulsar_event_with_an_invalid_field_errors() {
    let b = context(SourceTag::Synthetic);
    assert!(translate(&pulsar_event("derived-invalid-pid"), &sample_attachment("x"), &b).is_err());
}
