//! Pulsar event -> Koru event (schema v1). The mapping rules are in ADR-0003.

use std::time::{SystemTime, UNIX_EPOCH};

use koru_event::{
    Actor, Container, EventId, EventType, FileFlag, NetworkEndpoint, NetworkProtocol, Process, SchemaVersion, Tags,
    Target, Timestamp, Untrusted, User,
};
use pulsar_core::event::{Event, Host, Payload, PayloadDiscriminant};
use pulsar_core::kernel::file::flags as f;

use crate::{KORU_MODULE_NAME, ProcessAttachment, SkipReason, Translation, TranslationContext, TranslationError};

/// Translates a Pulsar event into a Koru event.
///
/// - Events with `header.threat` present are always skipped (KT-30); this check comes first.
/// - Types with no counterpart in schema v1 are skipped.
/// - If the produced event fails [`Event::validate`], an error is returned.
pub fn translate(
    event: &Event,
    attachment: &ProcessAttachment,
    context: &TranslationContext,
) -> Result<Translation, TranslationError> {
    let h = event.header();
    if let Some(threat) = &h.threat {
        return Ok(Translation::Skipped(SkipReason::ThreatDuplicate {
            koru_originated: &*threat.source == KORU_MODULE_NAME,
        }));
    }

    let mut target = Target::default();
    let mut exe = h.image.clone();
    let mut command_line = attachment.command_line.clone().unwrap_or_default();
    let path = |s: &String| Some(Untrusted::new(s.clone()));
    let event_type = match event.payload() {
        Payload::FileOpened { filename, flags: open_flags } => {
            target.path = path(filename);
            target.flags = flags(i32::from(open_flags.clone()));
            EventType::FileOpened
        }
        Payload::FileCreated { filename } => {
            target.path = path(filename);
            EventType::FileCreated
        }
        Payload::FileDeleted { filename } => {
            target.path = path(filename);
            EventType::FileDeleted
        }
        Payload::DirCreated { dirname } => {
            target.path = path(dirname);
            EventType::DirectoryCreated
        }
        Payload::DirDeleted { dirname } => {
            target.path = path(dirname);
            EventType::DirectoryDeleted
        }
        Payload::FileRename { source, destination } => {
            target.path = path(source);
            target.new_path = path(destination);
            EventType::FileRenamed
        }
        Payload::FileLink { source, destination, hard_link } => {
            target.path = path(source);
            target.new_path = path(destination);
            target.hard_link = Some(*hard_link);
            EventType::FileLink
        }
        Payload::Exec { filename, argv, .. } => {
            // Pulsar's header carries the pre-exec binary; in the Koru event the process is the
            // post-exec one (same meaning as Sigma process_creation; ADR-0003).
            target.path = path(filename);
            exe = filename.clone();
            command_line = Vec::<String>::from(argv.clone());
            EventType::ProcessExecuted
        }
        Payload::Exit { exit_code } => {
            target.exit_code = Some(*exit_code);
            EventType::ProcessExited
        }
        Payload::Connect { destination, is_tcp } => {
            target.remote = Some(network_endpoint(destination));
            target.protocol = Some(if *is_tcp { NetworkProtocol::Tcp } else { NetworkProtocol::Udp });
            EventType::NetworkConnection
        }
        Payload::Accept { source, destination } => {
            // Pulsar: source is the connecting client (remote), destination the listening address (local).
            target.remote = Some(network_endpoint(source));
            target.local = Some(network_endpoint(destination));
            target.protocol = Some(NetworkProtocol::Tcp);
            EventType::NetworkAccept
        }
        other => {
            return Ok(Translation::Skipped(SkipReason::UnsupportedKind {
                kind: format!("{:?}", PayloadDiscriminant::from(other)),
            }));
        }
    };

    let pid = u32::try_from(h.pid)
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| invalid("header.pid", format!("must be positive: {}", h.pid)))?;
    let ppid = u32::try_from(h.parent_pid)
        .map_err(|_| invalid("header.parent_pid", format!("must not be negative: {}", h.parent_pid)))?;
    let timestamp = Timestamp::try_from(h.timestamp).map_err(|e| invalid("header.timestamp", e.to_string()))?;
    let start_time = if h.fork_time == UNIX_EPOCH { None } else { Some(system_time("header.fork_time", h.fork_time)?) };
    let non_empty = |s: &str| (!s.is_empty()).then(|| Untrusted::new(s.to_string()));
    let container = Container {
        id: h.container.as_ref().and_then(|k| non_empty(&k.id)),
        name: h.container.as_ref().and_then(|k| non_empty(&k.name)),
        image: h.container.as_ref().and_then(|k| non_empty(&k.image)),
        image_digest: h.container.as_ref().and_then(|k| non_empty(&k.image_digest)),
        namespaces: attachment.namespaces,
    };

    let event = koru_event::Event {
        schema_version: SchemaVersion::V1,
        event_id: EventId::new(),
        timestamp,
        timestamp_trusted: context.timestamp_trusted,
        source_tag: context.source_tag,
        sensor: context.sensor.clone(),
        host: context.host.clone(),
        process: Process {
            pid,
            ppid,
            start_time,
            exe: Untrusted::new(exe),
            command_line: Untrusted::new(command_line),
            environment: Untrusted::new(Vec::new()),
            user: User { uid: h.uid, gid: h.gid },
            lineage: attachment.lineage.clone(),
        },
        container,
        event_type,
        target,
        actor: Actor::unknown(),
        detection: None,
        tags: Tags::default(),
        session_id: None,
        response: None,
    };
    event.validate()?;
    Ok(Translation::Event(Box::new(event)))
}

fn invalid(field: &'static str, reason: String) -> TranslationError {
    TranslationError::InvalidField { field, reason }
}

fn system_time(field: &'static str, st: SystemTime) -> Result<Timestamp, TranslationError> {
    Timestamp::try_from(st).map_err(|e| invalid(field, e.to_string()))
}

fn network_endpoint(h: &Host) -> NetworkEndpoint {
    NetworkEndpoint { ip: h.ip, port: h.port }
}

/// Decodes `open` flags with the constants of the architecture Pulsar was built for (`pulsar_core::kernel`).
/// The access mode comes first, the rest in Pulsar's order; unknown bits (e.g. O_LARGEFILE)
/// are not emitted.
fn flags(raw: i32) -> Vec<FileFlag> {
    let mut result = Vec::new();
    let mode = raw & f::O_ACCMODE;
    if mode == f::O_RDONLY {
        result.push(FileFlag::Rdonly);
    } else if mode == f::O_WRONLY {
        result.push(FileFlag::Wronly);
    } else if mode == f::O_RDWR {
        result.push(FileFlag::Rdwr);
    }
    for (bit, flag) in [
        (f::O_CREAT, FileFlag::Creat),
        (f::O_EXCL, FileFlag::Excl),
        (f::O_NOCTTY, FileFlag::Noctty),
        (f::O_TRUNC, FileFlag::Trunc),
        (f::O_APPEND, FileFlag::Append),
        (f::O_NONBLOCK, FileFlag::Nonblock),
        (f::O_DIRECTORY, FileFlag::Directory),
    ] {
        if raw & bit != 0 {
            result.push(flag);
        }
    }
    result
}
