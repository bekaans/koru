//! Event masking (privacy: GDPR/KVKK; ADR-0006 "Masking"). Text and address masking lives in
//! koru-event (`koru_event::mask_ip_in_text`, `koru_event::mask_ip`; ADR-0007 §8) and is
//! re-exported from here under the same name; behavior is unchanged. Only [`mask_event`], which
//! walks the event's fields, lives here.

pub use koru_event::mask_ip_in_text;
use koru_event::{AncestorProcess, Container, Event, NetworkEndpoint, Untrusted, mask_ip};

fn text(g: &Untrusted<String>) -> Untrusted<String> {
    Untrusted::new(mask_ip_in_text(g.untrusted_value()))
}

fn mask_list(g: &Untrusted<Vec<String>>) -> Untrusted<Vec<String>> {
    Untrusted::new(g.untrusted_value().iter().map(|s| mask_ip_in_text(s)).collect())
}

fn uc(u: NetworkEndpoint) -> NetworkEndpoint {
    NetworkEndpoint { ip: mask_ip(u.ip), port: u.port }
}

fn container(k: &Container) -> Container {
    Container {
        id: k.id.as_ref().map(text),
        name: k.name.as_ref().map(text),
        image: k.image.as_ref().map(text),
        image_digest: k.image_digest.as_ref().map(text),
        namespaces: k.namespaces,
    }
}

/// Masks all network endpoints in the event and the addresses in free-text fields; the event
/// stays valid. `host` and sensor information are not masked (ADR-0006 §7).
pub fn mask_event(event: &Event) -> Event {
    let mut o = event.clone();
    o.process.exe = text(&o.process.exe);
    o.process.command_line = mask_list(&o.process.command_line);
    o.process.environment = mask_list(&o.process.environment);
    o.process.lineage = o
        .process
        .lineage
        .iter()
        .map(|a| AncestorProcess { pid: a.pid, exe: text(&a.exe), command_line: mask_list(&a.command_line) })
        .collect();
    o.container = container(&o.container);
    o.target.path = o.target.path.as_ref().map(text);
    o.target.new_path = o.target.new_path.as_ref().map(text);
    o.target.local = o.target.local.map(uc);
    o.target.remote = o.target.remote.map(uc);
    if let Some(t) = &mut o.detection {
        t.rule = mask_ip_in_text(&t.rule);
        t.decoy_id = t.decoy_id.as_deref().map(mask_ip_in_text);
    }
    o.actor.rationale = o.actor.rationale.iter().map(|g| mask_ip_in_text(g)).collect();
    if let Some(n) = &o.tags.intent {
        o.tags.intent = Some(mask_ip_in_text(n));
    }
    if let Some(s) = &o.session_id {
        o.session_id = Some(mask_ip_in_text(s));
    }
    if let Some(y) = &mut o.response {
        y.rationale = mask_ip_in_text(&y.rationale);
    }
    o
}
