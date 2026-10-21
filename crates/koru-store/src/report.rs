//! The data quality report.

use crate::{RejectReason, StoreError};

/// The data quality report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityReport {
    /// Records in the store.
    pub record_count: u64,
    /// Records passing the schema and consistency checks in their export form.
    pub schema_compliant: u64,
    /// Records in the store whose key equals another record's (surplus).
    pub duplicates: u64,
    /// Records in the store without a valid source tag.
    pub untagged: u64,
    /// Total events rejected on ingest.
    pub rejected: u64,
    /// The distribution of rejections by reason (in code order, only those greater than zero).
    pub rejected_reasons: Vec<(RejectReason, u64)>,
    /// Events deduplicated on ingest.
    pub deduplicated_count: u64,
}

impl QualityReport {
    /// The schema compliance percentage (rounded down; 100 when there are no records).
    pub fn schema_compliance_percent(&self) -> u64 {
        if self.record_count == 0 {
            return 100;
        }
        let percent = u128::from(self.schema_compliant) * 100 / u128::from(self.record_count);
        u64::try_from(percent).unwrap_or(100)
    }

    /// "schema compliance 100% · duplicates 0 · untagged 0 · rejected N".
    pub fn summary_line(&self) -> String {
        format!(
            "schema compliance {}% · duplicates {} · untagged {} · rejected {}",
            self.schema_compliance_percent(),
            self.duplicates,
            self.untagged,
            self.rejected
        )
    }

    /// The detailed report (the first line is [`QualityReport::summary_line`]).
    pub fn text(&self) -> String {
        let mut m = self.summary_line();
        m.push('\n');
        m.push_str(&format!("records: {} (schema-compliant {})\n", self.record_count, self.schema_compliant));
        m.push_str(&format!("deduplicated on ingest: {}\n", self.deduplicated_count));
        if !self.rejected_reasons.is_empty() {
            m.push_str("rejected (by reason):\n");
            for (reason, count) in &self.rejected_reasons {
                m.push_str(&format!("  {}: {count}\n", reason.code()));
            }
        }
        m
    }

    /// All records in the store comply with the schema, with no duplicates or untagged records.
    pub fn is_clean(&self) -> bool {
        self.schema_compliant == self.record_count && self.duplicates == 0 && self.untagged == 0
    }
}

use std::collections::{BTreeMap, HashSet};

use koru_event::Event;

use crate::Store;
use crate::key::event_key;
use crate::raw::decode_record;
use crate::store::sqlite;

/// The text form of a serde-encoded value (the `snake_case` name for enums).
fn code<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_else(|| "?".to_string())
}

/// Sorts a distribution by descending count, then ascending name (the output is deterministic).
fn sort(distribution: BTreeMap<String, u64>) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = distribution.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

fn section(text: &mut String, title: &str, distribution: &[(String, u64)]) {
    text.push_str(title);
    text.push_str(":\n");
    if distribution.is_empty() {
        text.push_str("  (none)\n");
    }
    for (name, count) in distribution {
        text.push_str(&format!("  {name}: {count}\n"));
    }
}

/// A threat report summary: every number in the report is
/// verifiable from this output. Derived only from the given events; no external data is added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatReport {
    /// Total events.
    pub total: u64,
    /// Events carrying a detection.
    pub with_detection: u64,
    /// The first event's time (canonical text).
    pub first_time: Option<String>,
    /// The last event's time (canonical text).
    pub last_time: Option<String>,
    /// Event counts by day (ascending date).
    pub days: Vec<(String, u64)>,
    /// Distribution by source tag.
    pub references: Vec<(String, u64)>,
    /// Distribution by event kind.
    pub event_types: Vec<(String, u64)>,
    /// Distribution by detection rule.
    pub rules: Vec<(String, u64)>,
    /// Distribution by threat class.
    pub classes: Vec<(String, u64)>,
    /// Distribution by ATT&CK technique (in events carrying a detection).
    pub techniques: Vec<(String, u64)>,
    /// Distribution by actor kind.
    pub actors: Vec<(String, u64)>,
    /// The most targeted file paths (safe display; at most 10).
    pub paths: Vec<(String, u64)>,
}

impl ThreatReport {
    /// Derives the summary from a JSONL event stream. On an invalid or non-compliant line no
    /// report is produced; the error returns with the line number (none rather than a wrong
    /// number).
    pub fn read_jsonl<R: std::io::BufRead>(reader: R) -> Result<ThreatReport, String> {
        let mut events = Vec::new();
        for (i, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| e.to_string())?;
            if line.trim().is_empty() {
                continue;
            }
            let event: Event =
                serde_json::from_str(&line).map_err(|e| format!("line {}: invalid event: {e}", i + 1))?;
            event.validate().map_err(|e| format!("line {}: {e}", i + 1))?;
            events.push(event);
        }
        Ok(ThreatReport::create(events))
    }

    /// Derives the summary from the events.
    pub fn create(events: impl IntoIterator<Item = Event>) -> ThreatReport {
        let mut total = 0u64;
        let mut with_detection = 0u64;
        let mut first: Option<String> = None;
        let mut last: Option<String> = None;
        let mut days: BTreeMap<String, u64> = BTreeMap::new();
        let mut references: BTreeMap<String, u64> = BTreeMap::new();
        let mut event_types: BTreeMap<String, u64> = BTreeMap::new();
        let mut rules: BTreeMap<String, u64> = BTreeMap::new();
        let mut classes: BTreeMap<String, u64> = BTreeMap::new();
        let mut techniques: BTreeMap<String, u64> = BTreeMap::new();
        let mut actors: BTreeMap<String, u64> = BTreeMap::new();
        let mut paths: BTreeMap<String, u64> = BTreeMap::new();
        for event in events {
            total += 1;
            let timestamp = event.timestamp.text();
            if first.as_ref().is_none_or(|i| timestamp < *i) {
                first = Some(timestamp.clone());
            }
            if last.as_ref().is_none_or(|s| timestamp > *s) {
                last = Some(timestamp.clone());
            }
            *days.entry(timestamp.chars().take(10).collect()).or_default() += 1;
            *references.entry(code(&event.source_tag)).or_default() += 1;
            *event_types.entry(code(&event.event_type)).or_default() += 1;
            *actors.entry(code(&event.actor.kind)).or_default() += 1;
            if let Some(path) = &event.target.path {
                *paths.entry(path.safe_display()).or_default() += 1;
            }
            if let Some(detection) = &event.detection {
                with_detection += 1;
                *rules.entry(detection.rule.clone()).or_default() += 1;
                *classes.entry(code(&detection.threat_class)).or_default() += 1;
                for technique in &detection.attack {
                    *techniques.entry(technique.as_str().to_string()).or_default() += 1;
                }
            }
        }
        let mut path_list = sort(paths);
        path_list.truncate(10);
        ThreatReport {
            total,
            with_detection,
            first_time: first,
            last_time: last,
            days: days.into_iter().collect(),
            references: sort(references),
            event_types: sort(event_types),
            rules: sort(rules),
            classes: sort(classes),
            techniques: sort(techniques),
            actors: sort(actors),
            paths: path_list,
        }
    }

    /// The text report.
    pub fn text(&self) -> String {
        let mut m = String::new();
        m.push_str(&format!("total events: {}\n", self.total));
        m.push_str(&format!("events with detection: {}\n", self.with_detection));
        m.push_str(&format!("events without detection: {}\n", self.total - self.with_detection));
        match (&self.first_time, &self.last_time) {
            (Some(first), Some(last)) => {
                m.push_str(&format!("time range: {first} .. {last} ({} days)\n", self.days.len()));
            }
            _ => m.push_str("time range: (none)\n"),
        }
        section(&mut m, "days", &self.days);
        section(&mut m, "source tags", &self.references);
        section(&mut m, "event kinds", &self.event_types);
        section(&mut m, "detection rules", &self.rules);
        section(&mut m, "threat classes", &self.classes);
        section(&mut m, "ATT&CK techniques", &self.techniques);
        section(&mut m, "actor kinds", &self.actors);
        section(&mut m, "most targeted paths", &self.paths);
        m
    }
}

/// The first 128 bits of the key (memory saving for duplicate counting; collision odds are negligible).
fn short_key(hex: &str) -> u128 {
    u128::from_str_radix(hex.get(..32).unwrap_or(hex), 16).unwrap_or(0)
}

impl Store {
    /// The data quality report: every record is re-validated in its export form, the event key is
    /// recomputed from the content (the index is not trusted), and ingest rejections are added.
    pub fn quality_report(&self) -> Result<QualityReport, StoreError> {
        let mut report = QualityReport {
            record_count: 0,
            schema_compliant: 0,
            duplicates: 0,
            untagged: 0,
            rejected: self.rejected_total()?,
            rejected_reasons: self.rejected()?,
            deduplicated_count: self.deduplicated_count()?,
        };
        let mut seen: HashSet<u128> = HashSet::new();
        let mut s = self
            .connection
            .prepare("SELECT event_id, source_tag, timestamp, event_type, data FROM events ORDER BY seq")
            .map_err(sqlite)?;
        let lines = s
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(sqlite)?;
        for line in lines {
            let (id, source, timestamp, kind, data) = line.map_err(sqlite)?;
            report.record_count += 1;
            match decode_record(&id, &source, &timestamp, &kind, &data) {
                Ok(event) => {
                    report.schema_compliant += 1;
                    if !seen.insert(short_key(&event_key(&event))) {
                        report.duplicates += 1;
                    }
                }
                Err(RejectReason::UntaggedRecord | RejectReason::InvalidSourceTag) => report.untagged += 1,
                Err(_) => {}
            }
        }
        Ok(report)
    }
}
