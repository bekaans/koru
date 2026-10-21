//! JSONL and OCSF export.

use koru_event::SourceTag;

use crate::StoreError;

/// Export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// Each line is a Koru event (schema v1).
    Jsonl,
    /// Each line is an OCSF event.
    Ocsf,
}

/// Export options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOptions {
    /// Format.
    pub format: ExportFormat,
    /// Masks IPv4 and IPv6 addresses (GDPR/KVKK).
    pub mask: bool,
    /// Only events with this source tag; when `None`, a store holding more than one tag is rejected.
    pub source: Option<SourceTag>,
}

impl ExportOptions {
    /// Options without masking or filtering.
    pub fn new(format: ExportFormat) -> ExportOptions {
        ExportOptions { format, mask: false, source: None }
    }
}

/// Export result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportResult {
    /// Lines written.
    pub written: u64,
    /// Corrupt records not written because they fail the schema (the store may have been tampered with).
    pub skipped_corrupt: u64,
}

/// Export error.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// Mixed source tags; nothing was written.
    #[error("mixed source tags cannot be exported: {tags:?}")]
    MixedSources {
        /// Tags found in the store.
        tags: Vec<SourceTag>,
    },
    /// A store error.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The output could not be written.
    #[error("could not write to the output: {0}")]
    Write(String),
}

use std::io::Write;

use rusqlite::params;

use crate::Store;
use crate::mask::mask_event;
use crate::ocsf::ocsf_event;
use crate::raw::decode_record;
use crate::store::sqlite;

fn parse_source_tag(code: &str) -> Option<SourceTag> {
    match code {
        "synthetic" => Some(SourceTag::Synthetic),
        "legitimate" => Some(SourceTag::Legitimate),
        "real" => Some(SourceTag::Real),
        _ => None,
    }
}

fn source_tag_code(e: SourceTag) -> &'static str {
    match e {
        SourceTag::Synthetic => "synthetic",
        SourceTag::Legitimate => "legitimate",
        SourceTag::Real => "real",
    }
}

type InputLine = (String, String, String, String, String);

fn read_line(r: &rusqlite::Row<'_>) -> rusqlite::Result<InputLine> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

impl Store {
    /// Exports (ADR-0006 "Export"). Without a source filter, a store holding more than one source
    /// tag is rejected and nothing is written. Records failing the schema (tampered) are not
    /// written and are counted. Order: timestamp, then event id.
    pub fn export(&self, options: &ExportOptions, output: &mut dyn Write) -> Result<ExportResult, ExportError> {
        if options.source.is_none() {
            let mut s = self
                .connection
                .prepare("SELECT DISTINCT source_tag FROM events ORDER BY source_tag")
                .map_err(sqlite)?;
            let codes: Vec<String> = s
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(sqlite)?
                .collect::<Result<_, _>>()
                .map_err(sqlite)?;
            if codes.len() > 1 {
                return Err(ExportError::MixedSources {
                    tags: codes.iter().filter_map(|k| parse_source_tag(k)).collect(),
                });
            }
        }
        let mut outcome = ExportResult { written: 0, skipped_corrupt: 0 };
        let mut emit = |line: InputLine| -> Result<(), ExportError> {
            let (id, source, timestamp, kind, data) = line;
            let Ok(event) = decode_record(&id, &source, &timestamp, &kind, &data) else {
                outcome.skipped_corrupt += 1;
                return Ok(());
            };
            let event = if options.mask { mask_event(&event) } else { event };
            let text = match options.format {
                ExportFormat::Jsonl => serde_json::to_string(&event),
                ExportFormat::Ocsf => serde_json::to_string(&ocsf_event(&event)),
            }
            .map_err(|e| ExportError::Write(e.to_string()))?;
            output
                .write_all(text.as_bytes())
                .and_then(|()| output.write_all(b"\n"))
                .map_err(|e| ExportError::Write(e.to_string()))?;
            outcome.written += 1;
            Ok(())
        };
        if let Some(e) = options.source {
            let mut s = self
                .connection
                .prepare(
                    "SELECT event_id, source_tag, timestamp, event_type, data FROM events
                     WHERE source_tag = ?1 ORDER BY timestamp, event_id",
                )
                .map_err(sqlite)?;
            for line in s.query_map(params![source_tag_code(e)], read_line).map_err(sqlite)? {
                emit(line.map_err(sqlite)?)?;
            }
        } else {
            let mut s = self
                .connection
                .prepare(
                    "SELECT event_id, source_tag, timestamp, event_type, data FROM events
                     ORDER BY timestamp, event_id",
                )
                .map_err(sqlite)?;
            for line in s.query_map([], read_line).map_err(sqlite)? {
                emit(line.map_err(sqlite)?)?;
            }
        }
        Ok(outcome)
    }
}
