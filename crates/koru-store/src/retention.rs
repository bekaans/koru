//! Retention and rotation (ADR-0006 "Retention and rotation").

/// Rotation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationResult {
    /// Records deleted because the retention period expired.
    pub expired: u64,
    /// Records deleted (oldest) because the record cap was exceeded.
    pub over_limit: u64,
    /// Records remaining after rotation.
    pub remaining: u64,
}

use koru_event::Timestamp;
use rusqlite::{TransactionBehavior, params};

use crate::store::sqlite;
use crate::{Store, StoreError};

const DAY_NS: i128 = 86_400 * 1_000_000_000;

impl Store {
    /// Deletes expired records, enforces the record cap, truncates the WAL, and reclaims space.
    ///
    /// - Expired: `timestamp` < `now - retention_days`; a record exactly at the boundary stays.
    /// - Cap: when the record count exceeds `max_records`, the oldest by time are deleted.
    /// - `secure_delete` is on; deleted content is zeroed in pages, then `VACUUM` rewrites the
    ///   file and the WAL is truncated: deleted personal data does not linger in the file (GDPR/KVKK).
    pub fn freeze(&mut self, now: Timestamp) -> Result<RotationResult, StoreError> {
        let cutoff = Timestamp::from_unix_nanos(now.unix_nanos() - i128::from(self.settings.retention_days) * DAY_NS)
            .map(|z| z.text())
            .ok();
        let limit = i64::try_from(self.settings.max_records).unwrap_or(i64::MAX);
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sqlite)?;
        let expired = match &cutoff {
            Some(e) => tx.execute("DELETE FROM events WHERE timestamp < ?1", params![e]).map_err(sqlite)?,
            None => 0,
        };
        let remaining: i64 = tx.query_row("SELECT count(*) FROM events", [], |r| r.get(0)).map_err(sqlite)?;
        let excess = remaining.saturating_sub(limit);
        let over_limit = if excess > 0 {
            tx.execute(
                "DELETE FROM events WHERE seq IN (
                     SELECT seq FROM events ORDER BY timestamp ASC, event_id ASC LIMIT ?1)",
                params![excess],
            )
            .map_err(sqlite)?
        } else {
            0
        };
        let last: i64 = tx.query_row("SELECT count(*) FROM events", [], |r| r.get(0)).map_err(sqlite)?;
        tx.commit().map_err(sqlite)?;
        if expired + over_limit > 0 {
            self.connection.execute_batch("VACUUM").map_err(sqlite)?;
        }
        self.connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").map_err(sqlite)?;
        Ok(RotationResult {
            expired: expired as u64,
            over_limit: over_limit as u64,
            remaining: u64::try_from(last).unwrap_or(0),
        })
    }
}
