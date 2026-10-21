//! A UTC timestamp with nanosecond precision (schema v1 `timestamp` field).

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{Date, Month, OffsetDateTime, Time};

const NS_PER_SECOND: i128 = 1_000_000_000;

/// A UTC timestamp. In JSON it is written in a single canonical form and read only in that form:
/// `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ` (RFC 3339; every timestamp has a 9-digit fraction and `Z`). A
/// single form prevents the same instant from being written as two different texts
/// (deduplication).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

/// When a timestamp cannot be parsed or is out of range.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimestampError {
    /// The text is not in canonical form.
    #[error("invalid timestamp format (expected YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ): {0:?}")]
    Format(String),
    /// The format is right but the date or time is invalid (e.g. month 13).
    #[error("timestamp contains an invalid date or time: {0:?}")]
    Value(String),
    /// Outside the years 0000-9999.
    #[error("timestamp outside the years 0000-9999")]
    Range,
}

impl Timestamp {
    /// The current timestamp (UTC).
    pub fn now() -> Timestamp {
        Timestamp(OffsetDateTime::now_utc())
    }

    /// Nanoseconds since the Unix epoch.
    pub fn unix_nanos(&self) -> i128 {
        self.0.unix_timestamp_nanos()
    }

    /// From nanoseconds since the Unix epoch; outside 0000-9999 is rejected.
    pub fn from_unix_nanos(ns: i128) -> Result<Timestamp, TimestampError> {
        let z = OffsetDateTime::from_unix_timestamp_nanos(ns).map_err(|_| TimestampError::Range)?;
        if (0..=9999).contains(&z.year()) { Ok(Timestamp(z)) } else { Err(TimestampError::Range) }
    }

    /// Reads from the canonical text.
    pub fn parse(text: &str) -> Result<Timestamp, TimestampError> {
        let b = text.as_bytes();
        let format_error = || TimestampError::Format(text.chars().take(64).collect());
        let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':'), (19, b'.'), (29, b'Z')];
        if b.len() != 30 || separators.iter().any(|&(i, c)| b[i] != c) {
            return Err(format_error());
        }
        let number = |start: usize, end: usize| -> Result<u32, TimestampError> {
            let piece = &b[start..end];
            if !piece.iter().all(u8::is_ascii_digit) {
                return Err(format_error());
            }
            Ok(piece.iter().fold(0u32, |t, r| t * 10 + u32::from(r - b'0')))
        };
        let year = number(0, 4)?;
        let month_num = number(5, 7)?;
        let day = number(8, 10)?;
        let hour = number(11, 13)?;
        let minute = number(14, 16)?;
        let second = number(17, 19)?;
        let nanosecond = number(20, 29)?;
        let value_error = |_| TimestampError::Value(text.to_string());
        let month_num = Month::try_from(u8::try_from(month_num).map_err(|_| TimestampError::Value(text.to_string()))?)
            .map_err(value_error)?;
        let date = Date::from_calendar_date(year as i32, month_num, day as u8).map_err(value_error)?;
        let hour = Time::from_hms_nano(hour as u8, minute as u8, second as u8, nanosecond).map_err(value_error)?;
        Ok(Timestamp(date.with_time(hour).assume_utc()))
    }

    /// The canonical text.
    pub fn text(&self) -> String {
        let z = self.0;
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            z.year(),
            u8::from(z.month()),
            z.day(),
            z.hour(),
            z.minute(),
            z.second(),
            z.nanosecond()
        )
    }
}

impl TryFrom<SystemTime> for Timestamp {
    type Error = TimestampError;

    fn try_from(st: SystemTime) -> Result<Timestamp, TimestampError> {
        let ns = match st.duration_since(UNIX_EPOCH) {
            Ok(d) => i128::try_from(d.as_nanos()).map_err(|_| TimestampError::Range)?,
            Err(e) => -i128::try_from(e.duration().as_nanos()).map_err(|_| TimestampError::Range)?,
        };
        Timestamp::from_unix_nanos(ns)
    }
}

impl From<Timestamp> for SystemTime {
    fn from(z: Timestamp) -> SystemTime {
        let ns = z.unix_nanos();
        let absolute = ns.unsigned_abs();
        // The number of seconds in the 0000-9999 range fits in a u64.
        let dur = Duration::new((absolute / NS_PER_SECOND as u128) as u64, (absolute % NS_PER_SECOND as u128) as u32);
        if ns >= 0 { UNIX_EPOCH + dur } else { UNIX_EPOCH - dur }
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({})", self.text())
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.text())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Timestamp, D::Error> {
        let text = String::deserialize(d)?;
        Timestamp::parse(&text).map_err(D::Error::custom)
    }
}
