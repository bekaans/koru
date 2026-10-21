//! Per-channel rate limiting (token bucket) and flood summarization.

use koru_event::{EventId, Notification, Severity};

use crate::NotifyError;

/// Rate limit settings (configurable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateSettings {
    /// The bucket capacity (the most notifications sendable in a burst).
    pub capacity: u32,
    /// The refill time of one token (ms).
    pub refill_ms: u64,
    /// The summary window for suppressed notifications (ms): "N more in the last 60 s".
    pub summary_window_ms: u64,
}

impl RateSettings {
    /// Defaults: capacity 5, 12 s per token (5 per minute), a 60 s summary window.
    pub const DEFAULT: RateSettings = RateSettings { capacity: 5, refill_ms: 12_000, summary_window_ms: 60_000 };

    /// Rejects zero values.
    pub fn new(capacity: u32, refill_ms: u64, summary_window_ms: u64) -> Result<RateSettings, NotifyError> {
        if capacity == 0 || refill_ms == 0 || summary_window_ms == 0 {
            return Err(NotifyError::Settings("rate limit values must be greater than zero".to_string()));
        }
        Ok(RateSettings { capacity, refill_ms, summary_window_ms })
    }

    /// Whether the values are valid (no zeros).
    pub fn is_valid(&self) -> bool {
        self.capacity != 0 && self.refill_ms != 0 && self.summary_window_ms != 0
    }
}

impl Default for RateSettings {
    fn default() -> RateSettings {
        RateSettings::DEFAULT
    }
}

/// Token bucket. Time is given from outside (ms); tests never depend on the wall clock. When
/// time goes backwards (a clock change), no token is added or removed.
///
/// Credit is kept in milliseconds: each token costs `refill_ms` of credit, and credit
/// grows and is bounded by `capacity * refill_ms`. So a partial refill is never lost.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    settings: RateSettings,
    credit: u128,
    last_ms: u64,
}

impl TokenBucket {
    /// Starts with a full bucket.
    pub fn new(settings: &RateSettings, now_ms: u64) -> TokenBucket {
        let max = u128::from(settings.capacity) * u128::from(settings.refill_ms);
        TokenBucket { settings: *settings, credit: max, last_ms: now_ms }
    }

    fn update_record(&mut self, now_ms: u64) {
        if now_ms > self.last_ms {
            let max = u128::from(self.settings.capacity) * u128::from(self.settings.refill_ms);
            self.credit = (self.credit + u128::from(now_ms - self.last_ms)).min(max);
            self.last_ms = now_ms;
        }
    }

    /// Tries to spend one token.
    pub fn try_take(&mut self, now_ms: u64) -> bool {
        self.update_record(now_ms);
        let cost = u128::from(self.settings.refill_ms);
        if self.credit >= cost {
            self.credit -= cost;
            true
        } else {
            false
        }
    }

    /// The whole tokens spendable right now.
    pub fn token(&mut self, now_ms: u64) -> u32 {
        self.update_record(now_ms);
        u32::try_from(self.credit / u128::from(self.settings.refill_ms)).unwrap_or(u32::MAX)
    }
}

/// Counts suppressed notifications and, when the window fills, emits one summary.
#[derive(Debug, Clone)]
pub struct Summarizer {
    window_ms: u64,
    count: u64,
    first_ms: Option<u64>,
    last_event: Option<EventId>,
    highest: Severity,
}

impl Summarizer {
    /// `window_ms`: the summary delay measured from the first suppression.
    pub fn new(window_ms: u64) -> Summarizer {
        Summarizer { window_ms, count: 0, first_ms: None, last_event: None, highest: Severity::Info }
    }

    /// A notification was not sent because of the rate limit. Only counted; content not kept.
    pub fn suppressed(&mut self, notification: &Notification, now_ms: u64) {
        if self.count == 0 {
            self.first_ms = Some(now_ms);
            self.highest = notification.severity;
        } else {
            self.highest = self.highest.max(notification.severity);
        }
        self.count = self.count.saturating_add(1);
        self.last_event = Some(notification.event_id);
    }

    /// The notifications pending into the summary.
    pub fn pending(&self) -> u64 {
        self.count
    }

    /// Whether the summary should be sent (at least one suppression and the window filled).
    pub fn is_ready(&self, now_ms: u64) -> bool {
        self.first_ms.is_some_and(|first| now_ms >= first.saturating_add(self.window_ms))
    }

    /// Builds the summary and resets the counter (does not check the window; the caller checks
    /// with [`Summarizer::is_ready`]). Title `[Koru] Summary: N more findings`, body
    /// `In the last 60 s, N more findings (not sent one by one due to the rate limit).`; the severity
    /// is the highest of the suppressed, `event_id` the last one's. No attacker data.
    pub fn take_summary(&mut self, _now_ms: u64) -> Option<Notification> {
        let event_id = self.last_event.take()?;
        let n = std::mem::take(&mut self.count);
        self.first_ms = None;
        let secs = self.window_ms.div_ceil(1000);
        let severity = std::mem::replace(&mut self.highest, Severity::Info);
        Some(Notification {
            severity,
            title: format!("[Koru] Summary: {n} more findings"),
            body: format!("In the last {secs} s, {n} more findings (not sent one by one due to the rate limit)."),
            event_id,
        })
    }
}
