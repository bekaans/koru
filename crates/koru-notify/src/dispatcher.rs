//! The dispatcher: per-channel rate limiting, summarization, persistent queue and retries.
//!
//! Flow (`notify`): when the rate limit allows, the notification goes to the channel; on a
//! transient error it is queued (on disk), on a permanent error it drops and counts; when the
//! rate limit denies, it is suppressed and counted into the summary. `process` (called
//! regularly) sends the due summary and retries due queue records oldest first; while the
//! network is down it stops at the first failure (no full-queue drain per call). Time is given from outside (unix ms).

use std::path::PathBuf;

use koru_event::{InterfaceError, Notification, NotificationChannel};

use crate::backoff::random_u64;
use crate::{BackoffSettings, NotifyError, PersistentQueue, RateSettings, Summarizer, TokenBucket, mask_notification};

/// Channel settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSettings {
    /// Rate limit and summary window.
    pub rate: RateSettings,
    /// Retry attempts.
    pub backoff: BackoffSettings,
    /// The queue's record capacity.
    pub queue_capacity: usize,
}

impl Default for ChannelSettings {
    fn default() -> ChannelSettings {
        ChannelSettings { rate: RateSettings::DEFAULT, backoff: BackoffSettings::DEFAULT, queue_capacity: 1000 }
    }
}

/// Per-channel counters (for the process lifetime; `dropped_*` and `in_queue` are persistent).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChannelStats {
    /// Notifications delivered to the channel (summaries and queued deliveries included).
    pub sent: u64,
    /// Queued because of a transient error.
    pub queued: u64,
    /// Not sent one by one because of the rate limit (they enter the summary).
    pub suppressed_count: u64,
    /// Summary notifications delivered.
    pub summaries_sent: u64,
    /// Dropped because of a permanent error.
    pub permanent_errors: u64,
    /// Dropped because the queue overflowed.
    pub dropped_overflow: u64,
    /// Dropped because the attempt limit was exceeded.
    pub dropped_retries: u64,
    /// Currently pending in the queue.
    pub in_queue: usize,
    /// Notifications lost because the queue file could not be written (full disk, permission, etc.).
    pub queue_errors: u64,
}

/// The outcome of one send attempt.
enum Outcome {
    Delivered,
    Queued,
    Dropped,
}

/// One channel pipeline: the channel, the rate limit, the summarizer, the queue, the counters.
struct ChannelState {
    channel: Box<dyn NotificationChannel + Send>,
    name: String,
    settings: ChannelSettings,
    bucket: TokenBucket,
    summarizer: Summarizer,
    queue: PersistentQueue,
    counters: ChannelStats,
}

impl ChannelState {
    fn backoff_delay(&self, attempts: u32) -> u64 {
        self.settings.backoff.wait_ms(attempts, random_u64())
    }

    /// Sends directly; queues on a transient error; drops and counts on a permanent one.
    fn send(&mut self, b: &Notification, now_ms: u64) -> Outcome {
        match self.channel.send(b) {
            Ok(()) => {
                self.counters.sent += 1;
                Outcome::Delivered
            }
            Err(InterfaceError::Transient(_)) => {
                let next_at = now_ms.saturating_add(self.backoff_delay(0));
                match self.queue.append(b, now_ms, next_at) {
                    Ok(_) => {
                        self.counters.queued += 1;
                        Outcome::Queued
                    }
                    Err(_) => {
                        self.counters.queue_errors += 1;
                        Outcome::Dropped
                    }
                }
            }
            Err(InterfaceError::Permanent(_)) => {
                self.counters.permanent_errors += 1;
                Outcome::Dropped
            }
        }
    }

    fn notify(&mut self, b: &Notification, now_ms: u64) {
        if self.bucket.try_take(now_ms) {
            self.send(b, now_ms);
        } else {
            self.summarizer.suppressed(b, now_ms);
            self.counters.suppressed_count += 1;
        }
    }

    fn process(&mut self, now_ms: u64) {
        self.process_summary(now_ms);
        self.process_queue(now_ms);
    }

    /// Sends the due summary (waits when no token is available).
    fn process_summary(&mut self, now_ms: u64) {
        if self.summarizer.is_ready(now_ms)
            && self.bucket.try_take(now_ms)
            && let Some(b) = self.summarizer.take_summary(now_ms)
            && matches!(self.send(&b, now_ms), Outcome::Delivered)
        {
            self.counters.summaries_sent += 1;
        }
    }

    /// Retries due queue records oldest first; stops at the first transient failure.
    fn process_queue(&mut self, now_ms: u64) {
        for _ in 0..self.queue.length() {
            let Some(record) = self.queue.next(now_ms) else { return };
            if !self.bucket.try_take(now_ms) {
                return;
            }
            let Ok(notification) = record.notification() else {
                // The file was hand-edited: the record cannot be sent; it drops and counts.
                self.counters.permanent_errors += 1;
                if self.queue.succeeded(record.id).is_err() {
                    self.counters.queue_errors += 1;
                    return;
                }
                continue;
            };
            match self.channel.send(&notification) {
                Ok(()) => {
                    self.counters.sent += 1;
                    if self.queue.succeeded(record.id).is_err() {
                        self.counters.queue_errors += 1;
                        return;
                    }
                }
                Err(InterfaceError::Permanent(_)) => {
                    self.counters.permanent_errors += 1;
                    if self.queue.succeeded(record.id).is_err() {
                        self.counters.queue_errors += 1;
                        return;
                    }
                }
                Err(InterfaceError::Transient(_)) => {
                    let attempts = record.attempts.saturating_add(1);
                    let result = if attempts >= self.settings.backoff.max_attempts {
                        self.queue.drop_expired_retries(record.id)
                    } else {
                        let next_at = now_ms.saturating_add(self.backoff_delay(attempts));
                        self.queue.failed(record.id, next_at).map(|_| ())
                    };
                    if result.is_err() {
                        self.counters.queue_errors += 1;
                    }
                    return;
                }
            }
        }
    }

    fn stats(&self) -> ChannelStats {
        ChannelStats {
            dropped_overflow: self.queue.dropped_overflow(),
            dropped_retries: self.queue.dropped_retries(),
            in_queue: self.queue.length(),
            ..self.counters
        }
    }
}

/// The dispatcher.
pub struct Dispatcher {
    dir: PathBuf,
    channels: Vec<ChannelState>,
    mask: bool,
}

impl Dispatcher {
    /// The directory holding the queues (absolute; created 0700).
    pub fn new(dir: impl Into<PathBuf>) -> Dispatcher {
        Dispatcher { dir: dir.into(), channels: Vec::new(), mask: true }
    }

    /// Adds a channel and opens its queue (records left from a previous run load). A second channel
    /// with an already used name is rejected.
    pub fn add_channel(
        &mut self,
        channel: Box<dyn NotificationChannel + Send>,
        settings: ChannelSettings,
        now_ms: u64,
    ) -> Result<(), NotifyError> {
        let name = channel.name().to_string();
        if self.channels.iter().any(|h| h.name == name) {
            return Err(NotifyError::Settings("two channels cannot share a name".to_string()));
        }
        if !settings.rate.is_valid() {
            return Err(NotifyError::Settings("rate limit values must be greater than zero".to_string()));
        }
        let queue = PersistentQueue::open(&self.dir, &name, settings.queue_capacity)?;
        self.channels.push(ChannelState {
            bucket: TokenBucket::new(&settings.rate, now_ms),
            summarizer: Summarizer::new(settings.rate.summary_window_ms),
            channel,
            name,
            settings,
            queue,
            counters: ChannelStats::default(),
        });
        Ok(())
    }

    /// Whether IP masking is on (default: on).
    pub fn masking_enabled(&self) -> bool {
        self.mask
    }

    /// Turns IP masking on or off. While on, IPv4 (/24) and IPv6 (/48) addresses in the
    /// notification are masked before reaching a channel or the queue file.
    pub fn set_masking(&mut self, on: bool) {
        self.mask = on;
    }

    /// Dispatches the notification to every channel.
    pub fn notify(&mut self, notification: &Notification, now_ms: u64) {
        // Masking happens once, before anything reaches a channel or a queue file.
        let masked;
        let notification = if self.mask {
            masked = mask_notification(notification);
            &masked
        } else {
            notification
        };
        for h in &mut self.channels {
            h.notify(notification, now_ms);
        }
    }

    /// Processes due summaries and due queue records.
    pub fn process(&mut self, now_ms: u64) {
        for h in &mut self.channels {
            h.process(now_ms);
        }
    }

    /// A channel's counters; `None` when the channel does not exist.
    pub fn stats(&self, channel: &str) -> Option<ChannelStats> {
        self.channels.iter().find(|h| h.name == channel).map(ChannelState::stats)
    }
}
