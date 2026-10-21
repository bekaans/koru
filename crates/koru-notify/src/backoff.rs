//! Exponential backoff with jitter.

/// Retry settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffSettings {
    /// Delay before the first retry (ms).
    pub base_ms: u64,
    /// Longest delay (ms); the exponential growth stops here.
    pub max_ms: u64,
    /// Max attempts per notification; past it the record is dropped and counted.
    pub max_attempts: u32,
}

impl BackoffSettings {
    /// Default: 5 s base, 10 min cap, at most 48 attempts.
    pub const DEFAULT: BackoffSettings = BackoffSettings { base_ms: 5_000, max_ms: 600_000, max_attempts: 48 };

    /// Delay for `attempt` (0-based): `min(cap, base * 2^attempt)` jittered into `[d/2, d]`
    /// ("equal jitter"): `d/2 + floor(random * (d - d/2 + 1) / 2^64)`. `random` is a uniform u64;
    /// 0 → `d/2`, `u64::MAX` → `d`. Never overflows.
    pub fn wait_ms(&self, attempts: u32, random: u64) -> u64 {
        let exponent = attempts.min(63);
        let d = self.base_ms.saturating_mul(1u64 << exponent).min(self.max_ms);
        let half = d / 2;
        let range = u128::from(d - half) + 1;
        let extra = (u128::from(random) * range) >> 64;
        half + u64::try_from(extra).unwrap_or(d - half)
    }
}

impl Default for BackoffSettings {
    fn default() -> BackoffSettings {
        BackoffSettings::DEFAULT
    }
}

/// A u64 from the OS CSPRNG (for jitter).
pub fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    if getrandom::fill(&mut b).is_ok() {
        return u64::from_le_bytes(b);
    }
    // If the CSPRNG is unreadable (very rare) fall back to time; jitter spreads load, it is not security.
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos() & u128::from(u64::MAX)).unwrap_or(0));
    ns.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}
