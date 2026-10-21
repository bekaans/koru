//! Unbiased selection helpers over the operating system's CSPRNG (`getrandom`).
//!
//! All decoy values are generated here; no seedable or predictable generator is used. Range and
//! alphabet selections use rejection sampling (no modulo bias).

/// When the CSPRNG cannot be reached.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the operating system random number generator could not be used: {0}")]
pub struct RandomError(pub(crate) String);

/// Buffered CSPRNG reader.
pub(crate) struct Random {
    buffer: [u8; 512],
    pos: usize,
}

impl Random {
    pub(crate) fn new() -> Random {
        Random { buffer: [0; 512], pos: 512 }
    }

    fn byte(&mut self) -> Result<u8, RandomError> {
        if self.pos == self.buffer.len() {
            getrandom::fill(&mut self.buffer).map_err(|e| RandomError(e.to_string()))?;
            self.pos = 0;
        }
        let b = self.buffer[self.pos];
        self.buffer[self.pos] = 0;
        self.pos += 1;
        Ok(b)
    }

    /// `n` random byte.
    pub(crate) fn bytes<const N: usize>(&mut self) -> Result<[u8; N], RandomError> {
        let mut result = [0u8; N];
        for b in &mut result {
            *b = self.byte()?;
        }
        Ok(result)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, RandomError> {
        Ok(u64::from_le_bytes(self.bytes::<8>()?))
    }

    /// An unbiased integer in the `[min, max]` range (both ends included).
    pub(crate) fn range(&mut self, min: u64, max: u64) -> Result<u64, RandomError> {
        debug_assert!(min <= max);
        let span = (max - min).wrapping_add(1);
        if span == 0 {
            return self.u64();
        }
        // The top 2^64 mod width values are rejected; the remaining range is a multiple of the width.
        let remainder = (u64::MAX % span + 1) % span;
        loop {
            let x = self.u64()?;
            if x <= u64::MAX - remainder {
                return Ok(min + x % span);
            }
        }
    }

    /// An index in the `[0, n)` range.
    pub(crate) fn index(&mut self, n: usize) -> Result<usize, RandomError> {
        debug_assert!(n > 0);
        Ok(self.range(0, n as u64 - 1)? as usize)
    }

    /// An unbiased random string from the alphabet (at most 256 characters).
    pub(crate) fn string(&mut self, alphabet: &[u8], length: usize) -> Result<String, RandomError> {
        debug_assert!(!alphabet.is_empty() && alphabet.len() <= 256);
        let n = alphabet.len();
        let limit = 256 - (256 % n);
        let mut result = String::with_capacity(length);
        while result.len() < length {
            let b = usize::from(self.byte()?);
            if b < limit {
                result.push(char::from(alphabet[b % n]));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_and_string_stay_in_bounds() {
        let mut r = Random::new();
        for _ in 0..2000 {
            let x = r.range(3, 7).unwrap();
            assert!((3..=7).contains(&x));
        }
        assert!(r.range(0, u64::MAX).is_ok());
        let d = r.string(b"ab", 64).unwrap();
        assert_eq!(d.len(), 64);
        assert!(d.contains('a') && d.contains('b'));
        assert_ne!(r.bytes::<16>().unwrap(), r.bytes::<16>().unwrap());
    }
}
