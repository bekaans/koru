//! Value generators: values in real formats but used nowhere.
//!
//! - An ed25519 key pair and moment OpenSSH private key file (`openssh-key-v1`, unencrypted).
//! - A bcrypt-format password-hash-looking value (not the hash of a real password).
//! - The GitHub token format (with a CRC32 check), a UUID (version 4), a documentation-network address.
//! - A natural timestamp: in the past, weighted to work hours and weekdays, random nanoseconds.

use ed25519_dalek::SigningKey;

use crate::random::{Random, RandomError};

const BASE64_STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_BCRYPT: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE62_GITHUB: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Base64 encoding; when `pad` is false no `=` is added.
pub(crate) fn base64(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for part in data.chunks(3) {
        let b = [part[0], *part.get(1).unwrap_or(&0), *part.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let char_count = part.len() + 1;
        for i in 0..4 {
            if i < char_count {
                result.push(char::from(alphabet[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else if pad {
                result.push('=');
            }
        }
    }
    result
}

/// CRC-32 (IEEE 802.3; the GitHub token check).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn ssh_string(output: &mut Vec<u8>, data: &[u8]) {
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(data);
}

/// The first and last lines of moment OpenSSH private key file. The constant text does not appear
/// whole in the source; secret scanners do not mistake the source code for a private key.
pub(crate) fn openssh_limits() -> (String, String) {
    let kind = "OPENSSH PRIVATE KEY";
    (format!("-----BEGIN {kind}-----\n"), format!("-----END {kind}-----\n"))
}

/// A generated SSH key pair.
pub(crate) struct SshKey {
    /// The OpenSSH private key file (ends with a newline).
    pub(crate) private_key: String,
    /// `ssh-ed25519 AAAA… comment`
    pub(crate) public_part: String,
    /// `ssh-ed25519 AAAA…`
    pub(crate) public_key: String,
}

/// Generates a new ed25519 key pair; the private key is in `openssh-key-v1` format, unencrypted.
pub(crate) fn ssh_ed25519(r: &mut Random, comment: &str) -> Result<SshKey, RandomError> {
    let mut seed = r.bytes::<32>()?;
    let signing = SigningKey::from_bytes(&seed);
    let public_part = signing.verifying_key().to_bytes();
    let kind = b"ssh-ed25519";

    let mut public_blob = Vec::with_capacity(51);
    ssh_string(&mut public_blob, kind);
    ssh_string(&mut public_blob, &public_part);

    let checksum = u32::from_be_bytes(r.bytes::<4>()?);
    let mut private_section = Vec::with_capacity(160);
    private_section.extend_from_slice(&checksum.to_be_bytes());
    private_section.extend_from_slice(&checksum.to_be_bytes());
    ssh_string(&mut private_section, kind);
    ssh_string(&mut private_section, &public_part);
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&seed);
    secret[32..].copy_from_slice(&public_part);
    ssh_string(&mut private_section, &secret);
    ssh_string(&mut private_section, comment.as_bytes());
    let mut pad = 1u8;
    while private_section.len() % 8 != 0 {
        private_section.push(pad);
        pad += 1;
    }

    let mut file = Vec::with_capacity(320);
    file.extend_from_slice(b"openssh-key-v1\0");
    ssh_string(&mut file, b"none");
    ssh_string(&mut file, b"none");
    ssh_string(&mut file, b"");
    file.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&mut file, &public_blob);
    ssh_string(&mut file, &private_section);

    let body = base64(&file, BASE64_STANDARD, true);
    let (begin, last) = openssh_limits();
    let mut private_key = begin;
    for line in body.as_bytes().chunks(70) {
        private_key.push_str(std::str::from_utf8(line).expect("base64 ASCII'dir"));
        private_key.push('\n');
    }
    private_key.push_str(&last);

    // The secret bytes in the scratch buffer are erased (no trace even though the key is fake).
    seed.fill(0);
    secret.fill(0);
    private_section.fill(0);
    file.fill(0);

    let public_key = format!("ssh-ed25519 {}", base64(&public_blob, BASE64_STANDARD, true));
    let public_part = if comment.is_empty() { public_key.clone() } else { format!("{public_key} {comment}") };
    Ok(SshKey { private_key, public_part, public_key })
}

/// A random bcrypt-format value (`$2b$<cost>$` + a 22-character salt + a 31-character hash).
pub(crate) fn bcrypt(r: &mut Random, cost: u32) -> Result<String, RandomError> {
    let salt = r.bytes::<16>()?;
    let digest = r.bytes::<23>()?;
    Ok(format!("$2b${cost:02}${}{}", base64(&salt, BASE64_BCRYPT, false), base64(&digest, BASE64_BCRYPT, false)))
}

/// The GitHub personal access token format: `ghp_` + 30 base62 + a 6-character CRC32 check.
pub(crate) fn github_token(r: &mut Random) -> Result<String, RandomError> {
    let body = r.string(BASE62_GITHUB, 30)?;
    let mut crc = u64::from(crc32(body.as_bytes()));
    let mut checksum = [b'0'; 6];
    for b in checksum.iter_mut().rev() {
        *b = BASE62_GITHUB[(crc % 62) as usize];
        crc /= 62;
    }
    Ok(format!("ghp_{body}{}", std::str::from_utf8(&checksum).expect("ASCII")))
}

/// A random UUID (version 4, RFC 9562 variant), lowercase.
pub(crate) fn uuid4(r: &mut Random) -> Result<String, RandomError> {
    let mut b = r.bytes::<16>()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]))
}

/// An address from the RFC 5737 documentation networks (TEST-NET-1/2/3); network and broadcast addresses excluded.
pub(crate) fn test_network_ipv4(r: &mut Random) -> Result<String, RandomError> {
    let networks = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];
    let network = networks[r.index(networks.len())?];
    let host_octet = r.range(1, 254)?;
    Ok(format!("{}.{}.{}.{host_octet}", network[0], network[1], network[2]))
}

const DAY_NS: i128 = 86_400 * 1_000_000_000;
const HOUR_NS: i128 = 3_600 * 1_000_000_000;

/// A natural-looking moment in the past (Unix nanoseconds): in the
/// `[now - max_days, now - min_days]` range; mostly weekdays between 08-19 (UTC); minute,
/// second, and nanosecond random. The result cannot be after `now - min_days` (one hour ago
/// when min_days is 0); a candidate past the range is redrawn (no pile-up at the boundary).
pub(crate) fn natural_time(r: &mut Random, now_ns: i128, min_days: u32, max_days: u32) -> Result<i128, RandomError> {
    let today = now_ns.div_euclid(DAY_NS);
    let limit = now_ns - i128::from(min_days) * DAY_NS - if min_days == 0 { HOUR_NS } else { 0 };
    let oldest_moment = (today - i128::from(max_days)) * DAY_NS;
    for _ in 0..1000 {
        let mut day = today - i128::from(r.range(u64::from(min_days), u64::from(max_days))?);
        // 1970-01-01 is a Thursday: (day + 3) mod 7 = 0 Monday, 5 Saturday, 6 Sunday.
        let weekday = (day + 3).rem_euclid(7);
        if weekday >= 5 && r.range(0, 99)? < 85 {
            let candidate = if weekday == 5 { day - 1 } else { day + 1 };
            let newest = today - i128::from(min_days);
            let oldest = today - i128::from(max_days);
            if (oldest..=newest).contains(&candidate) {
                day = candidate;
            }
        }
        let hour = if r.range(0, 99)? < 85 { r.range(8, 18)? } else { r.range(0, 23)? };
        let seconds = r.range(0, 3599)?;
        let ns = r.range(0, 999_999_999)?;
        let moment = day * DAY_NS + i128::from(hour) * HOUR_NS + i128::from(seconds) * 1_000_000_000 + i128::from(ns);
        if moment <= limit && moment >= oldest_moment {
            return Ok(moment);
        }
    }
    // When the range is very narrow (e.g. max_days 0 in the day's first hour) it falls back to a
    // uniform pick below the bound; the result still does not exceed it.
    let child = oldest_moment.min(limit - HOUR_NS);
    let span = u64::try_from(limit - child).unwrap_or(u64::MAX);
    Ok(child + i128::from(r.range(0, span)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_crc32_known_values() {
        assert_eq!(base64(b"", BASE64_STANDARD, true), "");
        assert_eq!(base64(b"f", BASE64_STANDARD, true), "Zg==");
        assert_eq!(base64(b"fo", BASE64_STANDARD, true), "Zm8=");
        assert_eq!(base64(b"foobar", BASE64_STANDARD, true), "Zm9vYmFy");
        assert_eq!(base64(&[0u8; 16], BASE64_BCRYPT, false).len(), 22);
        assert_eq!(base64(&[0u8; 23], BASE64_BCRYPT, false).len(), 31);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn generator_formats() {
        let mut r = Random::new();
        let b = bcrypt(&mut r, 12).unwrap();
        assert_eq!(b.len(), 60);
        assert!(b.starts_with("$2b$12$"));
        let g = github_token(&mut r).unwrap();
        assert_eq!(g.len(), 40);
        let u = uuid4(&mut r).unwrap();
        assert_eq!(&u[14..15], "4");
        let ip: std::net::Ipv4Addr = test_network_ipv4(&mut r).unwrap().parse().unwrap();
        assert!(crate::format::is_test_network(ip));
        let a = ssh_ed25519(&mut r, "deploy@build").unwrap();
        assert!(a.public_part.ends_with(" deploy@build"));
        assert!(a.public_key.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert!(a.private_key.lines().all(|s| s.len() <= 70 || s.starts_with("-----")));
    }

    #[test]
    fn natural_time_in_range() {
        let mut r = Random::new();
        let now = 1_790_000_000i128 * 1_000_000_000;
        for _ in 0..500 {
            let t = natural_time(&mut r, now, 2, 30).unwrap();
            assert!(t <= now - 2 * DAY_NS);
            assert!(t >= now - 31 * DAY_NS);
            let t = natural_time(&mut r, now, 0, 0).unwrap();
            assert!(t <= now - HOUR_NS && t >= now - DAY_NS);
        }
    }
}
