//! IP masking (privacy: GDPR/KVKK; ADR-0006 "Masking", ADR-0007 §8). Lives here rather than in koru-store:
//! koru-notify does not know koru-store, but notifications also need masking; the shared layer is
//! the only place both sides depend on. koru-store re-exports the function under the same name.
//!
//! Format: for IPv4 the last octet is zeroed (/24); for IPv6 the first 48 bits are kept and the
//! rest zeroed (/48); for IPv4-mapped IPv6 (`::ffff:a.b.c.d`) the last octet of the IPv4 part is
//! zeroed. In free text, address-shaped strings are found and replaced. Masking is idempotent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn mask_v4(a: Ipv4Addr) -> Ipv4Addr {
    let o = a.octets();
    Ipv4Addr::new(o[0], o[1], o[2], 0)
}

fn mask_v6(a: Ipv6Addr) -> Ipv6Addr {
    if let Some(v4) = a.to_ipv4_mapped() {
        return mask_v4(v4).to_ipv6_mapped();
    }
    let s = a.segments();
    Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0)
}

/// Masks a single address: for IPv4 the last octet is zeroed (/24), for IPv6 the first 48 bits
/// are kept (/48); for IPv4-mapped IPv6 the last octet of the IPv4 part is zeroed.
pub fn mask_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(a) => IpAddr::V4(mask_v4(a)),
        IpAddr::V6(a) => IpAddr::V6(mask_v6(a)),
    }
}

/// The maximum length of IPv6 text (`ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255` = 45).
const V6_MAX_LEN: usize = 45;

fn word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// An IPv6 address does not start in the middle of a word: it must not be preceded by a letter,
/// digit, or underscore (it may start after separators such as `src:`). If it starts with a colon,
/// the preceding byte must not be a colon either.
fn v6_left_boundary(b: &[u8], i: usize) -> bool {
    match i.checked_sub(1).map(|j| b[j]) {
        None => true,
        Some(c) => !word_byte(c) && !(b[i] == b':' && c == b':'),
    }
}

/// The byte after the match must not look like a continuation of the address: no letter or digit;
/// `:` or `.` is accepted only when not followed by a hex digit, `:`, or `.` (end of sentence,
/// forms like "address:").
fn v6_right_boundary(b: &[u8], k: usize) -> bool {
    match b.get(k) {
        None => true,
        Some(c) if word_byte(*c) => false,
        Some(b':' | b'.') => !matches!(b.get(k + 1), Some(d) if d.is_ascii_hexdigit() || *d == b':' || *d == b'.'),
        Some(_) => true,
    }
}

/// The longest valid IPv6 match starting at `i`: (end, address). Parsing looks at most
/// [`V6_MAX_LEN`] bytes ahead and stops early on group length, colon count, and `:::`; scanning is
/// therefore linear in the input length.
fn v6_match(b: &[u8], i: usize) -> Option<(usize, Ipv6Addr)> {
    let limit = (i + V6_MAX_LEN).min(b.len());
    let (mut colons, mut dots, mut group) = (0usize, 0usize, 0usize);
    let mut longest = None;
    let mut k = i;
    while k < limit {
        let c = b[k];
        if c.is_ascii_hexdigit() {
            if dots > 0 && !c.is_ascii_digit() {
                break;
            }
            group += 1;
            if group > 4 || (dots > 0 && group > 3) {
                break;
            }
        } else if c == b':' {
            if dots > 0 || (k >= i + 2 && b[k - 1] == b':' && b[k - 2] == b':') {
                break;
            }
            colons += 1;
            if colons > 7 {
                break;
            }
            group = 0;
        } else if c == b'.' {
            if colons < 2 || dots >= 3 || group == 0 {
                break;
            }
            dots += 1;
            group = 0;
        } else {
            break;
        }
        k += 1;
        let last = b[k - 1];
        if colons >= 2
            && (last.is_ascii_hexdigit() || (last == b':' && b[k - 2] == b':'))
            && v6_right_boundary(b, k)
            && let Ok(text) = std::str::from_utf8(&b[i..k])
            && let Ok(ip) = text.parse::<Ipv6Addr>()
        {
            longest = Some((k, ip));
        }
    }
    longest
}

/// An IPv4 address must not be preceded by a digit or another dotted-number part (`1.2.3.4.5`, `2026.10.15.4`).
fn v4_left_boundary(b: &[u8], i: usize) -> bool {
    match i.checked_sub(1).map(|j| b[j]) {
        None => true,
        Some(c) if c.is_ascii_digit() => false,
        Some(b'.') => !matches!(i.checked_sub(2).map(|j| b[j]), Some(d) if d.is_ascii_digit()),
        Some(_) => true,
    }
}

/// IPv4 starting at `i`: (end, start of the last octet). 4 octets, each 1-3 digits and ≤ 255;
/// leading zeros are allowed. It must not be followed by a digit or another dotted-number part.
fn v4_match(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    let mut last_start = i;
    for n in 0..4 {
        last_start = j;
        let start = j;
        while j < b.len() && b[j].is_ascii_digit() && j - start < 4 {
            j += 1;
        }
        let digits = j - start;
        if digits == 0 || digits > 3 {
            return None;
        }
        let value = b[start..j].iter().fold(0u32, |t, r| t * 10 + u32::from(r - b'0'));
        if value > 255 {
            return None;
        }
        if n < 3 {
            if b.get(j) != Some(&b'.') {
                return None;
            }
            j += 1;
        }
    }
    match b.get(j) {
        Some(c) if c.is_ascii_digit() => None,
        Some(b'.') if matches!(b.get(j + 1), Some(d) if d.is_ascii_digit()) => None,
        _ => Some((j, last_start)),
    }
}

/// Masks the IPv4 and IPv6 addresses in text: for IPv4 the last octet is zeroed (/24; the first
/// three octets stay as written), for IPv6 the first 48 bits are kept (/48). Text that is not an
/// address is left untouched.
///
/// The scan is linear: at each byte, IPv6 then IPv4 is tried with a constant bounded lookahead (at
/// most 45 bytes). Addresses are also found in adjacent forms such as `label:IP`,
/// `8080:10.0.0.5:22`, `[v6]:port`; time, version, MAC, and date strings do not count as
/// addresses.
pub fn mask_ip_in_text(text: &str) -> String {
    let b = text.as_bytes();
    let mut output: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if (c.is_ascii_hexdigit() || c == b':')
            && v6_left_boundary(b, i)
            && let Some((end, ip)) = v6_match(b, i)
        {
            output.extend_from_slice(mask_ip(IpAddr::V6(ip)).to_string().as_bytes());
            i = end;
            continue;
        }
        if c.is_ascii_digit()
            && v4_left_boundary(b, i)
            && let Some((end, last)) = v4_match(b, i)
        {
            output.extend_from_slice(&b[i..last]);
            output.push(b'0');
            i = end;
            continue;
        }
        output.push(c);
        i += 1;
    }
    // Only ASCII regions were changed; the remaining bytes are the same valid UTF-8.
    String::from_utf8(output).unwrap_or_else(|_| text.to_string())
}
