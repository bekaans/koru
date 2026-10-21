//! The IP masking function living in koru-event (protected set): because
//! koru-notify does not know koru-store, the masking code moves to the shared layer (ADR-0007 §8);
//! the detailed behavior tests are in koru-store (`tests/masking*.rs`), and koru-store re-exports
//! the same function. The basic forms are checked here: IPv4 /24, IPv6 /48.

use std::net::IpAddr;

use koru_event::{mask_ip, mask_ip_in_text as m};

#[test]
fn ipv4_last_octet_is_zeroed() {
    assert_eq!(m("10.1.2.3"), "10.1.2.0");
    assert_eq!(m("203.0.113.77"), "203.0.113.0");
}

#[test]
fn ipv6_first_48_bits_are_kept() {
    assert_eq!(m("2001:db8:abcd:1234::5"), "2001:db8:abcd::");
    assert_eq!(m("fe80::1"), "fe80::");
}

#[test]
fn ipv4_mapped_ipv6_masks_the_ipv4_part() {
    assert_eq!(m("::ffff:192.168.1.9"), "::ffff:192.168.1.0");
}

#[test]
fn addresses_in_free_text_are_found_non_addresses_left_alone() {
    assert_eq!(
        m("connection 203.0.113.7:443 and [2001:db8:1:2::1]:22"),
        "connection 203.0.113.0:443 and [2001:db8:1::]:22"
    );
    assert_eq!(m("source:10.0.0.5 target 8080:10.0.0.6:22"), "source:10.0.0.0 target 8080:10.0.0.0:22");
    let not_addresses = "version 1.2.3, time 10:15:30, date 2026-10-15, Process /root/.ssh/id_ed25519";
    assert_eq!(m(not_addresses), not_addresses);
}

#[test]
fn masking_is_idempotent() {
    let masked = m("a 192.168.77.200 b 2001:db8:1:2:3:4:5:6");
    assert_eq!(m(&masked), masked);
}

#[test]
fn a_bare_ip_address_is_masked() {
    let v4: IpAddr = "198.51.100.23".parse().unwrap();
    assert_eq!(mask_ip(v4), "198.51.100.0".parse::<IpAddr>().unwrap());
    let v6: IpAddr = "2001:db8:aaaa:bbbb::1".parse().unwrap();
    assert_eq!(mask_ip(v6), "2001:db8:aaaa::".parse::<IpAddr>().unwrap());
}
