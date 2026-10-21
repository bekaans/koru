//! The heartbeat (protected set; ADR-0007 "Heartbeat"): regular
//! GETs to the Healthchecks.io ping address, `/start`, `/fail`, the regular loop, pings ending
//! on stop, and the ping address's secrecy. No real network.

mod common;

use std::time::{Duration, Instant};

use common::*;
use koru_event::{Heartbeat, InterfaceError};
use koru_notify::{HealthchecksHeartbeat, HeartbeatLoop, HttpsAddress, NotifyError};

const UUID: &str = "11111111-2222-3333-4444-555555555555";

fn heartbeat(s: &FakeHttp) -> HealthchecksHeartbeat {
    HealthchecksHeartbeat::new(HttpsAddress::parse_parts(&s.url(&format!("/ping/{UUID}"))).unwrap())
        .set_timeout(Duration::from_millis(800))
}

fn wait_for(condition: impl Fn() -> bool, dur: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < dur {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    condition()
}

#[test]
fn a_ping_sends_a_get_to_the_ping_address() {
    let s = FakeHttp::start();
    heartbeat(&s).beat().unwrap();
    let i = s.one_request();
    assert_eq!(i.method, "GET");
    assert_eq!(i.path, format!("/ping/{UUID}"));
    assert!(i.body.is_empty());
}

#[test]
fn start_and_fail_use_their_own_paths() {
    let s = FakeHttp::start();
    let mut k = heartbeat(&s);
    k.begin().unwrap();
    k.failed().unwrap();
    let paths: Vec<_> = s.requests().iter().map(|i| i.path.clone()).collect();
    assert_eq!(paths, [format!("/ping/{UUID}/start"), format!("/ping/{UUID}/fail")]);
}

#[test]
fn the_query_string_is_preserved() {
    let s = FakeHttp::start();
    let mut k =
        HealthchecksHeartbeat::new(HttpsAddress::parse_parts(&s.url(&format!("/ping/{UUID}?rid=abc"))).unwrap());
    k.failed().unwrap();
    assert_eq!(s.one_request().path, format!("/ping/{UUID}/fail?rid=abc"));
}

#[test]
fn http_statuses_are_classified_right() {
    for (state, is_transient) in [(500u16, true), (503, true), (429, true), (404, false), (400, false)] {
        let s = FakeHttp::start_answering(FakeReply::WithStatus(state));
        let error = heartbeat(&s).beat().expect_err("an error is expected");
        match (is_transient, &error) {
            (true, InterfaceError::Transient(_)) | (false, InterfaceError::Permanent(_)) => {}
            _ => panic!("state {state}: {error:?}"),
        }
    }
}

#[test]
fn a_connect_error_and_a_timeout_are_transient() {
    let k = HealthchecksHeartbeat::new(
        HttpsAddress::parse_parts(&format!("http://127.0.0.1:{}/p", a_free_port())).unwrap(),
    );
    assert!(matches!(k.clone().beat(), Err(InterfaceError::Transient(_))));
    let s = FakeHttp::start_answering(FakeReply::Silent);
    let t = Instant::now();
    assert!(matches!(heartbeat(&s).beat(), Err(InterfaceError::Transient(_))));
    assert!(t.elapsed() < Duration::from_secs(4));
}

#[test]
fn the_ping_address_stays_out_of_errors_and_debug() {
    let s = FakeHttp::start_answering(FakeReply::WithStatus(500));
    let mut k = heartbeat(&s);
    for error in
        [k.beat().unwrap_err().to_string(), k.failed().unwrap_err().to_string(), k.begin().unwrap_err().to_string()]
    {
        for forbidden in [UUID, "ping", "127.0.0.1", &s.port.to_string()] {
            assert!(!error.contains(forbidden), "the error message must not contain {forbidden:?}: {error}");
        }
    }
    let d = format!("{k:?}");
    assert!(!d.contains(UUID) && !d.contains("ping"), "{d}");
}

#[test]
fn the_ping_address_must_be_https() {
    assert!(matches!(HttpsAddress::parse_parts("http://hc-ping.com/abc"), Err(NotifyError::Settings(_))));
}

#[test]
fn an_https_ping_speaks_tls() {
    let (port, rx) = raw_capture();
    let mut k = HealthchecksHeartbeat::new(HttpsAddress::parse_parts(&format!("https://127.0.0.1:{port}/p")).unwrap())
        .set_timeout(TLS_START_DEADLINE);
    assert!(k.beat().is_err());
    let first_bytes = rx.recv_timeout(TLS_START_DEADLINE + Duration::from_secs(2)).unwrap();
    assert!(
        first_bytes.len() >= 3 && first_bytes[0] == 0x16 && first_bytes[1] == 0x03,
        "{:02x?}",
        &first_bytes[..first_bytes.len().min(8)]
    );
}

#[test]
fn the_loop_pings_regularly() {
    let s = FakeHttp::start();
    let d = HeartbeatLoop::start(heartbeat(&s), Duration::from_millis(50));
    assert!(
        wait_for(|| s.request_count() >= 4, Duration::from_secs(5)),
        "regular pings must arrive: {}",
        s.request_count()
    );
    assert!(d.dropped() >= 4);
    assert_eq!(d.error(), 0);
    d.stop(false).unwrap();
}

#[test]
fn the_loop_pings_immediately() {
    let s = FakeHttp::start();
    let d = HeartbeatLoop::start(heartbeat(&s), Duration::from_secs(3600));
    assert!(wait_for(|| s.request_count() == 1, Duration::from_secs(3)), "the first ping must go out immediately");
    d.stop(false).unwrap();
}

#[test]
fn stopping_ends_the_pings() {
    let s = FakeHttp::start();
    let d = HeartbeatLoop::start(heartbeat(&s), Duration::from_millis(30));
    assert!(wait_for(|| s.request_count() >= 2, Duration::from_secs(3)));
    d.stop(false).unwrap();
    let number = s.request_count();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(s.request_count(), number, "a stopped Koru must not ping (Healthchecks flips down at the deadline)");
    assert!(s.requests().iter().all(|i| !i.path.ends_with("/fail")), "stop(false) must not send /fail");
}

#[test]
fn stop_true_sends_fail_last_then_goes_quiet() {
    let s = FakeHttp::start();
    let d = HeartbeatLoop::start(heartbeat(&s), Duration::from_millis(30));
    assert!(wait_for(|| s.request_count() >= 2, Duration::from_secs(3)));
    d.stop(true).unwrap();
    let requests = s.requests();
    assert!(
        requests.last().unwrap().path.ends_with("/fail"),
        "the last request must be /fail: {:?}",
        requests.last().map(|i| &i.path)
    );
    assert_eq!(requests.iter().filter(|i| i.path.ends_with("/fail")).count(), 1);
    let number = requests.len();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(s.request_count(), number, "no ping should arrive after fail");
}

#[test]
fn the_loop_counts_network_errors_and_recovers() {
    let s = FakeHttp::start_answering(FakeReply::WithStatus(503));
    let d = HeartbeatLoop::start(heartbeat(&s), Duration::from_millis(30));
    assert!(wait_for(|| d.error() >= 2, Duration::from_secs(3)));
    assert_eq!(d.dropped(), 0);
    s.set_defaults(FakeReply::WithStatus(200));
    assert!(
        wait_for(|| d.dropped() >= 2, Duration::from_secs(3)),
        "pings must resume when the network returns (the loop must not die on the first error)"
    );
    d.stop(false).unwrap();
}

#[test]
fn stopping_the_loop_returns_fast_even_with_a_long_interval() {
    let s = FakeHttp::start();
    let d = HeartbeatLoop::start(heartbeat(&s), Duration::from_secs(3600));
    assert!(wait_for(|| s.request_count() == 1, Duration::from_secs(3)));
    let t = Instant::now();
    d.stop(false).unwrap();
    assert!(t.elapsed() < Duration::from_secs(2), "a sleeping loop must wake at once: {:?}", t.elapsed());
}

#[test]
fn stop_true_errors_when_fail_cannot_be_sent() {
    let s = FakeHttp::start();
    let d = HeartbeatLoop::start(heartbeat(&s), Duration::from_secs(3600));
    assert!(wait_for(|| s.request_count() == 1, Duration::from_secs(3)));
    s.set_defaults(FakeReply::WithStatus(500));
    assert!(d.stop(true).is_err(), "the caller must know when /fail could not be delivered");
}
