//! The source scan (code-review note; protected set): no construct in the source disables
//! or weakens certificate and host-name validation; redirects are never followed; the TLS
//! library is rustls only. It complements the behavior tests (`tls_validation.rs`,
//! `client_safety.rs`): if someone adds a verification-off switch tomorrow, this test breaks.

use std::fs;
use std::path::PathBuf;

fn references() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut v = Vec::new();
    for g in fs::read_dir(dir).unwrap() {
        let path = g.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            v.push((path.file_name().unwrap().to_string_lossy().into_owned(), fs::read_to_string(&path).unwrap()));
        }
    }
    assert!(v.len() >= 10);
    v
}

/// Drops comment and doc-comment lines (words in prose must not count).
fn reply_lines(source: &str) -> String {
    source.lines().filter(|s| !s.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n")
}

#[test]
fn there_is_no_verification_off_switch() {
    let forbidden = [
        "dangerous",
        "danger(",
        "with_custom_certificate_verifier",
        "ServerCertVerifier",
        "ServerCertVerified",
        "NoCertificateVerification",
        "InsecureSkip",
        "insecure",
        "accept_invalid",
        "verify_hostname",
        "enable_sni = false",
        "alpn_protocols = vec![]",
    ];
    for (name, k) in references() {
        let code = reply_lines(&k);
        for y in forbidden {
            assert!(!code.contains(y), "{name}: forbidden construct {y:?}");
        }
    }
}

#[test]
fn root_certificates_come_only_from_the_system_store_in_one_place() {
    let mut number = 0;
    for (name, k) in references() {
        let code = reply_lines(&k);
        number += code.matches("with_root_certificates").count();
        assert!(!code.contains("webpki_roots") && !code.contains("webpki-roots"), "{name}");
        if name != "http.rs" {
            assert!(!code.contains("ClientConfig"), "{name}: the TLS config is built only in http.rs");
        }
    }
    assert_eq!(number, 1, "the root-store setup must live in exactly one place");
}

#[test]
fn tls_is_rustls_and_ring_only() {
    for (name, k) in references() {
        let code = reply_lines(&k);
        for forbidden in ["openssl", "native_tls", "native-tls", "aws_lc", "boring"] {
            assert!(!code.contains(forbidden), "{name}: {forbidden}");
        }
    }
    let cargo = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    assert!(!cargo.contains("openssl") && !cargo.contains("native-tls") && !cargo.contains("aws-lc"));
}

#[test]
fn redirects_are_never_followed_and_location_is_not_read() {
    for (name, k) in references() {
        let code = reply_lines(&k).to_ascii_lowercase();
        assert!(!code.contains("\"location"), "{name}: the Location header must not be read");
        assert!(!code.contains("redirect"), "{name}: there must be no redirect logic");
    }
}

#[test]
fn the_http_client_only_takes_the_validated_address_type() {
    // Requests are built only from an HttpsAddress; no path may connect from a raw string.
    let http = references().into_iter().find(|(a, _)| a == "http.rs").unwrap().1;
    assert!(http.contains("pub(crate) url: &'a HttpsAddress") || http.contains("pub url: &'a HttpsAddress"));
}
