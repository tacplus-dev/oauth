//! Throwaway keys for the tests, generated when they run (oauth#26).
//!
//! No private key is committed, not even a test one: gitleaks cannot tell a
//! committed test key from a real one, and the security checks fail on any
//! secret. Each test module generates what it needs once per run with the
//! chassis key crate, the same crate the service parses keys with, and these
//! helpers give it the public halves in the forms the tests feed on.

use base64::Engine;
use key::keys::{ImmutableKey, ImmutablePublicKey, PublicKey};

/// `der` as a PEM block under `label`, in 64-column lines.
pub(crate) fn pem(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The key's private half as the PKCS#8 PEM it was generated as.
pub(crate) fn private_pem(key: &ImmutableKey) -> &str {
    std::str::from_utf8(key.pem_bytes()).unwrap()
}

/// The X.509 SubjectPublicKeyInfo DER of the key's public half.
pub(crate) fn spki_der(key: &ImmutableKey) -> Vec<u8> {
    match key.public_key() {
        PublicKey::Rsa(k) => k.spki_der().to_vec(),
        PublicKey::EcP256(k) | PublicKey::EcP384(k) => k.to_spki_der().unwrap(),
        // SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING key } (RFC 8410).
        PublicKey::Ed25519(k) => {
            let prefix = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
            [&prefix[..], k.as_bytes()].concat()
        }
    }
}

/// The key's public half as a `PUBLIC KEY` PEM, as an IdP or Apple hands it out.
pub(crate) fn public_pem(key: &ImmutableKey) -> String {
    pem("PUBLIC KEY", &spki_der(key))
}

/// The key's public half through the chassis, under the key's id.
pub(crate) fn public_key(key: &ImmutableKey) -> ImmutablePublicKey {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_pem(key));
    ImmutablePublicKey::from_pem(key.id().to_string(), &b64).unwrap()
}

/// No private key is committed (oauth#26): the tests generate theirs. A floor
/// under the build's gitleaks scan, which fails on any committed key, test
/// fixture or not; it reads the sources, fixtures and protos for the end of a
/// private key PEM block (a bare BEGIN line, as providers.rs's tests use, is no key).
#[test]
fn no_private_key_is_committed() {
    fn walk(dir: &std::path::Path, armor: &str, found: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, armor, found);
            } else if let Ok(text) = std::fs::read_to_string(&path) {
                if text.lines().any(|line| line.contains("-----END ") && line.contains(armor)) {
                    found.push(path.display().to_string());
                }
            }
        }
    }
    // Built at run time, so this file does not match it.
    let armor = ["PRIVATE", "KEY-----"].join(" ");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    for dir in ["src", "tests", "proto"] {
        walk(&root.join(dir), &armor, &mut found);
    }
    assert!(found.is_empty(), "private keys committed: {found:?}");
}
