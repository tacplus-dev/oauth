//! The release Dockerfile's base: what it ships is pinned, and carries Debian's
//! fixes the base's tag has not caught up with (#30).

const DOCKERFILE: &str = include_str!("../Dockerfile");

/// The default of `ARG BASE_IMAGE`, the base a build gets when the fleet hands in none.
fn base_image() -> &'static str {
    DOCKERFILE
        .lines()
        .find_map(|l| l.trim().strip_prefix("ARG BASE_IMAGE="))
        .expect("Dockerfile: no ARG BASE_IMAGE default")
}

/// The default base is pinned by digest, so a rebuild of the tag changes nothing
/// under a release until the digest is moved on purpose.
#[test]
fn base_image_is_pinned_by_digest() {
    let base = base_image();
    let (name, digest) = base
        .split_once("@sha256:")
        .unwrap_or_else(|| panic!("BASE_IMAGE {base}: not pinned by @sha256: digest"));
    assert_eq!(name, "debian:trixie-slim");
    assert_eq!(digest.len(), 64, "BASE_IMAGE {base}: not a sha256 digest");
    assert!(digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
}

/// trixie-slim 13.7 ships zlib1g 1:1.3.dfsg+really1.3.1-1+b1, CVE-2026-85091
/// (HIGH, a heap overflow in gz_vacate()); Debian fixed it in trixie-security's
/// 1:1.3.dfsg+really1.3.1-1+deb13u1. The image installs that version, by version.
#[test]
fn zlib1g_carries_the_cve_2026_85091_fix() {
    // Instructions, each with its `\` continuation lines joined.
    let installs = DOCKERFILE
        .replace("\\\n", " ")
        .lines()
        .filter(|l| l.trim_start().starts_with("RUN ") && l.contains("apt-get install"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        installs.split_whitespace().any(|w| w == "zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1"),
        "Dockerfile: no RUN apt-get install of zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1"
    );
}
