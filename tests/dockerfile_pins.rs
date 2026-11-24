//! Every image a Dockerfile builds from is pinned by digest (#36; tacplus-dev/roadmap
//! decisions/security-gates-ship-only-2026-11-23.md, point 2): a floating tag lets a
//! rebuild of the same commit ship a different, unscanned base. A `FROM` names its
//! image as `<image>:<tag>@sha256:<digest>`, or an earlier stage; an `ARG` it reads
//! defaults to such a reference (a fleet may still hand in its own base).

use std::collections::{HashMap, HashSet};
use std::path::Path;

const DOCKERFILES: &[&str] = &["Dockerfile", "Dockerfile.cross"];

/// The `FROM` lines of `text` that name an image not pinned by digest, after
/// substituting the `ARG` defaults declared before them.
fn unpinned_froms(text: &str) -> Vec<String> {
    let mut args = HashMap::new();
    let mut stages = HashSet::new();
    let mut unpinned = Vec::new();
    for line in text.lines().map(str::trim) {
        let mut words = line.split_whitespace();
        let instruction = words.next().unwrap_or_default().to_ascii_uppercase();
        let rest: Vec<&str> = words.collect();
        match instruction.as_str() {
            "ARG" => {
                if let Some((name, value)) = rest.first().and_then(|a| a.split_once('=')) {
                    args.insert(name.to_string(), value.trim_matches('"').to_string());
                }
            }
            "FROM" => {
                let mut operands = rest.iter().filter(|w| !w.starts_with("--"));
                let image = substitute(operands.next().copied().unwrap_or_default(), &args);
                if let (Some(as_), Some(name)) = (operands.next(), operands.next()) {
                    if as_.eq_ignore_ascii_case("as") {
                        stages.insert(name.to_ascii_lowercase());
                    }
                }
                let pinned = image
                    .split_once("@sha256:")
                    .is_some_and(|(reference, _)| reference.contains(':'));
                if !pinned && !stages.contains(&image.to_ascii_lowercase()) && image != "scratch" {
                    unpinned.push(line.to_string());
                }
            }
            _ => {}
        }
    }
    unpinned
}

fn substitute(word: &str, args: &HashMap<String, String>) -> String {
    let mut out = word.to_string();
    for (name, value) in args {
        out = out.replace(&format!("${{{name}}}"), value).replace(&format!("${name}"), value);
    }
    out
}

#[test]
fn every_from_is_pinned_by_digest() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in DOCKERFILES {
        let text = std::fs::read_to_string(root.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let unpinned = unpinned_froms(&text);
        assert!(unpinned.is_empty(), "{name}: FROM without <image>:<tag>@sha256:<digest>: {unpinned:?}");
    }
}

#[test]
fn the_check_catches_a_floating_tag() {
    assert_eq!(unpinned_froms("FROM debian:trixie-slim"), ["FROM debian:trixie-slim"]);
    assert_eq!(unpinned_froms("ARG BASE_IMAGE=debian:trixie-slim\nFROM ${BASE_IMAGE}"), ["FROM ${BASE_IMAGE}"]);
    assert_eq!(unpinned_froms("FROM --platform=linux/arm64 rust:trixie AS builder").len(), 1);
    assert_eq!(unpinned_froms("FROM debian@sha256:8aa5").len(), 1, "a digest without its tag");
}

#[test]
fn the_check_accepts_a_digest_and_a_stage() {
    let pinned = "ARG BASE_IMAGE=debian:trixie-slim@sha256:8aa5\nFROM ${BASE_IMAGE}\n\
                  FROM --platform=linux/arm64 rust:trixie@sha256:1f65 AS builder\nFROM builder\nFROM scratch";
    assert!(unpinned_froms(pinned).is_empty());
}
