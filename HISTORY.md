# History: oauth

Append-only: add entries at the end, never edit or remove one (CI enforces it). One line each:
`- <YYYY-MM-DD> <who: looper|agent|jody> <kind: issue|decision|release|deploy> <one line> (<links>)`

- 2026-10-28 looper issue Cargo.lock: patch unsound anyhow, rand 0.8, tokio (RUSTSEC-2026-0190, -0097, -0386) (#12, b466e5c)
- 2026-10-29 looper issue Pins: tacplus floor 2.4; the latest released line is 2.5 (#13, bc980e7)
- 2026-10-29 looper issue Pins: Dockerfile.cross builder on rust:bookworm (Debian 12); the latest released line is trixie (13) (#14, a110c48)
- 2026-11-08 looper issue Pins: tacplus floor 2.5; the latest released line is 2.6 (move the floor and commit tacplus.lock) (#20)
- 2026-11-08 looper issue Pin the build: floor 2.6 and a committed tacplus.lock, so the build pipeline and its security checks run on this repository (#21, abc418b)
- 2026-11-21 looper release v0.1.2 (https://github.com/tacplus-dev/oauth/releases/tag/v0.1.2)
- 2026-11-22 looper issue CodeQL fails the security checks on 14 false positives: literal nonces in #[cfg(test)] code, an OsRng-filled nonce buffer, a test's panic message (#31)
- 2026-11-22 looper release v0.1.3 (https://github.com/tacplus-dev/oauth/releases/tag/v0.1.3)
- 2026-11-22 looper issue Pinned images behind their lines: relock (tacplus.lock: tacplus 2.6.1 → 2.6.13, and 1 more) (#33)
- 2026-11-23 looper release v0.1.4 (https://github.com/tacplus-dev/oauth/releases/tag/v0.1.4)
- 2026-11-23 looper issue Pinned images behind their lines: relock (tacplus.lock: tacplus 2.6.13 → 2.6.14, and 1 more) (#34)
- 2026-11-24 looper issue Release image base pinned by digest, not the floating tag (#36)
- 2026-11-25 looper release v0.1.6 (https://github.com/tacplus-dev/oauth/releases/tag/v0.1.6)
- 2026-11-25 looper issue Cargo.lock: url 2.5.8 has RUSTSEC-2026-0592 (stack overflow in Url::origin on nested blob: URLs); relock to 2.5.9 (#35)
- 2026-11-25 looper issue Pinned images behind their lines: relock (Dockerfile.cross: rust:trixie → rust:trixie) (#37)
- 2026-11-25 looper release v0.1.7 (https://github.com/tacplus-dev/oauth/releases/tag/v0.1.7)
- 2026-11-27 looper issue MintCallbackTokens answers HTTP 500 for a refusal: kernel's status (a user no tenant claims: PERMISSION_DENIED) is flattened to INTERNAL (#38)
- 2026-11-28 looper issue RUSTSEC-2023-0071 (rsa, no fix) and RUSTSEC-2026-0387 (crypto-bigint 0.5) via generated chassis crates (#9)
- 2026-11-28 looper release v0.1.9 (https://github.com/tacplus-dev/oauth/releases/tag/v0.1.9)
