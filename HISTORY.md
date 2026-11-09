# History: oauth

Append-only: add entries at the end, never edit or remove one (CI enforces it). One line each:
`- <YYYY-MM-DD> <who: looper|agent|jody> <kind: issue|decision|release|deploy> <one line> (<links>)`

- 2026-10-28 looper issue Cargo.lock: patch unsound anyhow, rand 0.8, tokio (RUSTSEC-2026-0190, -0097, -0386) (#12, b466e5c)
- 2026-10-29 looper issue Pins: tacplus floor 2.4; the latest released line is 2.5 (#13, bc980e7)
- 2026-10-29 looper issue Pins: Dockerfile.cross builder on rust:bookworm (Debian 12); the latest released line is trixie (13) (#14, a110c48)
- 2026-11-08 looper issue Pins: tacplus floor 2.5; the latest released line is 2.6 (move the floor and commit tacplus.lock) (#20)
- 2026-11-08 looper issue Pin the build: floor 2.6 and a committed tacplus.lock, so the build pipeline and its security checks run on this repository (#21, abc418b)
