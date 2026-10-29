# Roadmap: oauth

Owned by Jody; changed only by an agent at Jody's request. Loopers propose in PROPOSALS.md.

## Now
The authentication and token broker (Rust): OAuth2/OIDC browser flows and CLI/device token brokering; kernel mints the tokens.
Offers fleet-wide providers plus each tenant's IdPs from its config slice. Unreleased; tacplus floor 2.4.

## Next
- Sign-in: per-tenant OIDC IdPs, Custom domain lookup, fresh-sign-in legs (#15)
- Tenant providers: a deleted tenant leaves nothing behind (#11)
- `gates` recipe in the justfile (#10; a `gates` recipe is already on main since b6e6a36)

## Later
- Release: tag from v0.1.0 and publish the image (#5; blocked on tacplus-dev/looper#12)
- Port SeaBeam oauth 7d4d37e..0c3c34b3 (#6; blocked on #5)
- RUSTSEC-2023-0071 (rsa) and RUSTSEC-2026-0387 (crypto-bigint 0.5) via generated chassis crates (#9; blocked on tacplus-dev/tacplus#186)
- Microsoft and Apple registrations for tacplus-dev, a login through each proven (tacplus-dev/roadmap:decisions/tacplus-dev-stable-gate-2026-10-25.md)

## Not doing
- Nothing recorded yet.
