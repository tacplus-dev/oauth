# OAuth

OAuth is the unified authentication and token broker for the control plane.
It handles OAuth2/OIDC browser flows (provider discovery, authorization code
exchange with PKCE, IDP token verification, kernel token minting delegation)
and CLI/device token brokering via bidirectional streaming.

## Architecture

```
  Browser                          CLI/Device
    │                                  │
    │  1. redirect to /authorize       │  1. open bidi stream
    │  2. IDP login + callback         │  2. receive auth URL
    │  3. exchange code → IDP token    │  3. user authenticates in browser
    │  4. verify IDP token (JWKS)      │  4. OAuth relays token
    │  5. kernel.MintUserToken         │  5. kernel.MintUserToken
    │  6. redirect with token          │  6. stream delivers token
    ▼                                  ▼
              ┌──────────────┐
              │    OAuth     │
              │              │
              │  OIDC flows  │──► kernel.Mint (token delegation)
              │  Session mgmt│
              │  Nonce store │
              └──────────────┘
```

## RPCs

### oauth.Auth

| RPC | Description |
|-----|-------------|
| `ListProviders` | Returns configured OAuth/OIDC providers |
| `Authorize` | Initiates OAuth flow — returns authorization URL |
| `MintCallbackTokens` | Handles IDP callback — exchanges code, verifies token, mints |
| `RevokeSession` | Invalidates session |

### oauth.Session

| RPC | Description |
|-----|-------------|
| `Session` | Bidirectional stream for CLI/device token brokering |

### oauth.Token

| RPC | Description |
|-----|-------------|
| `InstallToken` | Installs a pre-minted token (used by CLI after browser auth) |

## Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `session_timeout_seconds` | 300 | Session timeout (30s–600s) |
| `refresh_token_lifetime_seconds` | 604800 | Refresh token lifetime (1h–30d) |
| `auto_refresh_before_seconds` | 3600 | Auto-refresh window (60s–24h) |
| `enable` | false | Enable OAuth auth flows |
| `providers` | — | List of OAuth/OIDC provider configurations (fleet-wide) |
| `tenant_redirect_uri_prefixes` | — | Redirect allowlist for providers from tenant slices; empty offers none |
| `nonce_expire_seconds` | 300 | CSRF nonce expiry |
| `jwk_refetch_interval_seconds` | 300 | IDP JWKS refresh interval |

Each tenant's own IdPs come from its `oauth.OAuthTenantConfig` slice in kernel's
`ConfigState.tenant_configs` and are offered after `providers`. A tenant provider
with the issuer and client id of a fleet-wide provider (or another tenant's) is
refused and logged with its tenant; a slice that would take the list past 256 is
refused whole; the `people` tenant's slice is not read (its providers stay in
`providers`). An enabled provider missing its credential disables only itself.

## Tenant providers: where they live

A tenant's sign-in providers live in one place: its `oauth.OAuthTenantConfig`
slice in kernel's `ConfigState.tenant_configs`, which the tenant edits with
`UpdateTenantConfig` and kernel's `DeleteTenant` removes. oauth persists no
tenant-provider data of its own: it writes nothing to disk or to kernel, and
holds the slices only in memory, as the provider list, OIDC clients (with their
discovery and JWKS caches) and state codec that every Config delivery and
tenant config snapshot rebuilds whole. A provider its tenant removed, or a
deleted tenant's, is in nothing built after (`src/auth.rs`
`tenant_removal_tests`). A tenant change is applied over the last Config that
built, so a Config that fails to build does not hold a deleted tenant's
providers in place.

A sign-in in flight names its provider by a stable key (tenant, issuer and
client id; `fleet` for a fleet-wide provider) in its sealed `state`, not by an
index in the list. If that provider is gone or moved to another issuer or
client when the IdP answers, `MintCallbackTokens` answers FAILED_PRECONDITION
"this sign-in option no longer exists" (Apple's form_post callback sends the
browser to `/`), never another provider's login. The state is keyed by the
operator's secrets (fleet-wide client secrets and the Apple .p8), so a tenant's
edit does not void other sign-ins in flight; only with no operator secret at
all do the tenants' secrets key it.

The one fleet-level knob for tenant providers is `tenant_redirect_uri_prefixes`:
the fleet webapp's own addresses, set by the operator.

## Key Files

- `src/main.rs` — Server startup
- `src/service.rs` — Handler implementations
- `src/auth.rs` — OAuth flow logic
- `src/oidc.rs` — OIDC discovery and token verification
- `src/providers.rs` — The fleet-wide and tenant-slice provider list
- `src/session.rs` — Bidirectional session stream management
- `src/nonce.rs` — CSRF nonce generation and validation

## Build

```bash
just        # generate + compile
```

## Releasing

oauth is released by version, and fleets pin a release line, `MAJOR.MINOR`, which is always that line's
highest patch ([tacplus#180](https://github.com/tacplus-dev/tacplus/issues/180)). Versions are `0.x` until
SeaBeam's launch, when `1.0.0` is cut; on `0.x` a minor may break, a patch never does.

A change merged to main is released by the same run that merged it: a fix as the next patch, a feature as the
next minor. To cut one, from the commit to release:

```sh
git tag -a v0.1.2 -m "oauth 0.1.2: ..."   # a patch to an older line is tagged on release/MAJOR.MINOR
git push origin v0.1.2
```

The tag runs [release.yml](.github/workflows/release.yml): the gates on the tag ([ci.yml](.github/workflows/ci.yml)),
then `ghcr.io/tacplus-dev/oauth:<version>` ([ci/release-image.sh](ci/release-image.sh)), labelled with the
version, commit and commit date, and `:<MAJOR.MINOR>` moved to it only when it is the line's highest patch, so
the line tag never goes backwards and no other line moves ([ci/release-tags.sh](ci/release-tags.sh)). The
GitHub release's notes are the commits since the previous release ([ci/release-notes.sh](ci/release-notes.sh));
it is marked Latest only when it is the highest release, never a patch on an older line
([ci/release-plan.sh](ci/release-plan.sh)). A pre-release (`v0.2.0-rc.1`) publishes only its own tag. The
package is public: pulls need no credential.

The image is built for linux/arm64, what the fleets run on; amd64 is off by default, as in the fleets'
`images/pins.yaml`, and `PLATFORMS: amd64 arm64` in release.yml builds both into one image. It runs under the
[launcher](https://github.com/tacplus-dev/launcher), built from source at release.yml's `LAUNCHER_COMMIT`.

By hand, from main:

```sh
gh workflow run release.yml -f version=v0.1.1 -f publish=true   # release an existing tag; it is not moved
gh workflow run release.yml -f version=v0.1.2                   # dry run: builds HEAD as v0.1.2, publishes nothing
```

The first is for a tag pushed before release.yml existed: it checks the tag out and runs its gates with the CI
scripts of main. v0.1.1 is the first release with an image; v0.1.0 cannot be built as tagged (it has no
`tacplus.lock` and its `Cargo.lock` is stale, #20), so it has none.

## Proto

[`services/oauth.proto`](../../proto/services/oauth.proto)
