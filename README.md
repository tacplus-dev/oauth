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

## Proto

[`services/oauth.proto`](../../proto/services/oauth.proto)
