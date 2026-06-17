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
| `providers` | — | List of OAuth/OIDC provider configurations |
| `nonce_expire_seconds` | 300 | CSRF nonce expiry |
| `jwk_refetch_interval_seconds` | 300 | IDP JWKS refresh interval |

## Key Files

- `src/main.rs` — Server startup
- `src/service.rs` — Handler implementations
- `src/auth.rs` — OAuth flow logic
- `src/oidc.rs` — OIDC discovery and token verification
- `src/session.rs` — Bidirectional session stream management
- `src/nonce.rs` — CSRF nonce generation and validation

## Build

```bash
just        # generate + compile
```

## Proto

[`services/oauth.proto`](../../proto/services/oauth.proto)
