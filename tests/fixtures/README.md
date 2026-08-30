# TLS fixtures for the oidc certificate-verification tests

Throwaway certificates and keys, generated once with openssl and used only by the
`oidc::tests` in `src/oidc.rs`. They are not secrets and are not used by anything
that runs outside `cargo test`.

- `ed25519-ca.crt` / `ed25519-ca.key` — an **Ed25519** root CA. It exists to test
  the specific claim the removed `danger_accept_invalid_certs` workaround was
  justified by: that rustls-webpki cannot verify an Ed25519 CA chain. It can.
- `ed25519-leaf.crt` / `ed25519-leaf.key` — ECDSA P-256 leaf for
  `localhost`/`127.0.0.1`, issued by the Ed25519 CA. This is the same shape the
  live IDP presents (Let's Encrypt issues ECDSA leaves under its Ed25519 `YE1`
  intermediate).
- `rogue.crt` / `rogue.key` — a self-signed leaf for the same names, chaining to
  nothing. This plays the interceptor that verification must refuse.

All three are valid for 20 years from 2026-08-30, so they do not need reissuing.
To regenerate, see the openssl invocations in this file's git history.
