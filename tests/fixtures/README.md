# Test fixtures

No private key is committed here, not even a throwaway one (oauth#26): gitleaks
cannot tell a committed test key from a real one, and the build's security checks
fail on any secret. The tests generate their keys and certificates when they run,
with the chassis `key` and `x509` crates, once per test binary
(`src/test_keys.rs`, and the fixtures of each test module). The
`test_keys::no_private_key_is_committed` test fails if one comes back.

# TLS certificates

The oidc certificate-verification tests in `src/oidc.rs` issue their certificates
at run time (`oidc::tests::tls`), valid for a day:

- an **Ed25519** root CA. It exists to test the specific claim the removed
  `danger_accept_invalid_certs` workaround was justified by: that rustls-webpki
  cannot verify an Ed25519 CA chain. It can.
- an ECDSA P-256 leaf for `localhost`, issued by the Ed25519 CA. This is the same
  shape the live IDP presents (Let's Encrypt issues ECDSA leaves under its Ed25519
  `YE1` intermediate).
- a self-signed P-256 leaf for the same name, chaining to nothing. This plays the
  interceptor that verification must refuse.

# JWT alg-selection cases

`jwt-alg-cases.json` is the shared case table for which algorithm an IdP's JWKS
key verifies with (oauth#4): a key that declares no `alg` (Microsoft's) accepts
only the provider's discovery `id_token_signing_alg_values_supported` within the
key's own family, and `none` and HMAC never. It carries no key material: `keys`
names the throwaway RSA, P-256 and Ed25519 keys each run generates, each `jwks`
entry names the key whose public half it carries, and `hmac_secrets` says how the
HMAC key-confusion secrets (the public keys as PEM, DER and JWK `n`) are derived
from them. Every case has the outcome it must reach. `auth::idp_alg_selection_tests`
generates the keys, signs and verifies each case; another port reads the same file
so the cases cannot drift. The tokens are signed at test time, so nothing in it
expires.
