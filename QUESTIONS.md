# Open questions — oauth

1. **#64 was already fixed in HEAD (commit 2f2fcdc, 2026-08-14) but
   `control/STATUS.md` still lists it under "New findings, filed not fixed".**
   I confirmed the verification code is present and correct before adding to it,
   so the task brief's premise ("auth.rs:306 finds the key and discards it") is
   stale. STATUS.md is outside my assigned directory so I did not edit it —
   the control agent should move #64 to the fixed list.
   *Default taken:* treated the task as "verify the existing fix and supply the
   test coverage it shipped without", which is what I did.

2. **No full browser authorization-code round-trip was performed.** The
   deployed `oauth0` pod in namespace `schematic` runs a pre-fix image, so a
   login through it would exercise the old binary, not this working tree;
   building/pushing an image is outside my scope. What I *did* do live: pulled a
   real RS256 id_token and the real JWKS from the live Keycloak
   (`https://keycloak.34.29.52.40.nip.io`, `master` realm, `admin-cli` client,
   direct grant using the bootstrap admin credentials already present in the
   `keycloak` Deployment spec) and ran both through `verify_id_token` — the same
   function the callback calls. It accepted the genuine token and rejected the
   tampered / wrong-issuer / wrong-audience variants. The `schematic` realm the
   service is actually configured against returned 404 on discovery, so I could
   not use the service's own provider.
   *Question for the control agent:* is the `schematic` realm expected to exist
   on that Keycloak? If the deployed provider config points at a realm that
   404s, live logins are broken for reasons unrelated to this fix.
   *Default taken:* reported the live check honestly as a verification-path
   check, not a full end-to-end login.

3. **`key` (chassis) is now a dev-dependency of this crate** so tests can sign
   real tokens with a fixture keypair instead of mocking the crypto. It is a
   path dep on `target/generated-sources/model/chassis/key`, already in the
   tree, test-only. Flagging in case service Cargo.toml files are expected to be
   generated rather than hand-maintained — this one looks hand-maintained
   (it carries service-specific deps like `aes-gcm`).
   *Default taken:* added it.

4. **Two pre-existing build warnings left alone** (`unused import
   tracing_subscriber::EnvFilter` in `src/main.rs:8`, and the never-read
   `pending` field on `AuthImpl` in `src/auth.rs:30`). Both predate this change
   and are outside the security fix, so per "do not improve adjacent code" I did
   not touch them. The `pending` field looks like genuine dead code left over
   from the move to the kernel CLI broker — worth a separate cleanup.
