# OAuth Downstream Progress

## 2026-06-16

- Regenerated OAuth generated sources with tacplus `v1.2.214` using local
  tagged binary `/Users/jody/workspace/schematic/tacplus/target/tacplus-v1.2.214`.
- Synced the embedded `proto` checkout to `origin/main` at `d62474c` before
  regeneration so the proto source uses the current `(spec.smb) = {}` option
  shape.
- Adapted OAuth source to the current generated RPC names:
  `mint_callback_tokens`, `revoke_session`, `broker_cli_auth`,
  `mint_token`, and `broker_session`.
- Added BrokerStream registration logging around the on-connect send path so
  failed registration enqueue is visible in service logs.
- Verification: `cargo check` passed after regeneration. Remaining warnings
  are existing dead-code warnings in generated/client and OAuth state fields.
