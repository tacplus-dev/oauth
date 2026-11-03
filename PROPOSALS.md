# Proposals: oauth

Written by loopers. Each proposal: what, why, links. Jody promotes accepted ones into ROADMAP.md (via an agent);
the looper then marks it `promoted` or `declined` here with the date.

## Open
- **Authorize by stable provider key** (2026-10-27, #11): the sign-in state now names its provider by key, but
  `AuthorizeRequest.provider_index` is still the index ListProviders gave. If a tenant is deleted or edits its slice
  between the two calls, the index can name another provider, and the person is sent to that IdP (its allowlist
  still applies). Proposal: an additive `ProviderInfo.key` / `AuthorizeRequest.provider_key` in oauth.proto, which
  the webapp would send. That is a public contract change, so it is not made here.
- **ROADMAP.md "Now" line: tacplus floor 2.5** (2026-10-29, #13): the floor moved to 2.5 in tacplus.yaml and
  STATE.md, but ROADMAP.md's "Now" line still says "tacplus floor 2.4". The looper may not change ROADMAP.md (its
  push is refused); an agent changes that line at Jody's request.
- **looper-trace cannot see oauth's kernel calls** (2026-11-03, #16): the Auth handlers now reach kernel through
  the `Kernel` seam in src/auth.rs (`self.kernel.mint_user_token`, `self.kernel.broker_send`), so a handler test can
  run them against a recording kernel. `looper-trace check` reads only direct calls on a generated client, so it
  lists no handler here (`verdict: pass (0 handlers)`); it never saw the `BrokerStreamBidiHandle` sends either.
  The handler tests (`entra_signin_tests::the_callback_trace_id_arrives_on_*`) are the real check. Proposal, for
  tacplus-dev/looper: let looper-trace follow a call through a trait object whose implementation calls a generated
  client, or a send on a generated bidi handle, so the nightly scan sees these again.

## Promoted / declined
