# Followup: CLI login nonce binding (Critical #2)

Scope of this note: what is left *after* the kernel-side half of Critical #2 was fixed. It exists
because the remaining work is in `oauth` code, and the kernel fix was made under a
do-not-touch-oauth-code constraint.

## What was fixed in kernel

`CliTokenBrokerServiceImpl.brokerStream` / `REGISTER_NONCE` no longer last-write-wins. The
registration is now a `putIfAbsent` into the `cli-token-broker` IMap: the first registration for a
nonce owns it, a second registration for a live nonce is refused with a warning, and only an
*expired* registration is replaced (kernel nodes can disagree on expiry by their clock skew, so a
dead entry must not pin the nonce until its TTL lapses).

Test: `CliTokenBrokerServiceImplTest.duplicateNonceRegistrationFromAnotherInstanceIsRejected` —
two oauth instances register the same nonce; the second is rejected and the eventual token still
delivers to the first registrant's stream, not the second's.

This is not redundant with the oauth-side `pending`-map fix. `OauthImpl::pending` is **per-process**
(`src/service.rs:155`), so it cannot see a duplicate registration that lands on a *different* oauth
instance. Kernel's IMap is the only place in the flow where both registrations are visible. The two
fixes cover different halves of the same attack:

| Attacker's session lands on | Caught by |
| --- | --- |
| the same oauth instance as the victim | oauth `pending` first-wins check |
| a different oauth instance | kernel `REGISTER_NONCE` `putIfAbsent` (this fix) |

## What kernel deliberately did NOT change, and why

The audit's third angle — `COMPLETE_NONCE` "only checks that *some* valid token was presented, not
that the presenter opened that specific session" — **cannot be fixed inside kernel.** Findings from
reading the RPC path:

1. `BrokerStream` is already authenticated and authorized fail-closed to one caller service. The
   generated wrapper registers `authorizer.setMethodAuth("BrokerStream", List.of("oauth"))`
   (`tacplus/.../servers/services/kernel/CliTokenBroker.java`), and `Authorizer.authorizeWithToken`
   matches that allowlist against the caller's location-agnostic `servicePath`, throwing
   `PERMISSION_DENIED` when no policy matches. So the only principal that can send *any* broker
   message — `REGISTER_NONCE` or `COMPLETE_NONCE` — is the `oauth` service itself. The end user's
   token never reaches kernel on this path.
2. Consequently the `Caller` parameter on `brokerStream` carries no identity kernel could bind a
   nonce to. It resolves to the oauth service for every message on every stream. Binding a nonce to
   the registrant's `Caller.getSubject()` and requiring a match at completion — the
   `FencedLockServiceImpl.verifiedHolderId` pattern used elsewhere in kernel — would either be a
   no-op (all oauth instances share the service identity) or would break the documented design, in
   which "CompleteNonce … [is] sent by any oauth instance after browser auth completes"
   (`services/kernel.proto`): the browser callback legitimately lands on a different instance than
   the CLI session did.
3. The two parties are also genuinely different principals by design. The registrant is an
   *unauthenticated* CLI session (`broker_session`'s no-bearer branch); the completer is an
   authenticated browser user. There is no shared identity for kernel to compare. The device-flow
   security property is therefore "the token goes to whoever holds the device code, first claim
   wins" — which is exactly what the `putIfAbsent` fix now enforces — not "requester identity ==
   claimant identity".

## Remaining change needed, in `oauth`

`broker_cli_auth` (`src/auth.rs:546-625`) authenticates the caller and takes their `sub`, then sends
`CompleteNonce { nonce: req.session_id, subject, claims }` with `req.session_id` **taken verbatim
from the request and never checked against oauth's own session state**. Any authenticated user can
therefore complete any pending `session_id` they know.

Needed (oauth-side; kernel needs no further change):

1. **Reject a `session_id` this instance has no pending session for.** Before sending
   `COMPLETE_NONCE`, check `self.pending` for `req.session_id` and return
   `NOT_FOUND`/`PERMISSION_DENIED` if absent. This alone closes the "unrelated authenticated user
   completes someone else's nonce" angle for same-instance sessions. Note it does *not* close it
   across instances, because `pending` is per-process — see item 3.
2. **Make the `pending` insert first-wins** (`src/service.rs:155-156`, the sibling half of this
   finding): `if self.pending.read().await.contains_key(&session_id) { return
   Err(Status::already_exists(...)) }` or an equivalent `Entry`-style guarded insert, so a second
   CLI session cannot claim a live `session_id`.
3. **Decide the cross-instance story for (1).** With `pending` per-process, an attacker's
   `broker_cli_auth` landing on instance B cannot be validated against a session pending on
   instance A, so a naive version of (1) either rejects legitimate cross-instance completions or
   must be skipped when the session is not local. Two workable shapes:
   - Ask kernel: add an RPC (or a new broker request message) that answers "is nonce N registered
     and unconsumed?" so any oauth instance can validate a `session_id` against the IMap that
     already holds every registration. Kernel-side work, needs a proto change.
   - Or accept that (1) is best-effort same-instance and rely on the nonce remaining secret plus
     first-claim-wins (items 1+2 and the kernel fix) for the rest. This is the standard
     device-flow posture and requires no proto change.

   Recommendation: the second, unless the audit wants a stronger property than OAuth device flow
   itself provides. The nonce's secrecy is load-bearing either way, which makes the next item the
   higher-value follow-on.
4. **Separately worth reviewing:** the nonce doubles as both the CLI's wait key and the value
   carried in the browser login URL, so it is "visible to anyone who observes that URL" per the
   audit. Splitting it into a secret device code (CLI-held, never in a URL) and a distinct user
   code (in the URL) would remove the observability premise the whole finding rests on. Larger
   change across CLI + oauth + kernel proto; out of scope for this finding's fix, but it is the
   structural answer.
