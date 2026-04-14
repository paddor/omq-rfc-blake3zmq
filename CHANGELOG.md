# Changelog

## Unreleased

- Test suite updated for omq 0.20 socket API (`linger` setter, positional
  endpoint arg, `SUB#subscribe` replacing `subscribe:` on `#connect`).
  XPUB/XSUB integration test now uses `subscriber_joined.wait` after a
  raw `\x01` data-frame subscription.

## 0.2.0 — 2026-04-07

- Replace `[Async {}].each(&:wait)` with `Barrier` in tests.
- YARD documentation on all public methods and classes.
- Code style: expand `else X` one-liners, two blank lines between methods
  and constants.
- Add socket-level integration tests (PUSH/PULL, REQ/REP, PUB/SUB,
  XPUB/XSUB, multipart messages, multiple clients).

- **Breaking:** API is now kwargs-only:
  `Blake3.server(public_key:, secret_key:)` and
  `Blake3.client(server_key:)`. Client keys are optional — when omitted,
  an ephemeral permanent keypair is auto-generated. INITIATE always
  contains `C + vouch + metadata` (server-only mode with different wire
  format is removed).
- **Breaking:** Authenticator now receives a `Protocol::ZMTP::PeerInfo`
  (with a `crypto::PublicKey`) via `#call` (no more `#include?` duck-typing)
- Default `crypto:` kwarg to built-in `OMQ::Blake3ZMQ::Crypto` backend
- RFC updated: INITIATE wire format is now always `C || vouch || metadata`,
  clients without permanent keys auto-generate ephemeral identity
- Add Nuckle custom crypto backend test (demonstrates backend pluggability)
- Security audit fixes:
  - Authenticate ZMTP frame flags as AAD in data phase encrypt/decrypt
  - Validate all X25519 DH outputs are non-zero (low-order point rejection)
  - Bind ZMTP greetings into transcript hash h0 (prologue)
- Add `#maintenance` for automatic cookie key rotation (60s interval)
- Rename gem to `omq-rfc-blake3zmq` (require `"omq/rfc/blake3zmq"`)
- Ship built-in crypto backend (`OMQ::Blake3ZMQ::Crypto`) with
  x25519 (native C) key types — gem works out of the box
- Add x25519 as runtime dependency
- Remove nuckle dependency from tests and benchmarks
- RFC updates:
  - Cookie key rotation: SHOULD → MUST, with high-latency caveat
  - Data phase nonces: KDF → KDF24 for consistency
  - Nonce slice notation: use offset+length for clarity
  - Document flags-as-AAD and DH zero check requirements
  - Add greeting prologue to transcript hash specification
- Initial implementation: BLAKE3ZMQ security mechanism for ZMTP 3.1
