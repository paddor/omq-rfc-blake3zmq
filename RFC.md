# BLAKE3ZMQ: Secure Transport for ZMQ Draft Sockets

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| Status      | Draft                                              |
| Editor      |                                                    |
| Replaces    | [RFC 26/CurveZMQ](https://rfc.zeromq.org/spec/26/) |
| Requires    | [RFC 37/ZMTP 3.1](https://rfc.zeromq.org/spec/37/) |

## 1. Abstract

BLAKE3ZMQ provides authenticated encryption and perfect forward secrecy for
ZMQ connections using X25519 key exchange, ChaCha20-BLAKE3 AEAD, and BLAKE3
key derivation. It targets ZMQ draft socket types (SERVER/CLIENT, RADIO/DISH,
GATHER/SCATTER) which use single-frame messages exclusively.

## 2. Goals

- Perfect forward secrecy via ephemeral Diffie-Hellman
- Replay immunity via ephemeral keys and transcript binding
- Channel binding via BLAKE3 transcript hash (chaining key)
- No NIST primitives -- DJB cryptography throughout
- Zero-copy encryption on both sender and receiver
- 32 bytes overhead per message (one BLAKE3 authentication tag)
- No negotiation, renegotiation, or re-keying
- Stateless server until client authentication (cookie mechanism)

## 3. Non-Goals

- Legacy multi-frame socket support (see Section 15)
- Cipher agility or version negotiation
- Post-quantum key exchange
- Re-keying within a connection

## 4. Primitives

| Primitive           | Parameters                | Purpose              |
|---------------------|---------------------------|----------------------|
| X25519              | 32-byte keys              | Diffie-Hellman       |
| ChaCha20-BLAKE3     | 32-byte key, 24-byte nonce, 32-byte tag | AEAD |
| BLAKE3              | Variable output           | Transcript hash      |
| BLAKE3-derive-key   | Context string + material | Key derivation       |

All primitives are constant-time. Implementations can take advantage of
SIMD acceleration (x86-64: AVX2/AVX-512; ARM: NEON/SVE).

## 5. Notation

| Symbol              | Meaning                                          |
|---------------------|--------------------------------------------------|
| `X25519(a, B)`      | ECDH: scalar multiply secret `a` by public `B`  |
| `Encrypt(k, n, pt, aad)` | ChaCha20-BLAKE3 AEAD encrypt              |
| `Decrypt(k, n, ct, aad)` | ChaCha20-BLAKE3 AEAD decrypt              |
| `KDF(ctx, ikm)`     | `BLAKE3-derive-key(ctx, ikm)` -> 32 bytes        |
| `KDF24(ctx, ikm)`   | `BLAKE3-derive-key(ctx, ikm)` truncated to 24 bytes |
| `H(input)`          | `BLAKE3(input)` -> 32 bytes                      |
| `a \|\| b`          | Concatenation                                    |
| `C, c`              | Client permanent public/secret key               |
| `S, s`              | Server permanent public/secret key               |
| `C', c'`            | Client ephemeral public/secret key               |
| `S', s'`            | Server ephemeral public/secret key               |
| `K`                 | Cookie key (short-lived server secret)           |

## 6. Key Types

| Key              | Lifetime     | Size     | Purpose                        |
|------------------|--------------|----------|--------------------------------|
| Server permanent | Long-lived   | 32 bytes | Server identity                |
| Client permanent | Long-lived or ephemeral | 32 bytes | Client identity       |
| Client ephemeral | One connection | 32 bytes | Forward secrecy              |
| Server ephemeral | One connection | 32 bytes | Forward secrecy              |
| Cookie key       | ~60 seconds  | 32 bytes | Stateless server trick         |

The server's permanent public key `S` MUST be distributed to clients out of
band before any connection.

## 7. ZMTP Integration

BLAKE3ZMQ is a ZMTP 3.1 security mechanism. The mechanism name in the ZMTP
greeting is `BLAKE3` (6 octets, null-padded to 20). The `as-server` field in
the greeting determines which peer is client and which is server.

The handshake consists of four ZMTP command frames, followed by a data phase
where ZMTP message frames carry encrypted application data.

In the wire format diagrams below, numbers in parentheses are **byte
counts**. The ZMTP command frame body begins with a 1-byte name length
followed by the ASCII command name (per ZMTP 3.1); the remaining bytes
are command-specific data. Total sizes include the name-length byte and
name.

## 8. Transcript Hash

A running hash `h` binds every handshake message to its predecessors:

```
h0 = H("BLAKE3ZMQ-1.0" || client_greeting || server_greeting)
h1 = H(h0 || HELLO_wire_bytes)
h2 = H(h1 || WELCOME_wire_bytes)
h3 = H(h2 || INITIATE_wire_bytes)
h4 = H(h3 || READY_wire_bytes)
```

`h0` includes both ZMTP greetings as a prologue, binding the mechanism
name, version, and `as-server` bits into the transcript. All subsequent
wire bytes include the ZMTP command header. This ensures both peers
agree on the exact bytes exchanged. Any tampering with any message —
including the greetings — causes all subsequent transcript hashes, and
all keys derived from them, to diverge.

## 9. Handshake

```
Client                                    Server
  |                                          |
  |--- HELLO (C', hello_box) --------------->|
  |                                          |
  |<-- WELCOME (welcome_box) ----------------|
  |                                          |
  |--- INITIATE (cookie, initiate_box) ----->|
  |                                          |
  |<-- READY (ready_box) --------------------|
  |                                          |
  |========= encrypted data phase ===========|
```

### 9.1 HELLO (Client -> Server)

Client generates a fresh ephemeral keypair `(C', c')`.

**Derived values:**

```
dh1         = X25519(c', S)
hello_key   = KDF("BLAKE3ZMQ-1.0 HELLO key", dh1)
hello_nonce = KDF24("BLAKE3ZMQ-1.0 HELLO nonce", C')
hello_box   = Encrypt(hello_key, hello_nonce, zeros(64), aad = "HELLO")
```

`hello_box` proves the client knows `S` without revealing anything else.
It encrypts 64 zero bytes so the server can verify decryption without
ambiguity. (The AEAD tag alone proves correct decryption; the zero bytes
follow CurveZMQ convention and may be reduced in a future revision.)

**Wire format (ZMTP command frame):**

```
+-------------+-----------+--------+-----------+-------------+
| 0x05        | version   | C'     | padding   | hello_box   |
| "HELLO"     | (2 bytes) | (32)   | (64)      | (96)        |
| (6 bytes)   | 0x01,0x00 |        | zeros     |             |
+-------------+-----------+--------+-----------+-------------+
```

Total command body: 6 + 2 + 32 + 64 + 96 = 200 bytes.

The 64-byte padding ensures HELLO (200 bytes) >= WELCOME (192 bytes),
preventing amplification attacks where a small forged HELLO triggers a
large WELCOME response.

**Server processing:**

1. Compute `dh1 = X25519(s, C')`. Abort if `dh1` is all zeros.
2. Derive `hello_key` and `hello_nonce` as above.
3. Decrypt `hello_box`. If decryption fails, silently drop (do not respond).
4. Update transcript: `h1 = H(h0 || HELLO_wire_bytes)`.

### 9.2 WELCOME (Server -> Client)

Server generates a fresh ephemeral keypair `(S', s')`.

**Cookie construction:**

The cookie allows the server to remain stateless until INITIATE. It
encrypts the server's ephemeral secret key and the client's ephemeral
public key under a short-lived cookie key `K`.

```
cookie_nonce = random(24)
cookie_key   = KDF("BLAKE3ZMQ-1.0 cookie", K)
cookie_box   = Encrypt(cookie_key, cookie_nonce, C' || s', aad = "COOKIE")
cookie       = cookie_nonce || cookie_box
```

Cookie size: 24 + 64 + 32(tag) = 120 bytes.

The cookie nonce MUST be random because `K` is shared across connections.
After creating the cookie, the server MAY discard `s'` and all connection
state. The cookie key `K` MUST be rotated at least every 60 seconds.
Implementations MUST NOT reuse a cookie key indefinitely. The rotation
interval SHOULD NOT be shorter than the maximum expected HELLO-to-INITIATE
round-trip time; otherwise clients on high-latency links will see
persistent handshake failures as their cookies are invalidated before
they can be returned.

**Welcome box:**

```
welcome_key   = KDF("BLAKE3ZMQ-1.0 WELCOME key", dh1)
welcome_nonce = KDF24("BLAKE3ZMQ-1.0 WELCOME nonce", h1)
welcome_box   = Encrypt(welcome_key, welcome_nonce, S' || cookie, aad = "WELCOME")
```

Note: `welcome_key` uses `dh1` (same DH as HELLO) but a different KDF
context string, producing an independent key.

**Wire format (ZMTP command frame):**

```
+---------------+------------------+
| 0x07          | welcome_box      |
| "WELCOME"     | (184 bytes)      |
| (8 bytes)     |                  |
+---------------+------------------+
```

Welcome box: 32(S') + 120(cookie) + 32(tag) = 184 bytes.
Total command body: 8 + 184 = 192 bytes.

**Client processing:**

1. Derive `welcome_key` and `welcome_nonce` from `dh1` and `h1`.
2. Decrypt `welcome_box` to obtain `S'` and `cookie`.
3. Update transcript: `h2 = H(h1 || WELCOME_wire_bytes)`.

### 9.3 INITIATE (Client -> Server)

**Derived values:**

```
dh2 = X25519(c', S')    # ephemeral-ephemeral (forward secrecy)
dh3 = X25519(c, S')     # client-permanent x server-ephemeral (vouch)
```

**Vouch:**

The vouch proves the client owns `C` and binds its identity to this session.

```
vouch_key   = KDF("BLAKE3ZMQ-1.0 VOUCH key", dh3)
vouch_nonce = KDF24("BLAKE3ZMQ-1.0 VOUCH nonce", dh3)
vouch_box   = Encrypt(vouch_key, vouch_nonce, C' || S, aad = "VOUCH")
```

Vouch size: 32(C') + 32(S) + 32(tag) = 96 bytes.

The vouch is unforgeable (requires `c`), unreplayable (bound to `S'`
which is ephemeral), and binds the client's ephemeral key `C'` to its
permanent identity `C`.

Clients without pre-existing permanent keys MUST generate an ephemeral
permanent keypair for the connection. The wire format is always identical.

**Initiate box:**

```
initiate_key       = KDF("BLAKE3ZMQ-1.0 INITIATE key", dh2 || h2)
initiate_nonce     = KDF24("BLAKE3ZMQ-1.0 INITIATE nonce", dh2 || h2)
initiate_plaintext = C || vouch_box || metadata
initiate_box       = Encrypt(initiate_key, initiate_nonce, initiate_plaintext, aad = "INITIATE")
```

**Wire format (ZMTP command frame):**

```
+---------------+---------------+------------------+
| 0x08          | cookie        | initiate_box     |
| "INITIATE"    | (120 bytes)   | (variable)       |
| (9 bytes)     |               |                  |
+---------------+---------------+------------------+
```

Initiate box: 32(C) + 96(vouch) + metadata + 32(tag) = 160 + metadata bytes.

**Server processing:**

1. Decrypt cookie using `K` to recover `C'` and `s'`.
2. Compute `dh2 = X25519(s', C')`. Abort if `dh2` is all zeros.
3. Derive `initiate_key` and `initiate_nonce`.
4. Decrypt `initiate_box`.
5. Compute `dh3 = X25519(s', C)`. Abort if `dh3` is all zeros. Verify vouch.
6. If an authenticator is configured, check `C` against authorized keys. The server MAY reject unknown clients with an ERROR command.
7. Update transcript: `h3 = H(h2 || INITIATE_wire_bytes)`.

### 9.4 READY (Server -> Client)

```
ready_key   = KDF("BLAKE3ZMQ-1.0 READY key", dh2 || h3)
ready_nonce = KDF24("BLAKE3ZMQ-1.0 READY nonce", dh2 || h3)
ready_box   = Encrypt(ready_key, ready_nonce, metadata, aad = "READY")
```

**Wire format (ZMTP command frame):**

```
+-------------+------------------+
| 0x05        | ready_box        |
| "READY"     | (variable)       |
| (6 bytes)   |                  |
+-------------+------------------+
```

Ready box: metadata + 32(tag) bytes.

**Client processing:**

1. Derive `ready_key` and `ready_nonce`.
2. Decrypt `ready_box` to obtain server metadata.
3. Update transcript: `h4 = H(h3 || READY_wire_bytes)`.

### 9.5 ERROR (Server -> Client)

At any point during the handshake, the server MAY send an ERROR command
instead of the expected response:

```
+-------------+------------------+
| 0x05        | reason           |
| "ERROR"     | (1 + N bytes)    |
| (6 bytes)   |                  |
+-------------+------------------+
```

Where reason is a length-prefixed ASCII string (0-255 bytes). The client
MUST close the connection upon receiving ERROR.

## 10. Data Phase

### 10.1 Key Derivation

After READY, both peers derive directional session keys from the final
transcript hash and the ephemeral DH secret:

```
c2s_key   = KDF("BLAKE3ZMQ-1.0 client->server key",   h4 || dh2)
c2s_nonce = KDF24("BLAKE3ZMQ-1.0 client->server nonce", h4 || dh2)

s2c_key   = KDF("BLAKE3ZMQ-1.0 server->client key",   h4 || dh2)
s2c_nonce = KDF24("BLAKE3ZMQ-1.0 server->client nonce", h4 || dh2)
```

Each direction gets a Session initialized with `(key, nonce)`. The
Session manages per-message nonce derivation internally via a monotonic
counter (see Section 10.2).

### 10.2 Session Nonce Derivation

Each Session splits its 24-byte initial nonce into:

```
nonce_prefix = nonce[0, 16]     # 16 bytes (offset 0, length 16), fixed for session lifetime
counter_base = nonce[16, 8]     # 8 bytes (offset 16, length 8), little-endian u64
```

For message index `i` (starting at 0), the per-message nonce is:

```
message_nonce = nonce_prefix || to_le64(wrapping_add(counter_base, i))
```

This produces 2^64 unique nonces per session. Implementations MUST close
the connection if the counter reaches 2^64. Nonce reuse under the same
key is catastrophic for any stream cipher.

### 10.3 Wire Format

Each message is a single ZMTP message frame (not a command frame):

```
+-----------+----------------+------------------+-----------+
| flags     | length         | ciphertext       | tag       |
| (1 byte)  | (1 or 8 bytes) | (N bytes)        | (32 bytes)|
+-----------+----------------+------------------+-----------+
             |<---------- length = N + 32 ------------------>|
```

- `flags`: Standard ZMTP 3.1 flags byte. MORE bit (bit 0) MUST be zero
  (single-frame messages only). COMMAND bit (bit 2) MUST be zero.
- `length`: Ciphertext length + 32 (tag size). Encoded as 1 byte (short)
  or 8 bytes (long) per ZMTP 3.1.
- `ciphertext`: The encrypted message payload.
- `tag`: 32-byte BLAKE3 authentication tag.

The `flags` byte is used as additional authenticated data (AAD) for the
AEAD operation. This binds the frame type to the ciphertext, preventing
an attacker from flipping flag bits (e.g. MORE, COMMAND) without
detection.

No counter is sent on the wire. Both peers maintain synchronized internal
counters. TCP guarantees ordered delivery; if the connection breaks, both
peers discard the session.

### 10.4 Sender (Zero-Copy)

```
1. encrypt_in_place_detached(plaintext_buffer)
   -> ciphertext overwrites plaintext in same buffer
   -> tag returned as 32 bytes (stack-allocated)

2. Construct ZMTP header: flags + length(payload_len + 32)

3. writev([header, ciphertext_buffer, tag])
   -> single syscall, no copy
```

### 10.5 Receiver (Zero-Copy)

```
1. Read ZMTP header -> learn total length L.

2. read(L, buffer) -> single allocation, exact size.

3. Split: ciphertext = buffer[0 .. L-32], tag = buffer[L-32 .. L]

4. decrypt_in_place_detached(ciphertext, tag)
   -> plaintext overwrites ciphertext in same buffer
   -> raises error if authentication fails

5. Shrink buffer logical size by 32 bytes.
   -> application receives the buffer directly
```

If decryption fails, the Session counter is NOT advanced. The peer MUST
close the connection.

## 11. Overhead

| Per message          | Bytes |
|----------------------|-------|
| ZMTP frame header    | 1-9   |
| Authentication tag   | 32    |
| Counter on wire      | 0     |
| **Total overhead**   | **33-41** |

Compared to CurveZMQ:

| | BLAKE3ZMQ | CurveZMQ |
|---|---|---|
| Tag size | 32 bytes | 16 bytes |
| Counter on wire | 0 bytes | 8 bytes |
| Command wrapper | none | 17 bytes ("MESSAGE" + padding) |
| **Per-message overhead** | **32 bytes** | **41 bytes** |

BLAKE3ZMQ has 9 bytes less overhead per message despite a larger tag.

## 12. Authentication Modes

The INITIATE box always contains `C || vouch_box || metadata`. The wire
format is identical regardless of authentication mode. The authentication
mode is determined by server configuration (whether an authenticator is
present), not negotiated on the wire.

The server MUST always verify the vouch cryptographically.

### 12.1 Server-Only Mode

The server has a permanent keypair `(S, s)`. Clients without pre-existing
permanent keys generate an ephemeral permanent keypair for the connection.
The server verifies the vouch but does not check `C` against an allowlist.

The server authenticates to the client (the client verified `S` via the
HELLO box). The client's identity is ephemeral and not meaningful for
authorization.

### 12.2 Mutual Authentication

Both peers have long-lived permanent keypairs. The client's permanent
public key `C` and vouch are sent inside the INITIATE box, encrypted
under the ephemeral session keys.

The server verifies the vouch and checks `C` against its set of authorized
client keys. The server MAY reject unknown clients with an ERROR command.

The client's permanent public key is never sent in cleartext -- it is
protected by the ephemeral key exchange.

## 13. Security Properties

| Property | Mechanism |
|---|---|
| Confidentiality | ChaCha20-BLAKE3 AEAD |
| Integrity | 32-byte BLAKE3 tag per message |
| Perfect forward secrecy | Data keys derived from ephemeral DH (`dh2 = X25519(c', S')`) |
| Replay immunity | Ephemeral keys unique per connection; transcript hash binds all messages |
| Channel binding | Transcript hash `h4` mixed into data-phase key derivation |
| No reflection attacks | Separate keys per direction (client->server != server->client) |
| Identity protection | Client permanent key encrypted under ephemeral keys |
| Anti-amplification | HELLO (200 bytes) >= WELCOME (192 bytes) |
| Stateless server | Cookie mechanism; no per-connection state until INITIATE |
| Nonce misuse resistance | Nonces derived deterministically from DH and transcript; no randomness needed after ephemeral key generation |
| Low-order point rejection | All DH outputs MUST be checked for all-zero value; abort on detection |
| Frame flag integrity | Flags byte authenticated as AAD; prevents bit-flip attacks on frame type |
| Cookie key rotation | Cookie key K rotated every 60s; limits forward secrecy exposure window |

### 13.1 What BLAKE3ZMQ Does NOT Protect

- **Message size**: The total encrypted message size is visible in the ZMTP
  length field. Traffic analysis based on message sizes is possible.
- **Timing**: Message timing is visible to a network observer.
- **Endpoint identity**: IP addresses and ports are visible.
- **Denial of service**: An attacker can drop or corrupt TCP segments,
  causing connection failure.

## 14. Metadata

Both INITIATE and READY carry a metadata block. Metadata is encoded as a
sequence of name-value properties:

```
+----------+------+-----------+-------+
| name-len | name | value-len | value |  (repeated)
| (1)      | (N)  | (4, BE)   | (M)   |
+----------+------+-----------+-------+
```

- `name-len`: 1 byte, length of property name (1-255).
- `name`: ASCII string, case-insensitive.
- `value-len`: 4 bytes, big-endian, length of property value (0 to 2^31-1).
- `value`: Opaque bytes.

Standard properties:

| Name       | Value                        |
|------------|------------------------------|
| `Socket-Type` | ZMQ socket type (e.g. "CLIENT", "SERVER") |
| `Identity` | Socket identity (0-255 bytes) |

Implementations MUST ignore unknown properties.

## 15. Future Work: Legacy Socket Support

A future RFC MAY extend BLAKE3ZMQ to legacy socket types (REQ/REP,
ROUTER/DEALER, PUB/SUB, PUSH/PULL, etc.) which use multi-frame messages.

The recommended approach: the security mechanism collapses outgoing
multi-frame messages into a single encrypted blob and reconstructs frames
on the receiver side. The blob contains a serialized frame sequence:

```
[frame1_len (8 bytes LE)] [frame1_data] [frame2_len (8 bytes LE)] [frame2_data] ...
```

This approach:

- Requires a sender-side memcpy to serialize frames into one buffer
- Uses one AEAD operation per message (not per frame)
- Hides frame count and individual frame sizes from observers
- Is transparent to the socket type -- no application changes required
- Enables zero-copy on the receiver via sub-buffer referencing:
  `String#byteslice` on a frozen backing buffer (Ruby),
  `ByteBuffer.slice()` (Java), `memoryview` (Python),
  or pointer arithmetic (C/C++)

## 16. Constants

```
KEY_SIZE        = 32    # bytes
NONCE_SIZE      = 24    # bytes
TAG_SIZE        = 32    # bytes
COOKIE_SIZE     = 120   # bytes (24 nonce + 64 payload + 32 tag)
MECHANISM_NAME  = "BLAKE3"
PROTOCOL_ID     = "BLAKE3ZMQ-1.0"
```

## 17. References

- [RFC 26/CurveZMQ](https://rfc.zeromq.org/spec/26/) -- predecessor protocol
- [RFC 37/ZMTP 3.1](https://rfc.zeromq.org/spec/37/) -- underlying transport
- [X25519 (RFC 7748)](https://tools.ietf.org/html/rfc7748) -- Diffie-Hellman
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) -- hash function and KDF
- [The Noise Protocol Framework](https://noiseprotocol.org/noise.html) -- inspiration for transcript hash pattern
- [ChaCha20-BLAKE3 AEAD](https://github.com/skerkour/chacha20-blake3) -- AEAD construction combining ChaCha20 and BLAKE3
- [ChaCha20-BLAKE3: Secure, Simple and Fast](https://kerkour.com/chacha20-blake3) -- design rationale for ChaCha20-BLAKE3
