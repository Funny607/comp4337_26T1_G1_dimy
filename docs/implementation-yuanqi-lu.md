# Yuanqi Lu Implementation Details

## 1. Scope

This part implements the frontend protocol core, including EphID generation, Shamir Secret Sharing, UDP-based share exchange, EphID reconstruction, Encounter ID derivation, and the DBF/QBF scheduling pipeline.

The implementation mainly covers:

* `src/crypto_utils.py`
* `src/shamir_utils.py`
* `src/network_udp.py`
* `src/Dimy.py`
* `src/dbf_manager.py`

## 2. `crypto_utils.py`

### Purpose

This module contains the cryptographic primitives used by the DIMY node. It does not manage sockets, threads, Bloom filter scheduling, or protocol state.

### Implementation method

#### EphID design

The implementation uses the raw 32-byte X25519 public key as the EphID.

This design was chosen for two reasons:

1. The EphID is required to be 32 bytes.
2. The next protocol step requires Diffie-Hellman key exchange.

Using the X25519 public key directly as EphID avoids extra conversion logic and makes the transition from EphID reconstruction to EncID derivation straightforward.

#### Hash verification

Each EphID is hashed with SHA-256. The hash is advertised alongside the shares and used after reconstruction to verify that the recovered EphID is correct.

#### EncID derivation

After reconstructing a peer EphID, the node loads it as an X25519 public key and performs Diffie-Hellman using the local private key. The resulting shared secret is then processed using HKDF-SHA256 to derive a stable 32-byte EncID.

To ensure that both peers derive the same EncID, the local and peer EphID hashes are normalized and ordered before being placed into the HKDF context.

## 3. `shamir_utils.py`

### Purpose

This module implements the `k`-out-of-`n` Shamir Secret Sharing logic used to split and reconstruct EphIDs.

### Implementation method

#### Secret representation

The secret is treated as a byte string. For a 32-byte EphID, the implementation processes each byte position independently.

#### Finite field choice

The implementation uses arithmetic in `GF(257)`.

This allows every original byte value `0..255` to be represented safely as the constant term of a polynomial, while still allowing interpolation over a small prime field.

#### Share generation

For each byte in the secret:

1. The byte is used as the constant term.
2. `k - 1` random coefficients are generated.
3. The polynomial is evaluated at `x = 1..n`.

Each share stores one y-value for each byte position. Since values in `GF(257)` can range from `0` to `256`, each value is encoded using 2 bytes.

#### Reconstruction

When at least `k` distinct shares are available, Lagrange interpolation at `x = 0` is used to recover the constant term for each byte position. These recovered bytes are then combined into the original EphID.

#### Share serialization

To make the share transport-safe for JSON-based UDP messages, each share is serialized into a string of the form:

```text
<index>:<base64url_encoded_payload>
```

This allows `Dimy.py` to place the share directly into a UDP packet without additional binary encoding logic.

## 4. `network_udp.py`

### Purpose

This module handles UDP-based share transport between nodes.

It is intentionally kept separate from the cryptographic and protocol logic so that the network layer can be tested independently.

### Implementation method

#### Thin transport design

`UDPShareTransport` is implemented as a thin wrapper around Python UDP sockets.

It is responsible only for:

* sending JSON packets
* receiving JSON packets
* simulating receiver-side packet drops
* optionally ignoring packets sent by the same node

It does not attempt reconstruction, hashing, or Bloom filter updates.

#### Sending

Outgoing packets are JSON dictionaries encoded to UTF-8 bytes and transmitted to the configured UDP target endpoint.

#### Receiving

A background receive thread is started by `start()`. The receive loop continuously reads incoming UDP packets, decodes them as JSON, applies self-packet filtering, applies the probabilistic drop mechanism, and finally passes valid packets to the `on_packet` callback.

#### Drop mechanism

The drop mechanism is implemented on the receiver side using:

```python
random.random() < drop_prob
```

If the packet is dropped, it is discarded before the protocol logic sees it.

This directly simulates intermittent proximity loss between nodes.

## 5. `dbf_manager.py`

### Purpose

This module manages the Task 6 to Task 8 Bloom filter pipeline.

### Implementation method

#### Bloom filter structure

A `BloomFilter` class is used with:

* 100 KB filter size
* 3 hash functions

Each item is mapped to 3 bit positions derived from SHA-256.

#### DBF scheduling

A DBF window lasts `t * 6` seconds.

`DBFManager` uses time-based window IDs to decide which DBF is currently active. When the current window changes, a new DBF is created automatically.

#### Retention rule

At most 6 DBFs are kept. Older DBFs are removed either because they are outside the retention period or because the maximum DBF count has been exceeded.

#### QBF generation

Every `Dt = t * 6 * 6` seconds, all currently retained DBFs are merged bitwise into a new QBF.

The QBF is cached for the current period and only regenerated when the period changes or when forced explicitly.

#### CBF generation

For Task 9 integration, `build_cbf()` merges all retained DBFs into a single Bloom filter suitable for upload to the backend server.

## 6. `Dimy.py`

### Purpose

This is the frontend protocol controller. It connects the cryptographic, secret sharing, UDP, and Bloom filter components into one running DIMY node.

### Implementation method

#### State model

The node maintains three main categories of state:

1. **Local epoch state**

   * current and recent EphIDs
   * local private keys
   * generated shares

2. **Peer share buffers**

   * shares received from peers
   * tracked by `(epoch_id, ephid_hash, sender_id)`

3. **Encounter history**

   * a set of EncIDs already processed
   * prevents duplicate insertion into the DBF

#### Epoch alignment

The node computes:

```python
epoch_id = int(time.time() // t)
```

This ensures that nodes using the same `t` value rotate EphIDs on the same time boundaries.

Using a globally aligned epoch also makes it easy to select the correct local private key when reconstructing a peer EphID from the same epoch.

#### Local EphID generation

For each epoch:

1. Generate a fresh X25519 key pair.
2. Treat the public key bytes as the EphID.
3. Compute the SHA-256 hash of the EphID.
4. Split the EphID into `n` Shamir shares.

#### Share broadcasting

The node sends one share every 3 seconds. Shares are sent in cyclic order across the current epoch.

Each UDP share packet contains:

* packet type
* sender ID
* epoch ID
* EphID hash
* `k`
* `n`
* serialized share
* timestamp

#### Share reception and buffering

When a share packet arrives:

1. The serialized share is decoded.
2. A peer buffer is selected using `(epoch_id, ephid_hash, sender_id)`.
3. Duplicate share indices are ignored.
4. Distinct shares are counted.

Once at least `k` distinct shares are available, the node attempts reconstruction.

#### EphID reconstruction

The node reconstructs the peer EphID from the first `k` distinct shares in the buffer. The reconstructed EphID is then verified using the advertised SHA-256 hash.

If verification fails, the reconstructed value is discarded.

#### EncID generation

If verification succeeds, the node uses the local private key from the matching epoch and the reconstructed peer EphID to derive a shared EncID.

The EncID is deduplicated using an in-memory set before further processing.

#### DBF insertion

After a new EncID is derived:

1. It is inserted into the current DBF.
2. Metadata is emitted for testing or higher-level integration.
3. The EncID is treated as transient state and not stored separately outside the Bloom filter pipeline.

#### QBF scheduling

A dedicated scheduler loop periodically:

* checks whether the DBF window must rotate
* checks whether a new QBF period has started
* builds a QBF when needed
* exposes the latest QBF through a getter and optional callback

## 7. Testing

This part includes unit and integration tests.

### `tests/test_crypto.py`

Tests:

* EphID generation shape
* EphID hash verification
* X25519 key serialization
* symmetric EncID derivation
* invalid input handling

### `tests/test_shamir.py`

Tests:

* correct number of shares
* reconstruction from any valid subset of size `k`
* duplicate index rejection
* invalid parameter rejection
* serialization and deserialization

### `tests/test_udp_messages.py`

Tests:

* packet encoding and decoding
* local UDP send/receive
* drop probability behavior
* self-packet ignoring
* invalid payload rejection

### `tests/test_end_to_end.py`

Tests:

* two nodes deriving the same EncID from exchanged shares
* duplicate shares not being counted twice
* hash mismatch preventing encounter derivation
* duplicate encounters not being inserted again

### `tests/test_dbf_manager.py`

Tests:

* encounter insertion into DBF
* DBF rotation timing
* maximum of 6 retained DBFs
* QBF generation from multiple DBFs

### `tests/test_task6_8_flow.py`

Tests:

* EncID insertion into DBF after successful reconstruction
* QBF containing encounters from multiple DBFs

## 8. Summary

This part provides the core protocol pipeline required before backend upload and attacker analysis:

* EphID generation
* Shamir share creation and reconstruction
* UDP-based share communication with probabilistic drops
* Diffie-Hellman based EncID derivation
* DBF insertion and scheduling
* QBF generation

These components form the frontend core that later connects to Task 9 and Task 10 backend communication.
