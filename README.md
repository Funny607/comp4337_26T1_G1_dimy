# COMP4337 Assignment - DIMY Protocol Implementation

## Repository Overview

This repository contains our Python implementation of the DIMY protocol for the COMP4337/9337 Fixed and Wireless Network Security assignment.

The project is organized by functional modules so that the front-end node, back-end server, attacker node, testing scripts, and documentation can be developed in parallel and integrated cleanly.

---

## Team Responsibility Mapping

### Yuanqi Lu

Responsible for front-end node communication and cryptographic encounter generation:

* `src/Dimy.py`
* `src/shamir_utils.py`
* `src/network_udp.py`
* `src/crypto_utils.py` (EphID / Diffie-Hellman related logic)
* `src/dbf_manager.py`

### Emrik Moe

Responsible for Bloom Filter storage and back-end communication:

* `src/bloom.py`
* `src/DimyServer.py`
* `src/network_tcp.py`

### Xin Zhang

Responsible for attack implementation, execution workflow, and submission materials:

* `src/Attacker.py`
* `scripts/test_runner.sh`
* `docs/runbook.md`
* `docs/AssignmentReport.pdf`
* `docs/demo-plan.md`

---

## Core Files

### `src/Dimy.py`

Main DIMY client node.

Expected responsibilities:

* Parse command-line arguments.
* Generate EphID every `t` seconds.
* Split EphID into `n` Shamir shares with threshold `k`.
* Broadcast one share every 3 seconds using UDP.
* Receive shares from other nodes.
* Apply packet dropping probability `p`.
* Reconstruct peer EphID after collecting at least `k` shares.
* Verify reconstructed EphID using hash comparison.
* Derive EncID using Diffie-Hellman.
* Insert EncID into the active DBF.
* Periodically rotate DBFs.
* Build and send QBF/CBF to the back-end server.

### `src/DimyServer.py`

Back-end TCP server.

Expected responsibilities:

* Listen on TCP port 55000.
* Receive uploaded CBFs from positive nodes.
* Store received CBFs.
* Receive QBFs from querying nodes.
* Match QBF against stored CBFs.
* Return `matched` or `not matched`.

### `src/Attacker.py`

Attacker implementation for Task 11.

Expected responsibilities:

* Listen to node UDP broadcasts.
* Implement the chosen attack.
* Demonstrate the attack effect on normal nodes.

---

##  Helper Modules

### `src/shamir_utils.py`

Functions for:

* Splitting EphID into shares.
* Reconstructing EphID from shares.

### `src/crypto_utils.py`

Functions for:

* EphID generation.
* Hash calculation.
* Diffie-Hellman shared secret derivation.
* EncID derivation from shared secret.

### `src/network_udp.py`

Functions for:

* Building UDP share packets.
* Sending broadcast packets.
* Receiving and parsing incoming UDP packets.

### `src/network_tcp.py`

Functions for:

* Building TCP messages for QBF/CBF uploads.
* Sending requests to the server.
* Reading server responses.

### `src/bloom.py`

Bloom Filter implementation.

Should support:

* Insert item.
* Query item.
* Merge / union with another Bloom Filter.
* Export and import serialized data.

### `src/dbf_manager.py`

DBF lifecycle management.

Should support:

* Active DBF creation.
* Timed DBF rotation.
* Deleting expired DBFs.
* Merging DBFs into QBF.
* Merging DBFs into CBF.

### `src/config.py`

Central configuration file for:

* Default host/port values.
* Bloom Filter size.
* Number of hash functions.
* Debug flags.
* Packet/message type constants.

### `src/protocol_utils.py`

Shared protocol helpers for:

* Message formatting.
* JSON serialization.
* Base64 conversion for binary fields.
* Common validation utilities.

---

## Yuanqi Lu's part

This part covers the frontend protocol core from Task 1 to Task 5, and the handoff into Task 6 to Task 8 scheduling.

### Files

* [`src/Dimy.py`](src/Dimy.py)
* [`src/shamir_utils.py`](src/shamir_utils.py)
* [`src/network_udp.py`](src/network_udp.py)
* [`src/crypto_utils.py`](src/crypto_utils.py)
* [`src/dbf_manager.py`](src/dbf_manager.py)
* [`tests/test_crypto.py`](tests/test_crypto.py)
* [`tests/test_shamir.py`](tests/test_shamir.py)
* [`tests/test_udp_messages.py`](tests/test_udp_messages.py)
* [`tests/test_end_to_end.py`](tests/test_end_to_end.py)
* [`tests/test_dbf_manager.py`](tests/test_dbf_manager.py)
* [`tests/test_task6_8_flow.py`](tests/test_task6_8_flow.py)

### Responsibilities

This part is responsible for the following protocol stages:

1. Generate a 32-byte EphID.
2. Split the EphID into `n` shares using `k`-out-of-`n` Shamir Secret Sharing.
3. Broadcast one share every 3 seconds using UDP.
4. Receive shares from other nodes and simulate message drops with probability `p`.
5. Reconstruct a peer EphID after receiving at least `k` distinct shares.
6. Verify the reconstructed EphID using the advertised hash.
7. Derive a shared EncID using Diffie-Hellman.
8. Insert EncID into the current DBF.
9. Rotate DBFs and generate QBFs on schedule.

### Main Interfaces

#### `src/crypto_utils.py`

* `generate_ephid_keypair() -> LocalEphID`

  * Generates one fresh local EphID state.
  * Returns a local X25519 private key, 32-byte public key bytes, and the SHA-256 hash of the public key.

* `hash_ephid(ephid: bytes) -> str`

  * Computes the SHA-256 hash of a 32-byte EphID.

* `verify_ephid_hash(ephid: bytes, expected_hash: str) -> bool`

  * Verifies that a reconstructed EphID matches the advertised hash.

* `load_peer_public_key(ephid_bytes: bytes)`

  * Loads peer EphID bytes as an X25519 public key.

* `derive_encounter_id(my_private_key, peer_ephid_bytes, my_ephid_hash, peer_ephid_hash) -> bytes`

  * Performs Diffie-Hellman and derives a symmetric 32-byte EncID.

#### `src/shamir_utils.py`

* `split_secret(secret: bytes, k: int, n: int) -> list[ShamirShare]`

  * Splits a secret into `n` shares with threshold `k`.

* `combine_shares(shares: list[ShamirShare], k: int) -> bytes`

  * Reconstructs the secret from at least `k` distinct shares.

* `serialize_share(share: ShamirShare) -> str`

  * Serializes a share into a transport-safe string.

* `deserialize_share(text: str) -> ShamirShare`

  * Parses a serialized share string.

#### `src/network_udp.py`

* `UDPShareTransport.start()`

  * Starts the UDP receiver thread.

* `UDPShareTransport.stop()`

  * Stops the UDP receiver thread and closes sockets.

* `UDPShareTransport.send_packet(packet: dict) -> None`

  * Sends one JSON packet over UDP.

* `on_packet(packet: dict, addr: tuple[str, int]) -> None`

  * Callback used by `Dimy.py` to process received share packets.

#### `src/dbf_manager.py`

* `add_encounter(encid: bytes) -> DBFState`

  * Inserts EncID into the current DBF.

* `rotate_if_needed(now: float | None = None) -> DBFState`

  * Creates a new DBF when the current DBF time window expires.

* `get_dbfs() -> list[DBFState]`

  * Returns all currently retained DBFs.

* `build_qbf(now: float | None = None, force: bool = False) -> QBFState | None`

  * Combines all available DBFs into a QBF.

* `build_cbf(now: float | None = None)`

  * Combines all available DBFs into a CBF for backend upload.

#### `src/Dimy.py`

* `DimyNode.start()`

  * Starts the EphID rotation loop, share broadcast loop, and QBF scheduling loop.

* `DimyNode.stop()`

  * Stops all loops and closes sockets.

* `DimyNode.handle_udp_packet(packet: dict, addr: tuple[str, int])`

  * Processes one received UDP share packet.

* `DimyNode.get_dbfs() -> list[DBFState]`

  * Returns DBFs for debugging and testing.

* `DimyNode.get_last_qbf() -> QBFState | None`

  * Returns the most recently generated QBF.

### * [`implement`](docs/implementation-yuanqi-lu.md)

---

## Emrik Moe's part

This part covers the Bloom filter support layer, the TCP communication layer, and the backend server required for Task 9 and Task 10.

### Files

* [`src/bloom.py`](src/bloom.py)
* [`src/network_tcp.py`](src/network_tcp.py)
* [`src/DimyServer.py`](src/DimyServer.py)
* [`tests/test_bloom.py`](tests/test_bloom.py)
* [`tests/test_tcp_messages.py`](tests/test_tcp_messages.py)

### Responsibilities

This part is responsible for the following backend-related stages:

1. Provide Bloom filter serialization and deserialization helpers.
2. Encode Bloom filter data into a network-safe format for TCP transport.
3. Define a consistent JSON-over-TCP request and response format.
4. Support CBF upload from positive nodes.
5. Support QBF queries from normal nodes.
6. Validate backend request payloads such as version, filter size, hash count, and encoded Bloom payload.
7. Store uploaded CBFs on the server.
8. Perform QBF-CBF matching and return `matched` or `not_matched`.
9. Provide reusable TCP client and server utilities for Task 9 and Task 10 integration.

### Main Interfaces

#### `src/bloom.py`

* `to_bytes(bloom: BloomFilter) -> bytes`

  * Serializes a Bloom filter into raw bytes.

* `from_bytes(data: bytes, size_bytes: int = 100*1024, hash_count: int = 3) -> BloomFilter`

  * Reconstructs a Bloom filter from raw bytes.
  * Validates the incoming byte length before loading it.

* `to_base64(bloom: BloomFilter) -> str`

  * Encodes Bloom filter bytes into base64 for JSON/TCP transport.

* `from_base64(encoded: str) -> BloomFilter`

  * Decodes a base64 transport payload back into a Bloom filter.

#### `src/network_tcp.py`

* `TCPBackendClient.send_request(message: dict[str, Any]) -> dict[str, Any]`

  * Sends one JSON request to the backend and returns one JSON response.

* `TCPBackendClient.upload_cbf(node_id: str, cbf_bytes: bytes, size_bytes: int, hash_count: int) -> dict[str, Any]`

  * Uploads a CBF to the backend server.

* `TCPBackendClient.query_qbf(node_id: str, qbf_bytes: bytes, size_bytes: int, hash_count: int) -> dict[str, Any]`

  * Sends a QBF to the backend server for risk analysis.

* `TCPBackendServer.start()`

  * Starts the TCP backend listener.

* `TCPBackendServer.stop()`

  * Stops the TCP backend listener.

* `make_upload_cbf_request(...) -> dict[str, Any]`

  * Builds the standard JSON request for Task 9 CBF upload.

* `make_query_qbf_request(...) -> dict[str, Any]`

  * Builds the standard JSON request for Task 10 QBF query.

* `upload_cbf(...) -> dict[str, Any]`

  * Functional wrapper for client-side CBF upload.

* `query_qbf(...) -> dict[str, Any]`

  * Functional wrapper for client-side QBF query.

#### `src/DimyServer.py`

* `DimyServer.start()`

  * Starts the backend TCP server.

* `DimyServer.stop()`

  * Stops the backend TCP server.

* `DimyServer.serve_forever()`

  * Runs the backend server until interrupted.

* `DimyServer.handle_upload_cbf(node_id: str, cbf_bytes: bytes) -> dict[str, Any]`

  * Validates and stores an uploaded CBF.

* `DimyServer.handle_query_qbf(node_id: str, qbf_bytes: bytes) -> dict[str, Any]`

  * Performs backend risk analysis by matching a QBF against stored CBFs.

* `DimyServer.get_stored_cbfs() -> list[StoredCBF]`

  * Returns the currently stored CBF entries for testing and debugging.

### Implementation Summary

#### `src/bloom.py`

This module provides a small compatibility layer around the project Bloom filter representation. It does not reimplement the full Bloom filter logic. Instead, it focuses on safe conversion between in-memory Bloom filters and transport/storage representations.

The implementation supports:

* conversion from Bloom filter object to raw bytes
* conversion from raw bytes back to Bloom filter object
* conversion from Bloom filter object to base64 string
* conversion from base64 string back to Bloom filter object

Length validation is performed during deserialization so that corrupted or truncated Bloom filter payloads are rejected before being used by the backend.

#### `src/network_tcp.py`

This module implements a lightweight JSON-over-TCP protocol.

The design choice is one request per connection and one response per connection. This keeps the protocol simple and makes debugging easier during the assignment demo.

The implementation includes:

* a TCP client for frontend nodes
* a TCP server wrapper for the backend
* request builders for CBF upload and QBF query
* base64 helpers for Bloom filter transport
* validation for ports, timeouts, payload lengths, and message structure

The protocol fields are standardized so that frontend and backend use the same message format. Each request includes:

* request type
* protocol version
* node ID
* Bloom filter size in bytes
* number of hash functions
* base64-encoded Bloom filter bytes
* timestamp

This makes the interface explicit and reduces ambiguity during integration.

#### `src/DimyServer.py`

This module implements the backend server for Task 9 and Task 10.

The server keeps the application state, while `TCPBackendServer` only handles socket lifecycle and request dispatch.

The implementation supports two request types:

1. **CBF upload**

   * validates node ID and payload shape
   * reconstructs the uploaded Bloom filter
   * stores the uploaded CBF under the reporting node

2. **QBF query**

   * validates node ID and payload shape
   * reconstructs the uploaded QBF
   * compares it with stored CBFs
   * returns `matched` or `not_matched`

The server stores uploaded CBFs as backend state and performs the matching step needed for risk analysis. The request handling path is intentionally separated from the matching logic so that the backend code remains easier to test and maintain.

### Tests

#### `tests/test_bloom.py`

Tests:

* Bloom filter byte serialization and deserialization
* base64 encoding and decoding
* invalid payload length rejection

#### `tests/test_tcp_messages.py`

Tests:

* request builder correctness
* base64 transport encoding and decoding
* TCP client and server message exchange
* protocol validation failures
* CBF upload and QBF query end-to-end behaviour
