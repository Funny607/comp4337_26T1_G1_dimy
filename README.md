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

---