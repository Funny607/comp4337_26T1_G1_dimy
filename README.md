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

### Emrik Moe

Responsible for Bloom Filter storage and back-end communication:

* `src/bloom.py`
* `src/dbf_manager.py`
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
