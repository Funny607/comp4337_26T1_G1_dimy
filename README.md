# COMP4337 Assignment - DIMY Protocol Implementation

## Repository Overview

This repository contains our Python implementation of the DIMY protocol for the COMP4337/9337 Fixed and Wireless Network Security assignment.

The project is organized by functional modules so that the front-end node, back-end server, attacker node, testing scripts, and documentation can be developed in parallel and integrated cleanly.

---

## Recommended Repository Structure

```text
comp4337-dimy/
├── README.md
├── .gitignore
├── requirements.txt
├── docs/
│   ├── AssignmentReport.pdf
│   ├── demo-plan.md
│   ├── runbook.md
│   └── notes/
│       ├── meeting-log.md
│       ├── protocol-design.md
│       └── attack-notes.md
├── src/
│   ├── Dimy.py
│   ├── DimyServer.py
│   ├── Attacker.py
│   ├── shamir_utils.py
│   ├── crypto_utils.py
│   ├── bloom.py
│   ├── dbf_manager.py
│   ├── network_udp.py
│   ├── network_tcp.py
│   ├── config.py
│   └── protocol_utils.py
├── scripts/
│   ├── test_runner.sh
│   ├── run_node.sh
│   ├── run_server.sh
│   ├── run_attacker.sh
│   └── cleanup.sh
├── tests/
│   ├── test_shamir.py
│   ├── test_crypto.py
│   ├── test_bloom.py
│   ├── test_dbf_manager.py
│   ├── test_udp_messages.py
│   ├── test_tcp_messages.py
│   └── test_end_to_end.py
├── logs/
│   ├── .gitkeep
│   ├── node1.log
│   ├── node2.log
│   ├── node3.log
│   ├── server.log
│   └── attacker.log
└── assets/
    ├── screenshots/
    │   ├── task4-reconstruction.png
    │   ├── task7-dbf-rotation.png
    │   └── task10-server-match.png
    └── diagrams/
        ├── repository-structure.png
        └── dimy-workflow.png
```

---

## Why This Structure

This layout keeps the repository easy to maintain and makes team collaboration clearer:

* `src/` stores all executable source code.
* `docs/` stores the report, demonstration notes, and supporting writeups.
* `scripts/` stores runnable shell scripts for quick setup and demonstrations.
* `tests/` stores unit and integration tests.
* `logs/` stores runtime logs generated during debugging or demonstrations.
* `assets/` stores screenshots or other visual materials for the report if needed.

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

## Suggested Helper Modules

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

## Recommended Branch Strategy

A simple branch structure is enough:

* `main` — stable integrated version
* `yuanqi-node` — front-end node development
* `emrik-server` — server / Bloom Filter development
* `xin-attack-docs` — attacker, scripts, and documentation

Suggested workflow:

1. Develop on personal branches.
2. Open pull requests into `main`.
3. Review before merge.
4. Tag important milestones such as `v0.1`, `demo-ready`, and `submission`.

---

## Recommended `.gitignore`

```gitignore
__pycache__/
*.pyc
*.pyo
*.log
.venv/
venv/
.env
.DS_Store
logs/*.log
.idea/
.vscode/
```

---

## Suggested `requirements.txt`

Keep dependencies minimal. Example:

```txt
cryptography
mmh3
bitarray
```

If you implement Bloom Filter manually, `bitarray` is optional.
If you implement Shamir Secret Sharing yourself, additional libraries may not be needed.

---

## Recommended Run Commands

### Start server

```bash
python3 src/DimyServer.py
```

### Start a DIMY node

```bash
python3 src/Dimy.py 15 3 5 50 127.0.0.1 55000
```

### Start attacker

```bash
python3 src/Attacker.py
```

### Run scripted demo

```bash
bash scripts/test_runner.sh
```

---

## Suggested Milestone Plan

### Milestone 1 - Core Node Communication

* EphID generation
* Share splitting
* UDP broadcast
* UDP receive and packet dropping
* Reconstruction and hash verification

### Milestone 2 - Encounter Storage and Server

* EncID derivation
* Bloom Filter implementation
* DBF rotation
* QBF / CBF construction
* TCP server communication

### Milestone 3 - Attack and Final Integration

* Attacker implementation
* End-to-end testing
* Debug log cleanup
* README and report completion
* Demo recording preparation

---

## Integration Rules

To avoid merge conflicts, agree early on these shared interfaces:

### UDP share packet fields

Recommended fields:

* `type`
* `sender_id`
* `ephid_hash`
* `share_index`
* `share_value`
* `timestamp`

### TCP server message fields

Recommended fields:

* `type` (`UPLOAD_CBF` or `QUERY_QBF`)
* `node_id`
* `data`

### Common output style

All runtime programs should print consistent debug logs, such as:

* `Generated new EphID`
* `Broadcasting share 2/5`
* `Received share from node2`
* `Dropped packet due to p=50`
* `Reconstructed EphID successfully`
* `EncID inserted into DBF`
* `QBF sent to server`
* `Server response: matched`

---

## Minimum Deliverables Checklist

* [ ] `src/Dimy.py`
* [ ] `src/DimyServer.py`
* [ ] `src/Attacker.py`
* [ ] Supporting source modules
* [ ] `scripts/test_runner.sh`
* [ ] `docs/AssignmentReport.pdf`
* [ ] Demo plan and run instructions
* [ ] `README.md`

---

## Final Recommendation

Use this repository as a clean engineering workspace rather than placing every file in the root directory. Keeping code, scripts, tests, and documentation separate will make collaboration much easier and will reduce confusion during integration and video recording.
