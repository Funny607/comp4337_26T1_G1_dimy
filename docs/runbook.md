# DIMY Attack Demo Runbook

## 1. Purpose

This runbook provides step-by-step instructions to run the DIMY system, launch the attacker, and observe the attack behaviour. It allows the demo to be reproduced without modifying the code.

---

## 2. Environment Setup

Make sure:

- Python 3 is installed
- You are in the project root directory
- The project structure is:

src/  
scripts/  
docs/  

---

## 3. Running the System

### Step 1: Start the Server

Run:

PYTHONPATH=. python3 src/DimyServer.py

You should see:

[DIMY_SERVER] listening on 0.0.0.0:55000

Keep this running.

---

### Step 2: Start Normal Nodes

Open 2–3 terminals and run:

PYTHONPATH=. python3 src/DimyNode.py nodeA  
PYTHONPATH=. python3 src/DimyNode.py nodeB  
PYTHONPATH=. python3 src/DimyNode.py nodeC  

Expected behaviour:

- Nodes generate EphIDs
- Nodes split EphIDs into shares
- Nodes broadcast shares
- Nodes create DBFs

Example logs:

[nodeA] new EphID epoch=...  
[nodeA] generated shares...  
[nodeA] new DBF created...  

---

### Step 3: Start the Attacker

In a new terminal, run:

modch +x scripts/run_attacker.sh  

./scripts/run_attacker.sh  

Expected behaviour:

- Attacker generates fake EphID shares
- Attacker broadcasts forged packets
- Packets are sent repeatedly

Example logs:

[run_attacker] starting attacker...  
[attacker] forged packets sent  

---

## 4. Observing the Attack

Focus on the node terminals.

A successful attack should show:

- Node receives multiple shares
- Threshold is reached (e.g. k shares)
- Node reconstructs an EphID

Typical output:

[nodeX] received share ...  
[nodeX] reconstructed EphID ...  

This indicates the node has accepted attacker-generated data.

---

## 5. One-command Demo

If available, run:

chmod +x scripts/test_runner.sh
./ scripts/test_runner.sh

This will automatically start the server, nodes, and attacker.

---

## 6. Stopping the System

Press:

Ctrl + C

in each terminal.

---

## 7. Common Issues

### ModuleNotFoundError: No module named 'src'

Run from project root using:

PYTHONPATH=. python3 ...

---

### Attacker has no effect

Check:

- Broadcast IP is 255.255.255.255  
- Port matches node listening port  
- Enough shares are sent (meet threshold k)  

---

### Nodes show no activity

Check:

- Server is running  
- Nodes are started before attacker  
- Ports are consistent  

---

## 8. Expected Outcome

The attack is successful if:

- The attacker sends forged shares  
- A node receives enough shares  
- The node reconstructs an EphID  

This demonstrates that attacker-generated data is processed by the system.