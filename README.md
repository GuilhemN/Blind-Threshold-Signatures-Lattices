# Blind Threshold Signatures over Lattices

**This repository accompanies the academic paper:**  
*Lattice-based Threshold Blind Signatures*
Sebastian Faller, Guilhem Niot, Michael Reichle


This repository extends the original [Plover](https://github.com/GuilhemN/masksign-plover) code to build a **threshold blind signature** scheme over lattices.

## Overview

This codebase provides a Python implementation of a threshold blind signature scheme based on the Plover signature scheme, with additional components for threshold and blind signing.

## Disclaimer

**This code is for academic and research purposes only and is not production-ready.** It may not be constant time or have security vulnerabilities. Do not use this code in production environments without thorough review, testing, and security audits.

## Setup & Testing on Ubuntu

To get started on a fresh Ubuntu system, follow these steps:

### 1. Install Prerequisites

```bash
sudo apt update
sudo apt install -y python3-pip python3.12-venv unzip libgmp-dev libmpfr-dev cmake
```

### 2. Python Environment

Create and activate a virtual environment in the repository root:

```bash
python3 -m venv .
source bin/activate
```

Upgrade setuptools and install Python dependencies:

```bash
pip install --upgrade setuptools
pip install requests cffi
```

### 3. Build Dependencies

Initialize git submodules:

```bash
git submodule update --init --recursive
```

Build the LaZer library and Python bindings:

```bash
cd lazer/
make
cd python/
make
cd ../..
```

Install Python requirements for the threshold blind signature code:

```bash
pip install -r requirements.txt
```

Build proof components:

```bash
cd proof/
make
cd ..
```

### 4. Running Tests

After setup, you can run tests:

```bash
python threshold_party.py --help
```

If you encounter issues, ensure all dependencies are installed and submodules are up to date.

## Alternative Testing Method

To run the test in `plover_api.py`:

1. **Ensure dependencies are built** (follow steps 3 above)

2. **Run the test**
   ```bash
   python3 plover_api.py
   ```


## Using Threshold Blind Signatures

The `threshold_party.py` script implements a T-out-of-N threshold blind signature scheme using JSON-RPC communication between parties.

### Basic Usage

To run a threshold blind signature protocol, you need:
- **1 User party** (who wants to get a message signed)
- **T Signer parties** (who collectively sign the message)

### Starting Signer Parties

First, start the required number of signer parties (each in a separate terminal):

```bash
# Terminal 1: Start signer 1
python3 threshold_party.py --party-id 1 --party-type signer

# Terminal 2: Start signer 2
python3 threshold_party.py --party-id 2 --party-type signer

# Terminal 3: Start signer 3
python3 threshold_party.py --party-id 3 --party-type signer
```

Each signer will start a JSON-RPC server on port `8000 + party_id` (e.g., signer 1 on port 8001, signer 2 on port 8002, etc.).

### Starting the User Party

Once all signers are running, start the user party:

```bash
# Terminal 4: For a 2-out-of-3 threshold scheme
python3 threshold_party.py --party-id 0 --party-type user --threshold 2 --total-parties 3
```

### Command Line Options

- `--party-id`: Unique integer ID for the party
- `--party-type`: Either "user" or "signer"  
- `--threshold`: Number of signers required (T) - required for user party
- `--total-parties`: Total number of signer parties (N) - required for user party
- `--user-port`: Base port number (default: 8000)
- `--signer-hosts`: List of signer hosts for user party (format: host1:port1 host2:port2 ...)
- `--signer-host`: Host address for signer party (default: localhost)
- `--signer-port`: Port for signer party (defaults to 8000 + party-id)
- `--runs`: Number of signing runs for averaging measurements (default: 1)

### Protocol Flow

1. **Setup**: Signers start and wait for connections
2. **Key Generation**: User generates threshold keys and distributes shares to signers
3. **Round 1**: User collects commitments from signers
4. **Round 2**: User distributes commitments and collects witness values
5. **Round 3**: User distributes witnesses and collects final responses
6. **Completion**: User aggregates responses to create the final blind signature

### Example: 2-out-of-3 Threshold Signature

```bash
# Terminal 1: Start signer 1
python3 threshold_party.py --party-id 1 --party-type signer

# Terminal 2: Start signer 2
python3 threshold_party.py --party-id 2 --party-type signer

# Terminal 3: Start signer 3
python3 threshold_party.py --party-id 3 --party-type signer

# Terminal 4: Start user (will use signers 1 and 2 for threshold=2)
python3 threshold_party.py --party-id 0 --party-type user --threshold 2 --total-parties 3
```

The protocol will automatically select the first T signers that are available to participate in the signing.

### Performance Measurement

To get reliable performance measurements, run multiple signing iterations:

```bash
# Run 10 iterations and average the measurements
python3 threshold_party.py --party-id 0 --party-type user --threshold 2 --total-parties 3 --runs 10
```

This will perform key generation once, then execute the 3-round signing protocol 10 times and report averaged timing measurements with standard deviations.

### Using Different Hosts

You can run signers on different machines by specifying custom hosts and ports:

```bash
# On machine 192.168.1.10: Start signer 1
python3 threshold_party.py --party-id 1 --party-type signer --signer-host 192.168.1.10 --signer-port 9001

# On machine 192.168.1.11: Start signer 2
python3 threshold_party.py --party-id 2 --party-type signer --signer-host 192.168.1.11 --signer-port 9002

# On user machine: Start user with custom signer locations
python3 threshold_party.py --party-id 0 --party-type user --threshold 2 --total-parties 2 \
    --signer-hosts 192.168.1.10:9001 192.168.1.11:9002
```

## Project Structure

```
├── lazer/                 LaZer zero-knowledge proof library
├── Makefile               Clean target
├── polyr.py               Polynomial ring arithmetic + NTT code
├── plover_api.py          Serialization/deserialization, NIST functions, tests
├── plover_core.py         Plover signature scheme core algorithm
├── README.md              This file
├── requirements.txt       Python dependencies
├── test_ntt.py            Basic NTT tests
├── threshold_party.py     T-out-of-N threshold blind signature with JSON-RPC
└── proof/                 NIZK proof components
```

**Note:**  
This repository extends the original Plover code to support threshold and blind signature features. Please refer to the code and comments for details on the new functionalities.