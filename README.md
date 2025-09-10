# Application of Quantum Cryptography for Securing Network Management Protocols

This repository was created as part of the Master’s thesis at the Faculty of Electrical Engineering, University of Sarajevo.  
The work focuses on the integration of Quantum Key Distribution (QKD) with the SNMPv3 protocol, aiming to enhance the security of network management communications in the quantum era.  

A simulation environment was developed based on the NS-3/QKDNetSim emulator [1], Python implementations of SNMPv3 agents and managers, and Key Management System (KMS) servers.  
The SNMPv3 implementation is based on the open-source PySNMP project [2].  
Several scenarios were analyzed, covering QKD key consumption, response time (RTT), efficiency of SNMP operations, and encryption/decryption performance.

## Project Overview

The goal of this project is to explore the application of Quantum Key Distribution (QKD) in securing network management protocols, with a special focus on SNMPv3.  
The project combines network simulation, cryptographic mechanisms, and protocol analysis to evaluate how QKD-based keys can be used for dynamic rekeying of SNMPv3 communications.  

The implementation is based on three main components:

1. NS-3 with the QKDNetSim module, used to emulate the generation and distribution of quantum keys.  
2. A Key Management System (KMS) that handles key storage, distribution, and synchronization between SNMP entities.  
3. Python-based SNMPv3 agents and managers (adapted from the PySNMP library), extended to support dynamic key rotation using QKD-derived keys.

Through several experimental scenarios, the project analyzes:
- The consumption of QKD keys under different SNMP operations (GET, GET-NEXT, GET-BULK, TRAP/INFORM)  
- The effect of key generation rates on stability and efficiency  
- Response time (RTT) when retrieving keys from the KMS (batch vs one-by-one requests)  
- The performance of AES-128 and AES-256 encryption and decryption in this setup  

## Requirements and Installation

This project was developed and tested on Ubuntu 20.04 LTS.  
To reproduce the experiments, the following components need to be installed and configured:

### System
- Ubuntu 20.04 LTS (recommended)

### Python environment
- Python 3.8 or newer
- Required libraries:
  - PySNMP (for SNMPv3 implementation)
  - Requests (for HTTP communication with the Key Management System)
  - Matplotlib and Pandas (for analysis and plotting of CSV results)

Install Python dependencies:
```bash
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install pysnmp requests matplotlib pandas
```
## Project Structure

All scenario folders are located under the `src/` directory:

- `src/scenario1_one-message-one-key/` – Each SNMPv3 message (GET, GET-BULK, TRAP, INFORM) is protected with a unique QKD key, using AES-128 or AES-256.
- `src/scenario2_time-refresh-policy/` – Keys are rotated periodically instead of per message, and performance is analyzed for GET, GET-BULK, TRAP, and INFORM.
- `src/scenario3_key-generation-rates/` – The impact of varying QKD generation rates (10–150 kbps) is evaluated using GET, GET-NEXT, and GET-BULK.
- `src/scenario4_rtt-kms-retrieval/` – Response time is compared between one-by-one and batch retrieval of cryptographic keys from the KMS.
- `src/scenario5_aes-performance/` – AES-128 and AES-256 are benchmarked to measure processing speed and system overhead.

Each folder contains a README file with detailed descriptions of the scenario, parameter tables, and instructions for running the experiments.


## Simulation Environment

The QKD simulation is based on the NS-3/QKDNetSim framework.  
For the emulation of key distribution, the ETSI GS QKD 014 protocol was used, following the example `examples_qkd_etsi_014_emulation.cpp` provided in the QKDNetSim module.

## How to Run

1. Download or clone the repository from GitHub:
```
git clone https://github.com/ap876/quantum-snmp-qkd.git
cd quantum-snmp-qkd
```
2. Start the QKD emulation (ETSI GS QKD 014)
```
./ns3 run scratch/examples_qkd_etsi_014_emulation.cc
```
3. Start the SNMPv3 agent (separate terminal)
```
python3 src/agent.py 
```
4. Start the SNMPv3 manager (another terminal)
```
python3 src/manager.py
```
## References
[1] Mehic, M., Maurhart, O., Rass, S., & Voznak, M. (2017). Implementation of quantum key distribution network simulation module in the network simulator NS-3. Quantum Information Processing, 16(10), 253. Springer.  
[2] Ilya Etingof. PySNMP: SNMP library for Python. Available at: https://github.com/etingof/pysnmp  
