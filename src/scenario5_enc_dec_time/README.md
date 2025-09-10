# Scenario 5 – Encryption/decryption execution time

This scenario benchmarks the execution time of AES encryption and decryption during SNMPv3 communication.  
Tests cover AES-128 and AES-256 as configured in the scripts.

## Files

- agent.py
- manager.py

## How to run

1. Start the QKD emulation (ETSI GS QKD 014) from the ns-3 root directory:
```bash
./ns3 run scratch/examples_qkd_etsi_014_emulation.cc
```
2. In a separate terminal, start the SNMPv3 agent. 
```bash
cd src/scenario5_enc_dec_time
python3 agent.py
```
3. In another terminal, run the SNMPv3 manager with chosen mode.
Example for batch retrieval (1xN):
```
cd src/scenario5_enc_dec_time
python3 manager.py
```

## Results and visualization

Measurements are written to CSV files in this directory. Visualization is done only with gnuplot; plotting scripts exist locally but are not included here. From this scenario directory, run:
```
gnuplot *.plt
```
