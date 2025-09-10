# Scenario 4 – RTT analysis for KMS retrieval (batch vs one-by-one)

This scenario analyzes response time (RTT) when cryptographic keys are retrieved from the Key Management System (KMS).  
Two strategies are compared:

- One-by-one retrieval: each key is requested in a separate HTTP call (Nx1)
- Batch retrieval: multiple keys are requested in a single HTTP call and then consumed sequentially (1xN)

The goal is to observe how the chosen strategy affects RTT, stability, and overall efficiency of SNMPv3 communication with QKD-derived keys.

## Folder structure

- 1xN/  – batch retrieval
  - agent.py
  - manager.py
- Nx1/  – one-by-one retrieval
  - agent.py
  - manager.py

## How to run

1. Start the QKD emulation (ETSI GS QKD 014) from the ns-3 root directory:
```bash
./ns3 run scratch/examples_qkd_etsi_014_emulation.cc
```
2. In a separate terminal, start the SNMPv3 agent. 
   Navigate to the corresponding folder and run:
```bash
python3 src/scenario4/1xN/agent.py
```
3. In another terminal, run the SNMPv3 manager with chosen mode.
Example for batch retrieval (1xN):
```
python3 manager.py --want-keys 100 --max-per-request 20 --outfile results_batch.csv
```
Example for one-by-one retrieval (Nx1):
```
python3 manager.py --count 100 --outfile results_onebyone.csv
```
Results will be stored in CSV files for later analysis (e.g., results_batch.csv, results_onebyone.csv).

## Results and visualization

RTT measurements are stored in CSV during the experiments. Visualization is done only with gnuplot. Plotting scripts exist locally but are not included here. From the client-side scenario directory where the .plt files are generated (e.g., 1xN/ or Nx1/), run:
```bash
gnuplot *.plt
```
