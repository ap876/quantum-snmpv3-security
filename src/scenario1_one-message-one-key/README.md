# Scenario 1 – One-message–one-key policy

In this scenario, each SNMPv3 message (GET, GET-BULK, TRAP, INFORM) is protected with a unique QKD key.  
Two variants are implemented: AES-128 and AES-256.

## Folder Structure

- `128/` – One-message–one-key with AES-128  
  - `agent.py` – SNMPv3 agent with AES-128  
  - `manager.py` – SNMPv3 manager with AES-128  

- `256/` – One-message–one-key with AES-256  
  - `agent.py` – SNMPv3 agent with AES-256  
  - `manager.py` – SNMPv3 manager with AES-256  

## How to Run

1. Start the QKD emulation (ETSI GS QKD 014) from the ns-3 root directory:
```bash
./ns3 run scratch/examples_qkd_etsi_014_emulation.cc
```
2. Run the agent (separate terminal):
```
python3 128/agent.py 
```
3. Run the manager (another terminal):
```
python3 128/manager.py 
```
(Replace 128/ with 256/ to run the AES-256 variant.)

## Results and Visualization

To visualize results in QKD ns-3, run:
```
gnuplot *.plt
```
