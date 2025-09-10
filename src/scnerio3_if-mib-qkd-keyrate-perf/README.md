# Scenario 3 – IF-MIB with different QKD key generation rates

In this scenario, the IF-MIB model [IF-MIB](https://mibs.observium.org/mib/IF-MIB/) is traversed using SNMPv3 operations.  
The experiments analyze how different QKD key generation rates affect stability, buffer usage, and protocol efficiency.  
The QKD generation rate was modified in the example script to values of 10 kbps, 50 kbps, 100 kbps, and 150 kbps.  
The performance was compared for GET, GET-NEXT, and GET-BULK operations.

## Folder Structure

- `agent.py` – SNMPv3 agent for IF-MIB traversal  
- `manager.py` – SNMPv3 manager for IF-MIB traversal  

## How to Run

1. Start the QKD emulation (ETSI GS QKD 014) from the ns-3 root directory.  
   Adjust the QKD key generation rate in the example script before running:
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
(Replace 128/ with 256/ to run the AES-256 variant. The --period parameter defines the key refresh interval.)

## Results and Visualization

To visualize results in QKD ns-3, run:
```
gnuplot *.plt
```
