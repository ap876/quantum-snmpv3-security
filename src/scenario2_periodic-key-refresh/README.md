# Scenario 2 – Periodic key refresh policy

In this scenario, QKD keys are refreshed periodically instead of for every SNMPv3 message.  
The refresh period is configurable and can be adjusted to analyze the trade-off between security and performance.  
Two variants are implemented: AES-128 and AES-256.  
The performance and key consumption are analyzed for different SNMPv3 operations: GET, GET-BULK, TRAP, and INFORM.

## Folder Structure

- `128/` – Periodic key refresh with AES-128  
  - `agent.py` – SNMPv3 agent with AES-128  
  - `manager.py` – SNMPv3 manager with AES-128  

- `256/` – Periodic key refresh with AES-256  
  - `agent.py` – SNMPv3 agent with AES-256  
  - `manager.py` – SNMPv3 manager with AES-256  

## How to Run

1. Start the QKD emulation (ETSI GS QKD 014) from the ns-3 root directory:
```bash
./ns3 run scratch/examples_qkd_etsi_014_emulation.cc
```
2. Run the agent (separate terminal):
```
python3 128/agent.py --listen 0.0.0.0:161 --kms http://<kms-host>:<kms-port> --period <seconds>
```
3. Run the manager (another terminal):
```
python3 128/manager.py --target <agent-ip>:161 --kms http://<kms-host>:<kms-port>
```
(Replace 128/ with 256/ to run the AES-256 variant. The --period parameter defines the key refresh interval.)

## Results and Visualization

To visualize results in QKD ns-3, run:
```
gnuplot *.plt
```
