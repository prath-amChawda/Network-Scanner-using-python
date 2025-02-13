# Network-Scanner-using-python
cyber security project of network scanner using python
# Network Scanner

A simple network scanner that performs an ARP scan to discover active devices on a network and checks for open ports on each discovered host.

## 🚀 Features
- Scans a given IP range for active devices using ARP requests.
- Retrieves MAC addresses and hostnames of discovered devices.
- Scans open ports (1-1024) on each discovered device.
- Uses multi-threading for faster port scanning.

## Prerequisites
- Python 3.x
- Required Python modules:
  - `scapy`
  - `socket`
  - `concurrent.futures`
  
3️⃣ Install Dependencies

```sh
pip install scapy
