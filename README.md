# Wi-Fi Probe Request Sniffer

This Python script uses **Scapy** to sniff Wi-Fi probe request frames in monitor mode.  
It logs detected SSIDs along with the sender's MAC address and a timestamp.

## Features
- Captures **802.11 Probe Request** frames.
- Avoids duplicates — each SSID is logged only once.
- Saves detections to `probe_det.txt` with timestamps.

## Requirements
- Python 3
- [Scapy](https://scapy.net/)
- Wireless interface in **monitor mode** (e.g., `wlan0mon`).

## Usage
1. Install Scapy:
   ```bash
   pip install scapy
