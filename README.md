# Mini Network Intrusion Detection System (Mini NIDS)

## About the Project
Mini NIDS is a beginner-level cybersecurity project developed using Python. It analyzes saved network traffic and detects suspicious TCP activity using simple detection rules.

## Features
- Offline network traffic analysis using PCAP files.
- Potential TCP port-scan detection.
- High TCP SYN-count detection.
- Configurable detection thresholds.
- Input validation and missing-file checks.
- Console alerts and analysis summary.
- Alert logging to `nids_alerts.log`.

## Technologies Used
- Python
- Scapy
- TCP/IP
- PCAP
- Visual Studio Code

## Detection Rules

### 1. Potential TCP Port Scan
Counts unique TCP destination ports for each source IP address. If the count reaches the configured threshold, the system generates a HIGH-severity alert.

### 2. High TCP SYN Count
Counts TCP SYN packets that are not SYN-ACK packets for each source IP address. If the count reaches the configured threshold, the system generates a MEDIUM-severity alert.

## Requirements
- Python 3
- Scapy library
- A PCAP file for analysis

## Installation
Open the terminal in the project directory and run:

```powershell
py -m venv .venv
.venv\Scripts\activate
py -m pip install scapy
```

## How to Run

Run the following command:

```powershell
py main.py
```

Press Enter at the PCAP prompt to use the default test file, or enter another valid PCAP file path. Press Enter at the threshold prompts to use their default values.

## Testing Results
The project was tested using synthetic network traffic.

With the default thresholds:
- Packets analyzed: 22
- Unique source IP addresses: 3
- Port-scan alerts: 1
- High SYN-count alerts: 1
- Total alerts: 2

Invalid thresholds and missing PCAP files were also tested.

## Limitations
- Analyzes saved PCAP files; live capture is not configured.
- Uses basic thresholds that may produce false positives or miss threats.
- Counts traffic across the entire capture instead of a time window.
- Does not perform advanced behavioral analysis.

## Future Improvements
- Add time-window-based detection.
- Implement additional detection rules.
- Generate detailed reports.
- Add traffic visualization and a dashboard.
- Explore live packet monitoring with suitable capture support.

## Disclaimer
This project is for educational and authorized defensive cybersecurity purposes. Analyze only network traffic you own or have permission to inspect.

## Author
**Bhuvan**

## Project Status
Beginner-level prototype — core features implemented and tested.
