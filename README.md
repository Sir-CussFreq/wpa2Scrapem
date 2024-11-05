# WPA2 Enterprise Username Scraper (`wpa2scrapem.py`)

`wpa2scrapem.py` is a Python utility for penetration testing reconnaissance on WPA2 Enterprise networks. It captures and analyzes **EAP-Response/Identity** packets to extract usernames, supporting both live sniffing and offline analysis of PCAP files.

## Features
- **Monitor Mode Activation**: Switches a WiFi interface to monitor mode for live packet capture.
- **EAP Packet Parsing**: Extracts usernames from EAP-Response packets.
- **PCAP File Analysis**: Reads and processes PCAP files, with support for wildcards in filenames.
- **Output Options**: Displays usernames to stdout or saves them to a file.

## Installation
Ensure you have Python 3.x and `scapy` installed:
```bash
pip install scapy
```

## Usage
### Live Sniffing
```bash
sudo python3 wpa2scrapem.py --interface wlan0 --output-file usernames.txt
```

### PCAP File Analysis
Analyze a single PCAP file:
```bash
python3 wpa2scrapem.py --pcap capture.pcap --output-file usernames.txt
```

Analyze multiple PCAP files using a wildcard (ensure you quote the wildcard pattern):
```bash
python3 wpa2scrapem.py --pcap '*.cap' --output-file usernames.txt
```

### Requirements
- Python 3.x
- Scapy library (`pip install scapy`)
- Root privileges for live sniffing

## Notes
- When using a wildcard for PCAP file input, ensure the pattern is enclosed in single or double quotes to prevent shell expansion.
- Example: `'*.pcap'` or `"*.cap"`

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

