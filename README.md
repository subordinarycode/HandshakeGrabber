
# Wi-Fi Handshake Sniffer

This Python script captures WPA/WPA2 handshakes from Wi-Fi networks by sniffing wireless traffic using a specified network interface in monitor mode. It utilizes `scapy` for packet capture and supports multi-threaded packet processing to improve performance. It also features channel hopping, allowing you to capture handshakes across multiple Wi-Fi channels, and it saves the handshakes in `.pcap` files for later analysis.

## Features

- **Wi-Fi Handshake Capture:** Captures WPA/WPA2 EAPOL handshakes for network auditing or testing.
- **Channel Hopping:** Automatically hops across Wi-Fi channels (2.4GHz, 5GHz, or both) to capture handshakes from different networks.
- **Multi-threaded Processing:** Uses multiple worker threads to process packets concurrently, improving performance.
- **Packet Saving:** Saves the captured handshake packets to `.pcap` files for further analysis.
- **Monitor Mode Check:** Ensures the network interface is in monitor mode before starting the capture.
- **Logging:** Logs detailed information about the capture process and any errors encountered.

## Prerequisites

Before using this script, ensure you have the following:

- A wireless network interface in **monitor mode** (e.g., `wlan0`).
- The following Python packages installed:
  - `scapy`: For packet sniffing and manipulation.
  - `argparse`: For parsing command-line arguments.
  - `subprocess`: For executing system commands (used for changing Wi-Fi channels).
  - `threading` and `queue`: For concurrent packet processing.

You can install the necessary Python dependencies using pip:

```bash
pip install scapy
```

## Installation

1. Clone or download this repository to your local machine.
2. Ensure you have the necessary privileges to run the script (typically requires root/sudo access to put the interface in monitor mode and change channels).

## Usage

### Running the script

The script requires root privileges to access the network interface in monitor mode. You can run the script as follows:

```bash
sudo python3 main.py <interface> [options]
```

### Command-Line Arguments

- **interface (required)**: The network interface to use for sniffing (e.g., `wlan0`).
- **--max_workers (optional)**: The number of worker threads to process packets concurrently (default: `6`).
- **--channel (optional)**: The specific channel to sniff on (e.g., `1`, `6`, `11`). If not specified, the script will use channel hopping.
- **--band (optional)**: Specify the Wi-Fi band for channel hopping. Options:
  - `2.4GHz` (default)
  - `5GHz`
  - `all` (both 2.4GHz and 5GHz)

### Example Usage

1. **Sniffing on a specific channel (e.g., channel 6):**

   ```bash
   sudo python3 main.py wlan0 --channel 6
   ```

2. **Enabling channel hopping on both 2.4GHz and 5GHz bands:**

   ```bash
   sudo python3 main.py wlan0 --band all
   ```

3. **Sniffing with multiple worker threads (e.g., 10 threads):**

   ```bash
   sudo python3 main.py wlan0 --max_workers 10
   ```

4. **Check if the interface is in monitor mode:**

   The script will automatically check if the provided interface is in monitor mode. If it's not, it will exit with an error message.

### Stopping the Sniffer

The script will continue running until it is manually stopped (e.g., using `Ctrl + C`). Once stopped, it will gracefully clean up and stop the sniffing process.

## Notes

- **Monitor Mode:** Ensure your wireless network interface is in monitor mode. You can enable monitor mode using `airmon-ng` or similar tools.
- **Root Privileges:** The script requires root privileges to capture packets and change Wi-Fi channels. Use `sudo` to run the script.
- **PCAP Files:** Handshakes are saved in a directory named `pcaps` in the current working directory. If a network has a broadcast SSID, the filename will reflect the network name. If the SSID is hidden, the file will be named `hidden_networks_handshake.pcap`.

## Example Output

```
[2024-11-10 12:34:56] - [INFO] -# Starting the handshake sniffer...
[2024-11-10 12:34:57] - [INFO] -# New BSSID Found: 00:14:22:01:23:45
[2024-11-10 12:34:58] - [INFO] -# EAPOL packet 1/4 from 00:14:22:01:23:45
[2024-11-10 12:34:59] - [INFO] -# EAPOL packet 2/4 from 00:14:22:01:23:45
[2024-11-10 12:35:00] - [INFO] -# Saved handshake to pcaps/hidden_networks_handshake.pcap for AP with BSSID: 00:14:22:01:23:45
```



