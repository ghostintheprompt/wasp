<p align="center">
  <img src="assets/wasp_logo.png" alt="WASP Logo" width="500">
</p>

# WASP: WiFi Adapter Security Protocol

**WASP** is a specialized framework for verifying the integrity and security of wireless network adapters before deployment in high-stakes security research and education environments.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](#)
[![Release](https://img.shields.io/badge/release-v1.0.0-blue)](https://github.com/ghostintheprompt/wasp/releases)

## Why WASP?

Compromised hardware is a silent threat. Both new and second-hand network equipment can contain malicious firmware, hardware implants, or unauthorized modifications. WASP provides a systematic verification process to ensure your hardware is exactly what it claims to be.

## Verified Features

| Feature | Description | Status |
| :--- | :--- | :--- |
| **Hardware ID** | Verifies Vendor/Product IDs against a trusted signature database. | ✅ |
| **Firmware Check** | Inspects driver and firmware metadata for integrity. | ✅ |
| **Behavioral Analysis** | Monitors packet patterns in monitor mode for anomalies. | ✅ |
| **Power Audit** | Detects anomalous power draw that may indicate hardware implants. | ✅ |
| **Traffic Guard** | Inspects for unauthorized background network connections. | ✅ |

## Installation

### macOS (DMG)
Download the latest `WASP.dmg` from the [Releases](https://github.com/ghostintheprompt/wasp/releases) page.

### Homebrew
```bash
brew install ghostintheprompt/tap/wasp
```

### Build from Source
```bash
git clone https://github.com/ghostintheprompt/wasp.git
cd wasp
pip install -r requirements.txt
```

## Usage

WASP requires root privileges to access hardware and put interfaces into monitor mode.

```bash
# Basic verification
sudo python3 wasp.py -i wlan1

# Generate signature for a new trusted device
sudo python3 wasp.py -i wlan1 --generate-signature

# Save verification traffic to a PCAP for audit
sudo python3 wasp.py -i wlan1 --pcap audit.pcap

# Check for updates
python3 wasp.py --check-updates
```

## Privacy Statement

**Local Only.** WASP does not collect telemetry, usage statistics, or personal data. All verification logic runs locally on your machine. The only network connection made is an optional, lightweight check to GitHub's public API to verify the latest version.

---

**Built by [MDRN Corp](https://mdrn.app)**
