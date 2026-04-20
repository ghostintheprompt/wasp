# Building WASP

Follow these instructions to build and run WASP from source.

## Prerequisites

- Python 3.8 or higher
- `pip` (Python package manager)
- `libpcap` (usually pre-installed on macOS/Linux)

## 1. Clone the Repository

```bash
git clone https://github.com/ghostintheprompt/wasp.git
cd wasp
```

## 2. Install Dependencies

It is recommended to use a virtual environment.

```bash
# Optional: Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required packages
pip install -r requirements.txt
```

## 3. First Launch Instructions

WASP requires root privileges for most operations.

```bash
sudo python3 wasp.py --interface wlan0
```

## Troubleshooting

- **Scapy Warnings:** If you see `No libpcap provider found`, ensure `libpcap` is installed (`brew install libpcap` on macOS).
- **macOS Airport Tool:** Ensure the `airport` utility is in your path or linked:
  `sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport`

## Creating a DMG (macOS)

To package WASP as a DMG, use the provided script:

```bash
./make_dmg.sh
```
