<p align="center">
  <img src="assets/wasp_logo.png" alt="WASP Logo" width="500">
</p>

# WASP: WiFi Adapter Security Protocol

**Ghost-Protocol research bench. Passive observations, with the limits in the report.**

WASP inspects captured 802.11 frames, watches Linux interface-mode changes, inventories USB IDs, and records findings locally. It does not attest firmware, inspect kernel hooks, block packets, measure USB current, or certify an adapter as safe. The `ThreatSimulator` and `GuardrailEngine` class names remain for compatibility; their implemented methods are observation-only.

## Working checks

| Scenario | Mechanism | Boundary |
|---|---|---|
| `s1` Firmware Ghosting | Flags management-frame transmitters beginning `00:00:00` | Address heuristic, not firmware inspection or an OUI allowlist |
| `s2` Shadow Monitor | Reads `iw dev <interface> info` five times after an initial reading | Linux only; observes a change without attributing its cause |
| `s4` SSID length | Checks captured SSID elements for lengths above 32 bytes or declared/actual length mismatch | No probe transmission, driver crash test, or resilience result |
| `s8` Beacon rate | Flags 100 or more beacons in one capture-time second | Aggregate rate heuristic, not buffer-load measurement or flood prevention |

The USB inventory matches candidate vendor/product IDs within one device record. It does not associate that device with the selected network interface. `signatures.json` contains candidate labels inherited from the original project, not authenticated chipset, firmware or device-integrity evidence. No trusted firmware hash database is provided.

Cyber SOC is a JSON incident ledger, not an AI correlation system. Guardrail checks expose the reported Linux interface MAC where available and explicitly report power measurement as unsupported. No hardware state is changed.

## Run it

Use Python 3.8 or later and install Scapy in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Replay a capture without root or RF transmission:

```bash
python wasp.py --pcap capture.pcap --scenario s4
```

Omit `--scenario` to run all three packet checks against the capture. Offline mode does not inspect the host adapter. Live capture requires a compatible capture interface and appropriate privileges; WASP does not enable monitor mode:

```bash
sudo .venv/bin/python wasp.py --interface wlan1 --ghost-mode
```

Live capture collects up to 500 packets over 10 seconds. Mode observation adds five polls. Ethernet-formatted captures cannot establish 802.11 management-frame findings. macOS can provide USB inventory, but WASP currently has no macOS mode observer.

```bash
python wasp.py --soc-logs
python -m pip install pytest
python -m pytest -q
```

Reports default to `wasp_verification_report.json`; the ledger defaults to `wasp_incidents.json`. Override them with `--report` and `--incidents`. Exit codes are `0` for completed requested observations without findings, `1` for findings, and `2` for unavailable/unsupported checks or input errors. Zero is not a hardware-safety verdict. Full reports say `OBSERVATIONS_ONLY`; individual checks distinguish `FINDING`, `NO_FINDINGS`, `OBSERVED`, `UNAVAILABLE`, and `UNSUPPORTED`.

## Verification and scope

The automated suite uses constructed Scapy frames, PCAP replay, mocked platform command output, and CLI subprocesses. It checks both detection and benign cases. This audit did not exercise a physical USB adapter, live RF capture, Linux `iw`, or the macOS packaging process. The old 1.0.0 DMG predates this implementation and is not a validated build of it.

The original 12-scenario and 12-policy design remains in [features.md](features.md) as a roadmap with implementation status. It is not a list of shipped capabilities. See [WASP_GUIDE.md](WASP_GUIDE.md) for the implemented mechanics.

## Privacy

No network API or AI service is called by WASP. Capture data and findings remain in local files unless you move them. Live capture reads the selected interface; it does not inject traffic.

**Built by [MDRN Corp](https://mdrn.app)**
