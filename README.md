<p align="center">
  <img src="assets/wasp_logo.png" alt="WASP Logo" width="500">
</p>

# WASP: WiFi Adapter Security Protocol (Ghost-Protocol Tier)

**WASP** is a high-fidelity verification framework for auditing the integrity and security of wireless network adapters. Optimized with the **Ghost Proxy** methodology, WASP goes beyond simple hardware identification to provide deep-behavioral analysis and offensive-scenario simulation.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](#)
[![Release](https://img.shields.io/badge/release-v1.4.0-purple.svg)](https://github.com/ghostintheprompt/wasp/releases)

## Why WASP v1.4?

In 2026, compromised hardware is no longer a fringe threat—it's an industrial standard. New and second-hand network equipment can contain malicious firmware, shadow DOM-style overlays in the driver, or unauthorized hardware-level exfiltration. WASP v1.4 introduces the **Ghost-Protocol Optimization**, bridging the gap between hardware audit and offensive security research.

## Core Modules

| Module | Capability | Persistence |
| :--- | :--- | :--- |
| **THREAT_SIMULATOR** | executes 12 high-fidelity WiFi scenarios (e.g., Firmware Ghosting) | Volatile |
| **CYBER_SOC** | Neural Defense Center tracking 8 unique WiFi incidents (INC-...) | Session |
| **GUARDRAIL_ENGINE** | Enforces the "Dirty Dozen+" security policies in real-time | Active |
| **BEHAVIOR_AUDIT** | Monitors packet patterns and USB power for covert channels | Local DB |

## Ghost Proxy Manifest v1.4 (WASP Edition)

### 1. High-Fidelity WiFi Scenarios
The simulator now executes **12 specialized scenarios**:
*   **Firmware Ghosting:** Detecting hidden frames or unauthorized vendor-specific OUI usage.
*   **Shadow Monitor Mode:** Identifying unrequested hardware-level state shifts.
*   **SSID Buffer Overflow:** Testing driver resilience against malformed SSID strings.
*   **OUI Identity Hijack:** Verifying hardware ID persistence under extreme load.
*   **Timing Attack Analysis:** Spotting micro-delays that indicate hardware-level processing.

### 2. Cyber SOC: Neural Defense Center
Managing **8 active WiFi events** with AI correlation:
*   **[INC-WASP-001] Unexpected Monitor Transition**
*   **[INC-WASP-003] Excessive Power Draw (20%+ spike)**
*   **[INC-WASP-004] Management Frame Leak**
*   **[INC-WASP-008] Hardware HID Injection (Rubber Ducky detection)**

### 3. The Dirty Dozen+ Guardrails
Protected by 12+ security enforcements, including:
*   **State Lockdown:** Preventing unrequested Managed <-> Monitor mode shifts.
*   **Power Circuit Breaker:** Automated alerts on anomalous USB power draw.
*   **OUI Whitelisting:** Enforcing communication only with verified hardware vendors.
*   **SSID Sanitization:** Filtering malformed packets before they reach the OS stack.

## Usage

WASP requires root privileges to access hardware and simulate offensive scenarios.

```bash
# Full high-fidelity audit
sudo python3 wasp.py -i wlan1 --ghost-mode

# Run a specific scenario (e.g., Firmware Ghosting)
sudo python3 wasp.py -i wlan1 --scenario s1

# Check for incidents in the local SOC
python3 wasp.py --soc-logs
```

## Privacy Statement

**Zero-Telemetry.** WASP v1.4 maintains a strict local-only architecture. No usage statistics or hardware signatures are uploaded. All AI-assisted correlation is performed locally.

---

**Built by [MDRN Corp](https://mdrn.app)**
