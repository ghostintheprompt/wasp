# WASP: WiFi Adapter Security Protocol - Technical Guide

Welcome to the **Ghost-Protocol Tier** of wireless hardware auditing. This guide provides the deep technical research and theory behind the WASP framework.

## 1. High-Fidelity Scenarios (The Offensive Logic)

### [s1] Firmware Ghosting
*   **Theory:** Malicious firmware can inject management frames that are invisible to the host OS. This scenario monitors for frames with null or unauthorized OUIs (00:00:00) and specific 802.11 sub-types that suggest C2 activity.
*   **Action:** WASP uses `scapy` to sniff management frames and parses the `RadioTap` header for anomalies in frame length and encryption bitmasks.

### [s2] Shadow Monitor Mode
*   **Theory:** An adapter can be put into monitor mode by an attacker via a kernel-level hook without updating the OS networking stack's reported state.
*   **Action:** WASP performs a "State Persistence" check by polling the hardware registers directly (via `iw` or `airport`) and contrasting it against the reported driver state.

### [s4] SSID Buffer Overflow (CVE-2026-WASP-01)
*   **Theory:** Oversized SSID strings (exceeding 32 bytes) or those containing nested null bytes can crash legacy WiFi drivers or trigger RCE.
*   **Action:** WASP simulates a malformed probe response to test the driver's bounds-checking integrity.

## 2. Cyber SOC: Neural Defense Center

The SOC correlates raw hardware metrics into actionable incidents.
*   **[INC-WASP-003] Excessive Power Draw:** Uses `ioreg` (macOS) or `/sys` (Linux) to detect spikes in `milliAmps`. A 20%+ spike often indicates an active hardware implant or side-channel exfiltration in progress.
*   **[INC-WASP-008] Hardware HID Injection:** Monitors the USB bus for the appearance of secondary HID (keyboard/mouse) interfaces from a single physical WiFi device.

## 3. The Dirty Dozen+ Guardrails

Guardrails are active enforcements that prevent logic drift during operation.
*   **Identity Integrity:** Verifies the adapter's MAC address against the hardcoded ROM values using the `ETHTOOL_GGSO` equivalent on modern chipsets.
*   **Power Circuit Breaker:** An automated tripwire that halts the verification process if power consumption exceeds safe research thresholds.

## 4. Operational Requirements
*   **Root Privileges:** Required for `libpcap` access and hardware register polling.
*   **Monitor Mode Support:** The adapter must support `monitor mode` for behavioral audits.

---
*Built by MDRN Corp for the Ghost In The Prompt research initiative.*
