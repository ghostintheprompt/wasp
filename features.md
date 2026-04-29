# WASP Internal Feature Registry

This document is the source of truth for all research logic and data integrated into WASP (WiFi Adapter Security Protocol). **Mandate: No feature listed here shall be deleted or simplified during future updates.**

## 1. High-Fidelity WiFi Scenarios (Offensive/Research Scenarios)
- **[s1] Firmware Ghosting:** Detection of hidden frames or unauthorized vendor-specific OUI usage.
- **[s2] Shadow Monitor Mode:** Detecting if the adapter switches state without host command (hardware-level hijacking).
- **[s3] Power Injection Leak:** Monitoring for high-frequency power fluctuations indicating hardware-level data exfiltration.
- **[s4] Buffer Overflow Probe (SSID Poisoning):** Testing driver resilience against oversized/malformed SSID strings (CVE-2026-WASP-01).
- **[s5] OUI Spoofing & Identity Hijack:** Verifying hardware ID persistence and detecting "Hardware-ID Clones".
- **[s6] Timing Attack Analysis:** Identifying micro-delays in frame processing that suggest hardware-level MITM.
- **[s7] Side-Channel Exfiltration:** Monitoring for covert channels (e.g., LED patterns or specific USB timing variations).
- **[s8] Beacon Flood Resilience:** Stress-testing hardware/driver behavior under high-entropy beacon frame injection.
- **[s9] Deauth Defense Integrity:** Verifying the adapter's handling of unsolicited 802.11 deauthentication management frames.
- **[s10] Malicious Driver Hook:** Detecting unauthorized hooks in the kernel/adapter communication layer.
- **[s11] Hidden SSID Egress:** Checking if the hardware broadcasts hidden management frames to unauthorized OUIs.
- **[s12] Hardware-Level HID Emulation:** Monitoring for "Rubber Ducky" style HID injection during WiFi activity.

## 2. Cyber SOC: WiFi Defense Center (Incidents)
- **[INC-WASP-001] Unexpected Monitor Transition:** Adapter switched to monitor mode without system request.
- **[INC-WASP-002] OUI Mismatch Detection:** Hardware identity does not match the driver's reported Vendor ID.
- **[INC-WASP-003] Excessive Power Draw:** Detected 20%+ spike in USB power consumption.
- **[INC-WASP-004] Management Frame Leak:** Adapter is sending frames while supposedly in "Managed/Idle" state.
- **[INC-WASP-005] Driver Hook Anomaly:** Unauthorized memory modification detected in the WiFi driver space.
- **[INC-WASP-006] SSID Buffer Overrun Attempt:** Detected malformed SSID broadcast in the immediate vicinity.
- **[INC-WASP-007] Covert Channel Signature:** Identified high-entropy bitstream in management frame padding.
- **[INC-WASP-008] Hardware HID Injection:** Detected keyboard/mouse emulation from the WiFi adapter.

## 3. WASP Guardrails (The Dirty Dozen+)
1.  **Identity Integrity:** Blocks unauthorized MAC/OUI changes at the hardware level.
2.  **State Lockdown:** Prevents unrequested mode shifts (Managed <-> Monitor).
3.  **Egress Filter:** Blocks frames targeting non-local or suspicious management OUIs.
4.  **Power Circuit Breaker:** Alerts on 20%+ power spikes during standard operations.
5.  **Frame Entropy Monitor:** Detects encrypted/obfuscated management frames (Potential C2).
6.  **OUI Whitelisting:** Enforces hardware communication only with known-good vendor IDs.
7.  **SSID Sanitization:** Filters incoming SSID strings before they reach the OS network stack.
8.  **Driver Signature Check:** Verifies hash integrity of the active WiFi driver.
9.  **USB Path Isolation:** Blocks the adapter from appearing as a multi-function HID/Storage device.
10. **Timing Jitter Defense:** Normalizes frame processing times to defeat side-channel analysis.
11. **Beacon Filter:** Automatically drops beacon floods that exceed the hardware's buffer capacity.
12. **Zero-Trust Firmware:** Requires hardware-level cryptographic signatures for firmware loading.

---
**Last Updated: April 28, 2026 (Ghost-Protocol Optimization)**
**Integrity Protocol: V1.4 (WiFi Fidelity Expansion)**
