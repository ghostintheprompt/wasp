# WASP Feature Registry

The original research design is retained below with implementation status. Proposed work is not a shipping claim. This registry does not establish a CVE assignment or hardware-verification result.

## Scenario status

| ID | Research name | Implementation |
|---|---|---|
| s1 | Firmware Ghosting | Implemented as a zero-prefix management-transmitter heuristic; no firmware inspection |
| s2 | Shadow Monitor Mode | Implemented as Linux driver-reported mode polling; no kernel inspection |
| s3 | Power Injection Leak | Proposed; no measured-current or exfiltration detector |
| s4 | SSID Buffer Overflow Probe | Implemented as passive SSID length inspection; no driver probing or verified CVE |
| s5 | OUI Spoofing and Identity Hijack | Proposed; host USB ID inventory does not implement this |
| s6 | Timing Attack Analysis | Proposed |
| s7 | Side-Channel Exfiltration | Proposed |
| s8 | Beacon Flood Resilience | Implemented as capture-time beacon-rate thresholding; no resilience test |
| s9 | Deauth Defense Integrity | Proposed |
| s10 | Malicious Driver Hook | Proposed |
| s11 | Hidden SSID Egress | Proposed |
| s12 | Hardware-Level HID Emulation | Proposed |

## Incident status

Implemented: `INC-WASP-001` observed mode change, `INC-WASP-004` zero-prefix management transmitter, `INC-WASP-006` malformed captured SSID, and `INC-WASP-009` beacon-rate threshold crossing. These names do not establish an attack or attribution.

The original planned IDs `002` (identity mismatch), `003` (power draw), `005` (driver hook), `007` (covert channel), and `008` (HID injection) have no implemented detector. An unknown USB ID is not evidence of tampering.

## Policy roadmap

Identity Integrity, State Lockdown, Egress Filter, Power Circuit Breaker, Frame Entropy Monitor, OUI Whitelisting, SSID Sanitization, Driver Signature Check, USB Path Isolation, Timing Jitter Defense, Beacon Filter, and Zero-Trust Firmware remain proposed enforcement policies. None is currently enforced by WASP. A reported MAC and passive packet warnings are observations, not prevention.
