# WASP Technical Guide

The useful boundary is between an observed packet and an explanation of its origin. WASP can count and inspect the packet. A suspicious address alone cannot prove a firmware implant.

## Packet checks

`s1` considers management frames only (`Dot11.type == 0`) and reports zero-prefix transmitters. It does not inspect RadioTap encryption bitmasks or determine whether a frame was hidden from the host.

`s4` walks captured SSID information elements. A length above 32 bytes or a mismatch between declared and available bytes produces a finding. Null bytes alone are not treated as evidence of a vulnerability. This is input inspection, not a driver exploit or a test of driver bounds checking. The earlier `CVE-2026-WASP-01` label was a project placeholder, not a verified CVE assignment, and must not be cited as a vulnerability identifier.

`s8` groups beacons by integer capture timestamp and reports a threshold crossing at 100 per second across the capture. This coarse threshold has no learned baseline and can flag legitimate busy networks. Packets arriving across a second boundary can split one burst between buckets. It neither injects frames nor measures hardware buffer capacity.

## Host observations

`s2` reads the Linux driver's reported interface mode using `iw`. It compares five subsequent polls with the initial reading. An unreadable initial or later mode returns `UNAVAILABLE`. A change is an observation, not proof of an unauthorized actor or a kernel hook. macOS mode observation is unavailable; no deprecated `airport` fallback is represented as a working path.

USB inventory reads `lsusb` on Linux or structured `system_profiler` output on macOS. Vendor and product IDs must occur in the same device record. Candidate matches are not proof of ROM identity, trusted firmware, or that the matched USB device backs the selected interface.

The identity observation reads the selected Linux interface's reported MAC from sysfs. Power checks return `UNSUPPORTED`: no instantaneous current measurement is present. Configuration descriptors and power requests cannot stand in for measured current.

## Reporting

Cyber SOC stores timestamped findings in a local JSON array. An unreadable ledger fails explicitly rather than being silently overwritten. The ledger is not signed, tamper-evident, or a concurrent multi-writer database. There is no neural correlation model.

Packet checks share the captured packet batch during a full live run. Empty or non-802.11 captures report the relevant checks as unavailable. `NO_FINDINGS` means the check found nothing in that observation window. Full assessments remain `OBSERVATIONS_ONLY`.
