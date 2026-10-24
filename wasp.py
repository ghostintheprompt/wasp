#!/usr/bin/env python3
"""WASP: passive WiFi observations and offline packet checks. No RF injection."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from collections import defaultdict
from scapy.all import sniff, rdpcap, Dot11, Dot11Beacon, Dot11Elt

VERSION = '1.4.2'


def result(status, detail, **evidence):
    return {'status': status, 'detail': detail, **evidence}


class CyberSOC:
    """Local incident ledger, without AI correlation or hardware enforcement."""
    def __init__(self, incidents_path='wasp_incidents.json'):
        self.incidents_path = Path(incidents_path)
        if self.incidents_path.exists():
            self.incidents = json.loads(self.incidents_path.read_text())
            if not isinstance(self.incidents, list):
                raise ValueError('Incident ledger must contain a JSON array')
        else:
            self.incidents = []

    def log_incident(self, incident_id, description, severity='MEDIUM'):
        self.incidents.append({'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                               'id': incident_id, 'description': description, 'severity': severity})
        self.incidents_path.write_text(json.dumps(self.incidents, indent=2) + '\n')
        print(f'[!] [{incident_id}] {description} ({severity})')

    def display_logs(self):
        for incident in self.incidents[-20:]:
            print(json.dumps(incident))


class ThreatSimulator:
    """Legacy class name retained; scenarios now observe packets/state, not resilience."""
    def __init__(self, interface, soc, packets=None):
        self.interface, self.soc, self.packets = interface, soc, packets

    def _packets(self):
        if self.packets is None:
            self.packets = list(sniff(iface=self.interface, count=500, timeout=10, store=True))
        return self.packets

    def run_scenario(self, scenario_id):
        handlers = {'s1': self.scenario_firmware_ghosting, 's2': self.scenario_shadow_monitor,
                    's4': self.scenario_ssid_overflow, 's8': self.scenario_beacon_flood}
        if scenario_id not in handlers:
            raise ValueError(f'Unsupported scenario: {scenario_id}; supported: s1, s2, s4, s8')
        try:
            return handlers[scenario_id]()
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            return result('UNAVAILABLE', str(error))

    def scenario_firmware_ghosting(self):
        """Flag zero-prefix management transmitters; this does not inspect firmware."""
        frames = [p for p in self._packets() if p.haslayer(Dot11) and p[Dot11].type == 0]
        hits = sorted({p[Dot11].addr2 for p in frames if p[Dot11].addr2 and
                       p[Dot11].addr2.lower().startswith('00:00:00')})
        for address in hits:
            self.soc.log_incident('INC-WASP-004', f'Zero-prefix management transmitter: {address}')
        return result('FINDING' if hits else ('NO_FINDINGS' if frames else 'UNAVAILABLE'),
                      'Zero-prefix address heuristic; not proof of hidden traffic or malicious firmware',
                      management_frames=len(frames), transmitters=hits)

    def _get_mode(self):
        if sys.platform != 'linux':
            return None
        try:
            output = subprocess.check_output(['iw', 'dev', self.interface, 'info'], text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return None
        match = re.search(r'^\s*type\s+(\S+)', output, re.MULTILINE)
        return match.group(1) if match else None

    def scenario_shadow_monitor(self):
        initial = self._get_mode()
        if initial is None:
            return result('UNAVAILABLE', 'Mode observation requires Linux iw; no mode inferred')
        for _ in range(5):
            time.sleep(1)
            current = self._get_mode()
            if current is None:
                return result('UNAVAILABLE', 'Mode became unreadable during observation')
            if current != initial:
                self.soc.log_incident('INC-WASP-001', f'Observed mode change: {initial} -> {current}')
                return result('FINDING', 'Mode changed; cause and authorization are not determined', initial=initial, current=current)
        return result('NO_FINDINGS', 'No mode change in five polls; no prevention or kernel inspection', initial=initial)

    def scenario_ssid_overflow(self):
        """Inspect captured SSID information elements; never send malformed frames."""
        frames = 0
        malformed = 0
        for packet in self._packets():
            if not packet.haslayer(Dot11) or packet[Dot11].type != 0:
                continue
            element = packet.getlayer(Dot11Elt)
            while isinstance(element, Dot11Elt):
                if element.ID == 0:
                    frames += 1
                    declared = element.len if element.len is not None else len(element.info)
                    if declared > 32 or len(element.info) > 32 or declared != len(element.info):
                        malformed += 1
                element = element.payload
        if malformed:
            self.soc.log_incident('INC-WASP-006', f'{malformed} malformed SSID information element(s)')
        return result('FINDING' if malformed else ('NO_FINDINGS' if frames else 'UNAVAILABLE'),
                      'Captured SSID length check; no driver crash, RCE or resilience test',
                      ssid_elements=frames, malformed=malformed)

    def scenario_beacon_flood(self):
        """Count beacons per capture-time second; threshold is configurable only in code."""
        buckets = defaultdict(int)
        for packet in self._packets():
            if packet.haslayer(Dot11Beacon):
                buckets[int(packet.time)] += 1
        peak = max(buckets.values(), default=0)
        if peak >= 100:
            self.soc.log_incident('INC-WASP-009', f'Beacon-rate threshold reached: {peak} in a capture-time second')
        return result('FINDING' if peak >= 100 else ('NO_FINDINGS' if buckets else 'UNAVAILABLE'),
                      '100-beacons-per-second heuristic; no buffer stress or hardware resilience claim',
                      peak_per_second=peak, threshold=100)


class GuardrailEngine:
    """Observation-only checks. Does not block, sanitize or alter hardware state."""
    def __init__(self, interface, soc):
        self.interface, self.soc = interface, soc

    def enforce_policies(self):
        return {'identity': self._check_identity_integrity(), 'power': self._check_power_circuit_breaker()}

    def _check_identity_integrity(self):
        if sys.platform != 'linux' or not self.interface or not re.fullmatch(r'[A-Za-z0-9_.:-]+', self.interface):
            return result('UNAVAILABLE', 'MAC observation requires a Linux interface; no ROM identity validation')
        try:
            address = (Path('/sys/class/net') / self.interface / 'address').read_text().strip()
            return result('OBSERVED', 'Reported interface MAC; not authenticated hardware identity', address=address)
        except OSError as error:
            return result('UNAVAILABLE', str(error))

    def _check_power_circuit_breaker(self):
        return result('UNSUPPORTED', 'No measured USB current source; no power-spike detection or circuit breaker')


class WaspVerifier:
    def __init__(self, interface=None, verbose=False, packets=None, soc=None):
        self.interface, self.verbose = interface, verbose
        self.soc = soc or CyberSOC()
        self.simulator = ThreatSimulator(interface, self.soc, packets)
        self.guardrails = GuardrailEngine(interface, self.soc)
        self.known_signatures = json.loads((Path(__file__).parent / 'signatures.json').read_text())
        self.results = {}

    def verify_hardware(self):
        """Enumerate candidate USB IDs together per device, never across devices."""
        try:
            if sys.platform == 'linux':
                output = subprocess.check_output(['lsusb'], text=True, timeout=10)
                devices = re.findall(r'\bID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\b', output)
            elif sys.platform == 'darwin':
                output = subprocess.check_output(['system_profiler', '-json', 'SPUSBDataType'], text=True, timeout=30)
                devices = []
                def walk(node):
                    if isinstance(node, dict):
                        vendor = re.search(r'0x([0-9a-fA-F]{4})', str(node.get('vendor_id', '')))
                        product = re.search(r'0x([0-9a-fA-F]{4})', str(node.get('product_id', '')))
                        if vendor and product:
                            devices.append((vendor.group(1), product.group(1)))
                        for value in node.values():
                            walk(value)
                    elif isinstance(node, list):
                        for value in node:
                            walk(value)
                walk(json.loads(output))
            else:
                return result('UNAVAILABLE', 'USB inventory supported on macOS/Linux')
            matches = [name for name, signature in self.known_signatures.items() if
                       (signature['vendor_id'].lower(), signature['product_id'].lower()) in
                       [(v.lower(), p.lower()) for v, p in devices]]
            return result('OBSERVED', 'Candidate USB ID matches across host inventory; not linked to the selected interface or proof of authenticity', candidates=matches, usb_devices=len(devices))
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            return result('UNAVAILABLE', str(error))

    def check_behavior(self):
        try:
            packets = self.simulator._packets()
            count = sum(p.haslayer(Dot11) for p in packets)
            return result('OBSERVED' if count else 'UNAVAILABLE', '802.11 frame availability; packet receipt alone is not an integrity check', frames=count)
        except (OSError, subprocess.SubprocessError) as error:
            return result('UNAVAILABLE', str(error))

    def run_ghost_audit(self):
        checks = {key: self.simulator.run_scenario(key) for key in ('s1', 's2', 's4', 's8')}
        checks['observations'] = self.guardrails.enforce_policies()
        return checks

    def run_all_checks(self, ghost_mode=False):
        self.results = {'hardware_check': self.verify_hardware(), 'behavior_check': self.check_behavior(),
                        'scope': 'Passive observations only. No firmware verification, enforcement or hardware safety certification.'}
        if ghost_mode:
            self.results['ghost_audit'] = self.run_ghost_audit()
        # An observation-only tool must never certify hardware as PASS.
        self.results['overall'] = 'OBSERVATIONS_ONLY'
        return self.results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-i', '--interface')
    parser.add_argument('--pcap', help='Read captured packets without root or RF activity')
    parser.add_argument('--ghost-mode', action='store_true', help='Run supported passive checks, not enforcement')
    parser.add_argument('--scenario', choices=['s1', 's2', 's4', 's8'])
    parser.add_argument('--soc-logs', action='store_true')
    parser.add_argument('--incidents', default='wasp_incidents.json')
    parser.add_argument('--report', default='wasp_verification_report.json')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--version', action='version', version=f'WASP v{VERSION}')
    args = parser.parse_args()
    soc = CyberSOC(args.incidents)
    if args.soc_logs:
        soc.display_logs()
        return 0
    if not args.pcap and not args.interface:
        parser.error('Specify --pcap or --interface')
    if args.pcap and args.scenario == 's2':
        parser.error('s2 requires a live Linux interface; it cannot be inferred from a capture')
    if not args.pcap and os.geteuid() != 0:
        parser.error('Live capture requires root; offline --pcap does not')
    try:
        packets = list(rdpcap(args.pcap)) if args.pcap else None
        verifier = WaspVerifier(args.interface, args.verbose, packets, soc)
        if args.pcap:
            keys = [args.scenario] if args.scenario else ['s1', 's4', 's8']
            report = {key: verifier.simulator.run_scenario(key) for key in keys}
        elif args.scenario:
            report = {args.scenario: verifier.simulator.run_scenario(args.scenario)}
        else:
            report = verifier.run_all_checks(args.ghost_mode)
        Path(args.report).write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        statuses = []
        def collect(node):
            if isinstance(node, dict):
                if 'status' in node:
                    statuses.append(node['status'])
                for value in node.values():
                    collect(value)
        collect(report)
        return 1 if 'FINDING' in statuses else (2 if any(s in ('UNAVAILABLE', 'UNSUPPORTED') for s in statuses) else 0)
    except (OSError, ValueError) as error:
        print(f'WASP error: {error}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
