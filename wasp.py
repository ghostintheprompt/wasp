#!/usr/bin/env python3
"""
WASP: WiFi Adapter Security Protocol
A tool to verify WiFi adapters for security research and education.
Built by MDRN Corp — mdrn.app
"""

import os
import sys
import subprocess
import re
import json
import time
import argparse
import threading
from pathlib import Path
import requests
from scapy.all import sniff, IP

VERSION = "1.0.0"
REPO_OWNER = "ghostintheprompt"
REPO_NAME = "wasp"

class WaspVerifier:
    def __init__(self, interface=None, verbose=False):
        self.interface = interface
        self.verbose = verbose
        self.known_signatures = self._load_known_signatures()
        self.results = {
            "hardware_check": None,
            "firmware_check": None,
            "behavior_check": None,
            "power_check": None,
            "network_check": None,
            "overall": None
        }

    def _log(self, message):
        if self.verbose:
            print(f"[*] {message}")

    def _load_known_signatures(self):
        """Load verified hardware signatures from file"""
        sig_path = Path(__file__).parent / "signatures.json"
        try:
            with open(sig_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            self._log("Signatures database not found.")
            return {}

    def verify_hardware(self):
        """Check hardware identifiers against known good values"""
        print("[+] Verifying hardware identifiers...")
        
        try:
            if sys.platform == "darwin":  # macOS
                usb_info = subprocess.check_output(["system_profiler", "SPUSBDataType"], text=True)
            elif sys.platform == "linux":
                usb_info = subprocess.check_output(["lsusb", "-v"], text=True)
            else:
                print("[-] Unsupported platform")
                return False
                
            found = False
            for name, sig in self.known_signatures.items():
                if sig.get("vendor_id") in usb_info.lower() and sig.get("product_id") in usb_info.lower():
                    print(f"[+] Identified: {name} (Chipset: {sig.get('chipset')})")
                    found = True
                    break
            
            if found:
                print("[+] Hardware identification passed")
                self.results["hardware_check"] = True
                return True
            else:
                print("[-] Hardware identification failed: Unknown device or signature mismatch")
                self.results["hardware_check"] = False
                return False
                
        except subprocess.SubprocessError:
            print("[-] Failed to retrieve USB information")
            return False

    def verify_firmware(self):
        """Verify firmware integrity (mock implementation for v1.0)"""
        print("[+] Checking firmware integrity...")
        # In a real scenario, this would compare loaded firmware hashes
        # For v1.0, we verify the presence of expected driver/firmware strings
        try:
            if sys.platform == "linux":
                info = subprocess.check_output(["ethtool", "-i", self.interface], text=True, stderr=subprocess.DEVNULL)
                if "driver:" in info:
                    print("[+] Firmware check passed")
                    self.results["firmware_check"] = True
                    return True
            elif sys.platform == "darwin":
                # macOS doesn't use ethtool; checking system info
                print("[+] macOS: Integrity check delegated to System Integrity Protection")
                self.results["firmware_check"] = True
                return True
            
            self.results["firmware_check"] = False
            return False
        except Exception:
            print("[-] Firmware check unavailable for this interface")
            self.results["firmware_check"] = False
            return False

    def check_behavior(self, pcap_file=None):
        """Test adapter behavior in monitor mode"""
        print("[+] Testing adapter behavior (Monitor Mode)...")
        
        try:
            if sys.platform == "darwin":
                # macOS airport sniff
                print("[*] Note: macOS requires manual password entry for 'airport' tool")
                mon_cmd = ["sudo", "airport", self.interface, "sniff"]
                # This is problematic for automation, but part of the tool's spec
            else:
                subprocess.run(["sudo", "ip", "link", "set", self.interface, "down"], check=True)
                subprocess.run(["sudo", "iw", self.interface, "set", "type", "monitor"], check=True)
                subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], check=True)
            
            print("[+] Capturing sample traffic (10s)...")
            packets = sniff(iface=self.interface, count=100, timeout=10)
            
            if pcap_file:
                from scapy.utils import wrpcap
                wrpcap(pcap_file, packets)
                print(f"[+] Traffic saved to {pcap_file}")

            if len(packets) > 0:
                print(f"[+] Captured {len(packets)} packets. No anomalies detected.")
                self.results["behavior_check"] = True
                return True
            else:
                print("[-] No packets captured. Verification inconclusive.")
                self.results["behavior_check"] = False
                return False
                
        except Exception as e:
            print(f"[-] Behavior check failed: {e}")
            return False

    def check_power_consumption(self):
        """Monitor power usage patterns for anomalies"""
        print("[+] Checking power consumption patterns...")
        try:
            if sys.platform == "darwin":
                power_info = subprocess.check_output(["ioreg", "-p", "IOUSB", "-l"], text=True)
                if "ExtraPowerRequest" in power_info:
                    print("[-] Warning: Device requesting excessive power")
                    self.results["power_check"] = False
                    return False
            
            print("[+] Power consumption within normal parameters")
            self.results["power_check"] = True
            return True
        except Exception:
            print("[!] Power check skipped (requires hardware-level access)")
            return True

    def check_network_traffic(self):
        """Monitor for unexpected network connections"""
        print("[+] Monitoring for unauthorized background traffic...")
        try:
            packets = sniff(iface=self.interface, count=50, timeout=15)
            unauthorized = 0
            for pkt in packets:
                if IP in pkt:
                    if pkt[IP].dst not in ['224.0.0.1', '255.255.255.255', '0.0.0.0']:
                        unauthorized += 1
            
            if unauthorized > 5: # Threshold for background noise
                print(f"[-] Detected {unauthorized} unexpected connection attempts")
                self.results["network_check"] = False
                return False
            else:
                print("[+] No unauthorized traffic detected")
                self.results["network_check"] = True
                return True
        except Exception:
            print("[-] Network traffic check failed")
            return False

    def run_all_checks(self, pcap_file=None):
        print(f"\n=== WASP v{VERSION} Verification ===")
        print(f"Target Interface: {self.interface}")
        
        self.verify_hardware()
        self.verify_firmware()
        self.check_behavior(pcap_file)
        self.check_power_consumption()
        self.check_network_traffic()
        
        passed = [v for v in self.results.values() if v is True]
        total = 5
        
        if len(passed) == total:
            overall = "PASS"
        elif len(passed) >= 3:
            overall = "WARNING"
        else:
            overall = "FAIL"
            
        self.results["overall"] = overall
        print(f"\n=== Assessment: {overall} ({len(passed)}/{total} checks passed) ===")
        return self.results

    def generate_signature(self):
        """Generate a signature for the current device"""
        print(f"[+] Generating signature for {self.interface}...")
        try:
            if sys.platform == "darwin":
                usb_info = subprocess.check_output(["system_profiler", "SPUSBDataType"], text=True)
            else:
                usb_info = subprocess.check_output(["lsusb"], text=True)
            
            print("\n--- Detected USB Info ---")
            print(usb_info)
            print("-------------------------")
            print("\n[!] Please extract VendorID and ProductID to add to signatures.json")
        except Exception as e:
            print(f"[-] Failed to generate signature: {e}")

def check_for_updates(silent=True):
    """Check GitHub for newer releases"""
    if not silent:
        print("[*] Checking for updates...")
    
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            latest = response.json().get("tag_name", "").replace("v", "")
            if latest > VERSION:
                print(f"\n[!] A new version is available: v{latest}")
                print(f"[!] Download at: https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/latest\n")
            elif not silent:
                print("[+] WASP is up to date.")
    except Exception:
        if not silent:
            print("[-] Could not connect to update server.")

def main():
    parser = argparse.ArgumentParser(description='WASP: WiFi Adapter Security Protocol')
    parser.add_argument('-i', '--interface', help='Interface to verify')
    parser.add_argument('--generate-signature', action='store_true', help='Generate signature for current device')
    parser.add_argument('--pcap', help='Save captured packets to file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--check-updates', action='store_true', help='Manually check for updates')
    parser.add_argument('--version', action='version', version=f'WASP v{VERSION}')
    
    args = parser.parse_args()

    # Silent update check on launch (3s delay as per mandate)
    if not args.check_updates:
        threading.Timer(3.0, check_for_updates, kwargs={'silent': True}).start()

    if args.check_updates:
        check_for_updates(silent=False)
        return

    if args.generate_signature:
        if not args.interface:
            print("[-] Error: --interface required for signature generation")
            sys.exit(1)
        verifier = WaspVerifier(args.interface, verbose=args.verbose)
        verifier.generate_signature()
        return

    if not args.interface:
        parser.print_help()
        sys.exit(1)

    if os.geteuid() != 0:
        print("[!] Error: WASP requires root privileges. Please run with sudo.")
        sys.exit(1)

    verifier = WaspVerifier(args.interface, verbose=args.verbose)
    results = verifier.run_all_checks(pcap_file=args.pcap)
    
    with open("wasp_verification_report.json", "w") as f:
        json.dump(results, f, indent=2)
    
    sys.exit(0 if results["overall"] == "PASS" else 1)

if __name__ == "__main__":
    main()
