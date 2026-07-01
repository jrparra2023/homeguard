#!/usr/bin/env python3
"""
HomeGuard - Device Fingerprinter
Detecta OS probable de cada dispositivo via TTL y TCP window size.
Requiere sudo.
"""

import json
import argparse
import datetime
from collections import defaultdict
from pathlib import Path
from scapy.all import sniff, IP, TCP, ICMP

BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"
FINGERPRINT_LOG = LOGS_DIR / "fingerprints.json"

# TTL típicos por OS
TTL_MAP = {
    (60, 70):   "Linux",
    (126, 130): "Windows",
    (253, 256): "Cisco/Network Device",
    (1, 10):    "Proxy/VPN hop",
}

# TCP Window Size típicos
WINDOW_MAP = {
    65535: "macOS / BSD",
    8192:  "Windows XP/2003",
    65535: "Linux (tuned)",
    29200: "Linux (default)",
    64240: "Windows 10/11",
    5840:  "Linux (older)",
}

results = {}


def guess_os_ttl(ttl: int) -> str:
    for (lo, hi), os_name in TTL_MAP.items():
        if lo <= ttl <= hi:
            return os_name
    return "Unknown"


def guess_os_window(window: int) -> str:
    return WINDOW_MAP.get(window, f"Unknown (win={window})")


def process_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        ttl = pkt[IP].ttl
        os_ttl = guess_os_ttl(ttl)

        entry = results.get(src, {"ip": src, "ttl": ttl, "os_ttl": os_ttl, "os_window": "—", "window": None})

        if TCP in pkt:
            window = pkt[TCP].window
            os_win = guess_os_window(window)
            entry["window"] = window
            entry["os_window"] = os_win

        results[src] = entry


def run(interface: str, duration: int, subnet: str):
    print(f"[HomeGuard] Fingerprinter activo en '{interface}' por {duration}s...\n")
    sniff(iface=interface, prn=process_packet, timeout=duration, store=False)

    # Filtrar solo subred local
    local = {ip: v for ip, v in results.items() if ip.startswith(subnet)}

    if not local:
        print("[HomeGuard] No se capturó tráfico local.")
        return

    print(f"{'IP':<18} {'TTL':<6} {'OS (TTL)':<22} {'Window':<8} {'OS (Window)'}")
    print("-" * 80)
    report = []
    for ip, d in sorted(local.items()):
        print(f"{ip:<18} {d['ttl']:<6} {d['os_ttl']:<22} {str(d['window'] or '—'):<8} {d['os_window']}")
        report.append({**d, "timestamp": datetime.datetime.now().isoformat()})

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with open(FINGERPRINT_LOG, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[INFO] Fingerprints guardados en {FINGERPRINT_LOG}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HomeGuard Fingerprinter")
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--subnet", default="192.168.1.")
    args = parser.parse_args()
    run(args.iface, args.duration, args.subnet)
