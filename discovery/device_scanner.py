"""
HomeGuard — device_scanner.py
Descubre todos los dispositivos activos en la red local via ARP scan.
Autor: José Rafael Parra Dugarte
"""

from scapy.all import ARP, Ether, srp
from datetime import datetime, timezone
import json
import os
import sys

try:
    from manuf import manuf
    MAC_PARSER = manuf.MacParser()
except Exception:
    MAC_PARSER = None

LOG_PATH = os.path.join(os.path.dirname(__file__), "../logs/devices.json")


def get_vendor(mac):
    """Identifica el fabricante por el prefijo MAC."""
    if MAC_PARSER is None:
        return "Unknown"
    try:
        vendor = MAC_PARSER.get_manuf(mac)
        return vendor if vendor else "Unknown"
    except Exception:
        return "Unknown"


def scan_network(subnet):
    """
    Hace ARP scan a toda la subred.
    subnet ejemplo: '192.168.1.0/24'
    """
    print(f"[HomeGuard] Escaneando red: {subnet} ...")

    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    # timeout=3 da tiempo suficiente para que todos los dispositivos respondan
    answered, _ = srp(packet, timeout=3, verbose=False)

    devices = []
    for sent, received in answered:
        device = {
            "ip":           received.psrc,
            "mac":          received.hwsrc,
            "vendor":       get_vendor(received.hwsrc),
            "discovered_at": datetime.now(timezone.utc).isoformat(),
        }
        devices.append(device)

    return devices


def save_devices(devices):
    """Guarda el inventario de dispositivos encontrados."""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "w") as f:
        json.dump(devices, f, indent=2)
    print(f"[INFO] {len(devices)} dispositivo(s) guardados en {LOG_PATH}")


def print_devices(devices):
    print(f"\n{'IP':<16} {'MAC':<20} {'Vendor':<30}")
    print("-" * 66)
    for d in sorted(devices, key=lambda x: x["ip"]):
        print(f"{d['ip']:<16} {d['mac']:<20} {d['vendor']:<30}")
    print(f"\n[HomeGuard] {len(devices)} dispositivo(s) activos encontrados.\n")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[ERROR] Ejecuta con sudo: sudo venv/bin/python3 discovery/device_scanner.py <subnet>")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Uso: sudo venv/bin/python3 device_scanner.py 192.168.1.0/24")
        sys.exit(1)

    subnet = sys.argv[1]
    devices = scan_network(subnet)
    print_devices(devices)
    save_devices(devices)
