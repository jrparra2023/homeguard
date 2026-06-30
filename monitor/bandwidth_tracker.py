#!/usr/bin/env python3
"""
HomeGuard - Bandwidth Tracker
Captura tráfico de red y mide bytes por IP en tiempo real.
Requiere sudo (captura de paquetes).
"""

import time
import json
import datetime
import argparse
from collections import defaultdict
from pathlib import Path
from scapy.all import sniff, IP

BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"

stats = defaultdict(lambda: {"sent": 0, "received": 0})


def process_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        size = len(pkt)
        stats[src]["sent"] += size
        stats[dst]["received"] += size


def format_bytes(b):
    if b >= 1_000_000:
        return f"{b/1_000_000:.2f} MB"
    elif b >= 1_000:
        return f"{b/1_000:.2f} KB"
    return f"{b} B"


def run_tracker(interface: str, duration: int, subnet: str = "192.168.1."):
    print(f"[HomeGuard] Capturando tráfico en '{interface}' por {duration}s...\n")
    sniff(iface=interface, prn=process_packet, timeout=duration, store=False)

    # Filtrar solo IPs de la subred local
    local = {ip: v for ip, v in stats.items() if ip.startswith(subnet)}

    if not local:
        print("[HomeGuard] No se capturó tráfico local. ¿Interfaz correcta?")
        return

    print(f"{'IP':<18} {'Enviado':<15} {'Recibido':<15} {'Total'}")
    print("-" * 65)

    report = []
    for ip, v in sorted(local.items()):
        total = v["sent"] + v["received"]
        print(f"{ip:<18} {format_bytes(v['sent']):<15} {format_bytes(v['received']):<15} {format_bytes(total)}")
        report.append({
            "ip": ip,
            "sent_bytes": v["sent"],
            "received_bytes": v["received"],
            "total_bytes": total
        })

    # Guardar log
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    output = {
        "timestamp": datetime.datetime.now().isoformat(),
        "interface": interface,
        "duration_seconds": duration,
        "devices": report
    }
    log_path = LOGS_DIR / "bandwidth.json"
    with open(log_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[INFO] Reporte guardado en {log_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HomeGuard Bandwidth Tracker")
    parser.add_argument("--iface", default="eth0", help="Interfaz de red (default: eth0)")
    parser.add_argument("--duration", type=int, default=15, help="Segundos de captura (default: 15)")
    parser.add_argument("--subnet", default="192.168.1.", help="Prefijo de subred a filtrar")
    args = parser.parse_args()

    run_tracker(args.iface, args.duration, args.subnet)
