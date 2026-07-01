#!/usr/bin/env python3
"""
HomeGuard - Port Scan Detector
Detecta patrones de SYN scan (Scapy) en la red local.
Alerta si una IP toca más de N puertos distintos en T segundos.
Requiere sudo.
"""

import json
import datetime
import argparse
from collections import defaultdict
from pathlib import Path
from scapy.all import sniff, IP, TCP

BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"
SCAN_LOG = LOGS_DIR / "port_scans.json"

# IP -> set de puertos destino tocados
port_hits = defaultdict(set)
# IP -> timestamps de paquetes SYN
timestamps = defaultdict(list)

THRESHOLD_PORTS = 10   # puertos distintos
THRESHOLD_SECS  = 5    # en N segundos


def process_packet(pkt):
    if IP in pkt and TCP in pkt:
        flags = pkt[TCP].flags
        # SYN sin ACK = inicio de conexión / scan
        if flags == 0x02:
            src = pkt[IP].src
            dst_port = pkt[TCP].dport
            now = datetime.datetime.now()

            port_hits[src].add(dst_port)
            timestamps[src].append(now)

            # Limpiar timestamps viejos
            timestamps[src] = [
                t for t in timestamps[src]
                if (now - t).total_seconds() <= THRESHOLD_SECS
            ]

            if len(port_hits[src]) >= THRESHOLD_PORTS:
                alert_scan(src, port_hits[src])
                port_hits[src].clear()


def alert_scan(src_ip: str, ports: set):
    ts = datetime.datetime.now().isoformat()
    ports_list = sorted(ports)
    print(f"\n[⚠ PORT SCAN] {src_ip} tocó {len(ports_list)} puertos: {ports_list[:10]}...")

    alert = {
        "timestamp": ts,
        "type": "port_scan",
        "src_ip": src_ip,
        "ports_scanned": ports_list,
        "count": len(ports_list)
    }

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    existing = []
    if SCAN_LOG.exists():
        with open(SCAN_LOG) as f:
            existing = json.load(f)
    existing.append(alert)
    with open(SCAN_LOG, "w") as f:
        json.dump(existing, f, indent=2)

    # Notificación desktop
    try:
        from monitor.notifier import notify_intrusion
        notify_intrusion(src_ip, f"Port scan: {len(ports_list)} puertos")
    except Exception:
        pass


def run(interface: str, duration: int):
    print(f"[HomeGuard] Port Scan Detector activo en '{interface}'")
    print(f"[HomeGuard] Umbral: {THRESHOLD_PORTS} puertos en {THRESHOLD_SECS}s")
    print(f"[HomeGuard] Capturando por {duration}s... (Ctrl+C para detener)\n")
    sniff(
        iface=interface,
        filter="tcp",
        prn=process_packet,
        timeout=duration,
        store=False
    )
    print("\n[HomeGuard] Captura finalizada.")
    if SCAN_LOG.exists():
        print(f"[INFO] Log guardado en {SCAN_LOG}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HomeGuard Port Scan Detector")
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--duration", type=int, default=30)
    args = parser.parse_args()
    run(args.iface, args.duration)
