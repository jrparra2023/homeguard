#!/usr/bin/env python3
"""
HomeGuard - Scheduler
Ejecuta device_scanner + intrusion_detector automáticamente cada N minutos.
Requiere sudo para el scanner ARP.
"""

import time
import subprocess
import datetime
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")


def run_scan(interface: str = "192.168.1.0/24"):
    log("Iniciando scan de red...")
    result = subprocess.run(
        ["sudo", str(BASE_DIR / "venv/bin/python3"),
         str(BASE_DIR / "discovery/device_scanner.py"), interface],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log("Scan completado.")
    else:
        log(f"Error en scan: {result.stderr.strip()}")


def run_detection():
    log("Ejecutando detección de intrusos...")
    result = subprocess.run(
        [str(BASE_DIR / "venv/bin/python3"),
         str(BASE_DIR / "monitor/intrusion_detector.py")],
        capture_output=True, text=True
    )
    output = result.stdout.strip()
    if "ALERTA" in output:
        log("⚠ INTRUSOS DETECTADOS — revisa el dashboard.")
    else:
        log("✓ Red limpia.")
    print(output)


def main(interval: int, subnet: str):
    log(f"HomeGuard Scheduler iniciado — intervalo: {interval} min | subred: {subnet}")
    log("Presiona Ctrl+C para detener.\n")
    try:
        while True:
            run_scan(subnet)
            run_detection()
            log(f"Próximo scan en {interval} minuto(s)...\n")
            time.sleep(interval * 60)
    except KeyboardInterrupt:
        log("Scheduler detenido por el usuario.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HomeGuard Scheduler")
    parser.add_argument("--interval", type=int, default=5,
                        help="Minutos entre scans (default: 5)")
    parser.add_argument("--subnet", default="192.168.1.0/24",
                        help="Subred a escanear")
    args = parser.parse_args()
    main(args.interval, args.subnet)
