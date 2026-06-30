#!/usr/bin/env python3
"""
HomeGuard - Intrusion Detector
Compara dispositivos activos contra la whitelist.
Alerta si detecta una MAC no reconocida.
"""

import json
import yaml
import os
import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEVICES_JSON = BASE_DIR / "logs" / "devices.json"
WHITELIST_YAML = BASE_DIR / "inventory" / "known_devices.yaml"
ALERTS_LOG = BASE_DIR / "logs" / "alerts.json"


def load_whitelist() -> set:
    """Carga las MACs conocidas desde known_devices.yaml."""
    if not WHITELIST_YAML.exists():
        print(f"[ERROR] Whitelist no encontrada: {WHITELIST_YAML}")
        return set()
    with open(WHITELIST_YAML, "r") as f:
        data = yaml.safe_load(f)
    macs = {d["mac"].lower() for d in data.get("devices", [])}
    print(f"[HomeGuard] {len(macs)} dispositivo(s) en whitelist cargados.")
    return macs


def load_scanned_devices() -> list:
    """Carga el último resultado del device_scanner."""
    if not DEVICES_JSON.exists():
        print(f"[ERROR] No se encontró {DEVICES_JSON}. Corre primero device_scanner.py.")
        return []
    with open(DEVICES_JSON, "r") as f:
        return json.load(f)


def run_detection():
    whitelist = load_whitelist()
    devices = load_scanned_devices()

    if not devices:
        return

    alerts = []
    print(f"\n[HomeGuard] Analizando {len(devices)} dispositivo(s) activo(s)...\n")
    print(f"{'IP':<18} {'MAC':<22} {'Vendor':<25} {'Estado'}")
    print("-" * 80)

    for d in devices:
        mac = d.get("mac", "").lower()
        ip = d.get("ip", "?")
        vendor = d.get("vendor", "Unknown")

        if mac in whitelist:
            status = "✓ Conocido"
        else:
            status = "⚠ DESCONOCIDO"
            alert = {
                "timestamp": datetime.datetime.now().isoformat(),
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "alert": "MAC no registrada en whitelist"
            }
            alerts.append(alert)
            print(f"{ip:<18} {mac:<22} {vendor:<25} {status}  ← ALERTA")
            continue

        print(f"{ip:<18} {mac:<22} {vendor:<25} {status}")

    print()

    if alerts:
        ALERTS_LOG.parent.mkdir(parents=True, exist_ok=True)
        # Cargar alertas previas si existen
        existing = []
        if ALERTS_LOG.exists():
            with open(ALERTS_LOG, "r") as f:
                existing = json.load(f)
        existing.extend(alerts)
        with open(ALERTS_LOG, "w") as f:
            json.dump(existing, f, indent=2)
        print(f"[ALERTA] {len(alerts)} dispositivo(s) desconocido(s) detectado(s).")
        print(f"[INFO] Alertas guardadas en {ALERTS_LOG}")
    else:
        print("[HomeGuard] Red limpia. Todos los dispositivos son conocidos.")


if __name__ == "__main__":
    run_detection()
