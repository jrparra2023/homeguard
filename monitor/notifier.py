#!/usr/bin/env python3
"""
HomeGuard - Notifier
Envía notificación desktop via notify-send (nativo en Kali).
"""

import subprocess
import json
from pathlib import Path

ALERTS_LOG = Path(__file__).resolve().parent.parent / "logs" / "alerts.json"


def notify_intrusion(ip: str, mac: str):
    msg = f"IP: {ip} | MAC: {mac}\nDispositivo no reconocido en la red."
    try:
        subprocess.run(
            ["notify-send", "-u", "critical", "-t", "10000",
             "HomeGuard — INTRUSO DETECTADO", msg],
            check=True
        )
        print(f"[HomeGuard] Notificación enviada: {ip}")
    except FileNotFoundError:
        print("[HomeGuard] notify-send no disponible.")
    except subprocess.CalledProcessError as e:
        print(f"[HomeGuard] Error al notificar: {e}")


def check_and_notify():
    if not ALERTS_LOG.exists():
        print("[HomeGuard] No hay alertas registradas.")
        return
    with open(ALERTS_LOG) as f:
        alerts = json.load(f)
    if not alerts:
        print("[HomeGuard] Sin alertas.")
        return
    latest = alerts[-1]
    print(f"[HomeGuard] Notificando intruso: {latest['ip']} ({latest['mac']})")
    notify_intrusion(latest["ip"], latest["mac"])


if __name__ == "__main__":
    check_and_notify()
