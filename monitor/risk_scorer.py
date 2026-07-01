#!/usr/bin/env python3
"""
HomeGuard - Risk Scorer
Calcula puntuación de riesgo por dispositivo combinando:
- Si está en whitelist
- Si generó alertas de intrusión
- Si generó alertas de port scan
- OS fingerprint (dispositivos desconocidos suman riesgo)
"""

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"


def load_json(filename):
    path = LOGS_DIR / filename
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f)


def load_whitelist():
    import yaml
    wl = BASE_DIR / "inventory" / "known_devices.yaml"
    if not wl.exists():
        return set()
    with open(wl) as f:
        data = yaml.safe_load(f)
    return {d["mac"].lower() for d in data.get("devices", [])}


def score_devices():
    devices   = load_json("devices.json")
    alerts    = load_json("alerts.json")
    scans     = load_json("port_scans.json")
    fps       = load_json("fingerprints.json")
    whitelist = load_whitelist()

    # Indexar por IP
    alerted_ips  = {a["ip"] for a in alerts}
    scanned_ips  = {s["src_ip"] for s in scans}
    fp_map       = {f["ip"]: f for f in fps}

    print(f"\n{'IP':<18} {'MAC':<22} {'Score':<8} {'Nivel':<10} {'Motivos'}")
    print("-" * 90)

    report = []
    for d in devices:
        ip     = d.get("ip", "?")
        mac    = d.get("mac", "").lower()
        score  = 0
        reasons = []

        if mac not in whitelist:
            score += 40
            reasons.append("MAC desconocida")

        if ip in alerted_ips:
            score += 30
            reasons.append("alerta intrusión")

        if ip in scanned_ips:
            score += 20
            reasons.append("port scan detectado")

        if ip in fp_map:
            os_name = fp_map[ip].get("os_ttl", "")
            if "Unknown" in os_name or "Proxy" in os_name:
                score += 10
                reasons.append(f"OS sospechoso ({os_name})")

        if score == 0:
            level = "✓ BAJO"
        elif score <= 30:
            level = "⚡ MEDIO"
        elif score <= 60:
            level = "⚠ ALTO"
        else:
            level = "🔴 CRÍTICO"

        reason_str = ", ".join(reasons) if reasons else "ninguno"
        print(f"{ip:<18} {mac:<22} {score:<8} {level:<10} {reason_str}")

        report.append({
            "ip": ip, "mac": mac,
            "score": score, "level": level.split()[-1],
            "reasons": reasons
        })

    # Guardar
    out = LOGS_DIR / "risk_scores.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[INFO] Risk scores guardados en {out}")


if __name__ == "__main__":
    score_devices()
