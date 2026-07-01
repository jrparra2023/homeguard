#!/usr/bin/env python3
"""
HomeGuard - Dashboard Flask
Visualiza dispositivos, alertas y ancho de banda.
API protegida por token.
"""

from flask import Flask, render_template, jsonify, request, abort
from pathlib import Path
import json
import yaml

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"
CONFIG_FILE = BASE_DIR / "config.yaml"


def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f)
    return {}


def get_api_token():
    config = load_config()
    return config.get("api", {}).get("token", "homeguard-secret-token")


def require_token():
    token = request.headers.get("X-API-Token") or request.args.get("token")
    if token != get_api_token():
        abort(401)


def read_json(filename):
    path = LOGS_DIR / filename
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    require_token()
    return jsonify(read_json("devices.json") or [])


@app.route("/api/alerts")
def api_alerts():
    require_token()
    return jsonify(read_json("alerts.json") or [])


@app.route("/api/bandwidth")
def api_bandwidth():
    require_token()
    return jsonify(read_json("bandwidth.json") or {})


@app.route("/api/risk")
def api_risk():
    require_token()
    return jsonify(read_json("risk_scores.json") or [])


@app.route("/api/fingerprints")
def api_fingerprints():
    require_token()
    return jsonify(read_json("fingerprints.json") or [])


@app.route("/api/port_scans")
def api_port_scans():
    require_token()
    return jsonify(read_json("port_scans.json") or [])


@app.route("/api/status")
def api_status():
    require_token()
    config = load_config()
    return jsonify({
        "status": "ok",
        "subnet": config.get("network", {}).get("subnet", "—"),
        "interface": config.get("network", {}).get("interface", "—"),
    })


if __name__ == "__main__":
    config = load_config()
    host = config.get("dashboard", {}).get("host", "0.0.0.0")
    port = config.get("dashboard", {}).get("port", 5000)
    app.run(host=host, port=port, debug=False)
