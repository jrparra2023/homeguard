#!/usr/bin/env python3
"""
HomeGuard - Dashboard Flask
Visualiza dispositivos, alertas y ancho de banda.
"""

from flask import Flask, render_template, jsonify
from pathlib import Path
import json

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"


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
    return jsonify(read_json("devices.json") or [])


@app.route("/api/alerts")
def api_alerts():
    return jsonify(read_json("alerts.json") or [])


@app.route("/api/bandwidth")
def api_bandwidth():
    return jsonify(read_json("bandwidth.json") or {})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
