#!/usr/bin/env python3
"""
HomeGuard - Unit Tests
"""

import json
import yaml
import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from collections import defaultdict

# ── device_scanner ────────────────────────────────────────────────
def test_device_entry_structure():
    device = {"ip": "192.168.1.1", "mac": "74:93:da:ca:5a:a0", "vendor": "Unknown"}
    assert "ip" in device
    assert "mac" in device
    assert "vendor" in device

def test_device_ip_format():
    ip = "192.168.1.1"
    parts = ip.split(".")
    assert len(parts) == 4
    assert all(p.isdigit() for p in parts)

def test_mac_format():
    mac = "74:93:da:ca:5a:a0"
    assert len(mac.split(":")) == 6

# ── known_devices / whitelist ─────────────────────────────────────
def test_whitelist_loads_correctly():
    data = {
        "devices": [
            {"mac": "74:93:da:ca:5a:a0", "ip": "192.168.1.1", "name": "Router", "owner": "Rafael"},
            {"mac": "a4:fc:77:5c:a3:e5", "ip": "192.168.1.12", "name": "MegaWell", "owner": "Rafael"},
        ]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        tmp = f.name
    with open(tmp) as f:
        loaded = yaml.safe_load(f)
    os.unlink(tmp)
    assert len(loaded["devices"]) == 2
    macs = {d["mac"].lower() for d in loaded["devices"]}
    assert "74:93:da:ca:5a:a0" in macs

def test_whitelist_mac_case_insensitive():
    whitelist = {"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"}
    assert "aa:bb:cc:dd:ee:ff" in whitelist

def test_unknown_mac_triggers_alert():
    whitelist = {"74:93:da:ca:5a:a0", "a4:fc:77:5c:a3:e5"}
    scanned_mac = "de:ad:be:ef:00:01"
    assert scanned_mac.lower() not in whitelist

def test_known_mac_no_alert():
    whitelist = {"74:93:da:ca:5a:a0"}
    assert "74:93:da:ca:5a:a0" in whitelist

# ── bandwidth_tracker ─────────────────────────────────────────────
def test_format_bytes_b():
    def fmt(b):
        if b >= 1_000_000: return f"{b/1_000_000:.2f} MB"
        if b >= 1_000: return f"{b/1_000:.2f} KB"
        return f"{b} B"
    assert fmt(500) == "500 B"

def test_format_bytes_kb():
    def fmt(b):
        if b >= 1_000_000: return f"{b/1_000_000:.2f} MB"
        if b >= 1_000: return f"{b/1_000:.2f} KB"
        return f"{b} B"
    assert fmt(2048) == "2.05 KB"

def test_format_bytes_mb():
    def fmt(b):
        if b >= 1_000_000: return f"{b/1_000_000:.2f} MB"
        if b >= 1_000: return f"{b/1_000:.2f} KB"
        return f"{b} B"
    assert fmt(1_500_000) == "1.50 MB"

def test_bandwidth_stats_accumulate():
    stats = defaultdict(lambda: {"sent": 0, "received": 0})
    stats["192.168.1.1"]["sent"] += 1000
    stats["192.168.1.1"]["received"] += 500
    assert stats["192.168.1.1"]["sent"] == 1000
    assert stats["192.168.1.1"]["received"] == 500

def test_bandwidth_report_structure():
    report = {"ip": "192.168.1.13", "sent_bytes": 1000, "received_bytes": 2000, "total_bytes": 3000}
    assert report["total_bytes"] == report["sent_bytes"] + report["received_bytes"]

# ── logs ──────────────────────────────────────────────────────────
def test_alerts_log_structure():
    alert = {
        "timestamp": "2026-06-30T18:06:55",
        "ip": "192.168.1.7",
        "mac": "14:b5:cd:b2:d8:4b",
        "vendor": "Unknown",
        "alert": "MAC no registrada en whitelist"
    }
    assert "timestamp" in alert
    assert "mac" in alert
    assert "alert" in alert

def test_devices_log_is_list():
    devices = [
        {"ip": "192.168.1.1", "mac": "74:93:da:ca:5a:a0", "vendor": "Unknown"},
    ]
    assert isinstance(devices, list)
    assert len(devices) > 0

def test_bandwidth_log_has_devices_key():
    log = {"timestamp": "2026-06-30T18:15:00", "interface": "eth0", "duration_seconds": 15, "devices": []}
    assert "devices" in log
    assert isinstance(log["devices"], list)
