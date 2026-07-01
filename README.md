# 🛡 HomeGuard — Home Network Monitor

A real-time home network security monitoring tool built on Kali Linux.  
Companion project to [NetWatch](https://github.com/jrparra2023/netwatch) — focused on personal network visibility and intrusion detection.

---

## Features

- **Device Discovery** — ARP scan of the local subnet, vendor lookup via MAC OUI
- **Intrusion Detection** — Compares active devices against a known whitelist, alerts on unknown MACs
- **Bandwidth Tracking** — Packet capture per IP using Scapy, reports sent/received bytes
- **Live Dashboard** — Flask web UI with auto-refresh showing devices, alerts, and bandwidth
- **Persistent Logs** — JSON logs for devices, alerts, and bandwidth sessions
- **15 Unit Tests** — pytest suite covering all core modules

---

## Stack

| Tool | Purpose |
|------|---------|
| Python 3.13 | Core language |
| Scapy | ARP scanning & packet capture |
| Flask | Web dashboard |
| PyYAML | Whitelist configuration |
| pytest | Unit testing |

---

## Setup

```bash
git clone https://github.com/jrparra2023/homeguard
cd homeguard
python3 -m venv venv
source venv/bin/activate
pip install scapy flask pyyaml pytest
```

> **Note:** Requires bridged adapter mode in VirtualBox to scan the real LAN.  
> Switch to NAT only for installing packages.

---

## Usage

### 1. Scan the network
```bash
sudo venv/bin/python3 discovery/device_scanner.py 192.168.1.0/24
```

### 2. Configure your whitelist
Edit `inventory/known_devices.yaml` with your known devices.

### 3. Run intrusion detection
```bash
venv/bin/python3 monitor/intrusion_detector.py
```

### 4. Track bandwidth (15s capture)
```bash
sudo venv/bin/python3 monitor/bandwidth_tracker.py --iface eth0 --duration 15
```

### 5. Launch dashboard
```bash
venv/bin/python3 dashboard/app.py
# Open http://127.0.0.1:5000
```

### 6. Run tests
```bash
venv/bin/python3 -m pytest tests/ -v
```

---

## Project Structure

```text
homeguard/
├── discovery/
│   └── device_scanner.py      # ARP scan + vendor lookup
├── monitor/
│   ├── intrusion_detector.py  # Whitelist comparison + alerting
│   └── bandwidth_tracker.py   # Per-IP traffic measurement
├── inventory/
│   └── known_devices.yaml     # Trusted device whitelist
├── dashboard/
│   ├── app.py                 # Flask API + server
│   └── templates/index.html   # Live web UI
├── logs/                      # Auto-generated JSON logs
├── tests/
│   └── test_homeguard.py      # 15 unit tests
└── README.md
```

## Author

**José Rafael Parra Dugarte**  
Electronics & Telecommunications Engineering — Universidad del Cauca  
Researcher @ GRIAL Wireless Networks Research Group  
[github.com/jrparra2023](https://github.com/jrparra2023) · [LinkedIn](https://linkedin.com/in/josé-rafael-parra-dugarte)

---

## Roadmap

### v1.0 — Core Pipeline ✅
- [x] ARP-based device discovery with vendor lookup
- [x] MAC whitelist (YAML) with unknown device alerting
- [x] Per-IP bandwidth tracking via packet capture
- [x] Flask live dashboard (devices + alerts + bandwidth)
- [x] Persistent JSON logging
- [x] 15 unit tests (pytest)

### v1.1 — Scheduled Monitoring ✅
- [x] Cron-based auto-scan every N minutes
- [x] Alert history with timestamps in dashboard
- [x] Desktop notification on new intrusion

### v1.2 — Intelligence Layer ✅
- [x] Port scan detection (Scapy SYN flood patterns)
- [x] Device fingerprinting (OS detection via TTL/TCP)
- [x] Risk scoring per device

### v1.3 — Production Ready ✅
- [x] Docker container for easy deployment
- [x] Config file (`config.yaml`) for subnet, interface, duration
- [x] REST API with authentication
