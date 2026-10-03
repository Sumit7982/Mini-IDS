# 🛡️ Mini Intrusion Detection System (Mini-IDS)

A Python-based Intrusion Detection System that monitors network traffic, analyzes packets, detects suspicious port-scanning activity, assigns severity levels, stores security alerts in SQLite, and displays network statistics through a Streamlit dashboard.

---

## 📌 Project Overview

The Mini-IDS is a beginner-friendly cybersecurity project developed using Python.

The system captures live network packets using Scapy and analyzes:

- Source IP address
- Destination IP address
- Protocol
- Destination port
- TCP flags
- Number of unique ports accessed within a time window

The system can detect possible:

- Port scans
- SYN scans
- Suspicious network activity

Detected alerts are stored in an SQLite database and displayed on a Streamlit dashboard.

---

## ✨ Features

- 🔍 Live network packet capture
- 🌐 Source and destination IP detection
- 🔌 TCP packet detection
- 📡 UDP packet detection
- 📶 ICMP packet detection
- 🚨 Port scan detection
- ⚡ SYN scan detection
- 🟢 Low severity alerts
- 🟡 Medium severity alerts
- 🔴 High severity alerts
- 💾 SQLite alert storage
- 📊 Packet statistics storage
- 📈 Streamlit monitoring dashboard
- ⏱️ 10-second detection window
- ⏳ 60-second alert cooldown
- 🖥️ Windows Npcap support
- 🧪 Localhost testing using Scapy

---

## 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Main programming language |
| Scapy | Network packet capture and analysis |
| SQLite | Alert and statistics database |
| Streamlit | Web dashboard |
| Npcap | Windows packet capture |
| VS Code | Development environment |
| Git & GitHub | Version control and project hosting |

---

## 📂 Project Structure

```text
Mini-IDS/
│
├── main.py
├── dashboard.py
├── test_ids.py
├── ids_alerts.db
├── README.md
└── venv/