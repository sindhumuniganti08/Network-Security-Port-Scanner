# 📡 Network Security Port Scanner

A high-performance, multi-threaded network security port scanner built in Python using concurrent socket connections, banner grabbing, and service identification.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi)
![Sockets](https://img.shields.io/badge/Networking-Sockets%20%26%20Threads-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## 📌 Project Overview

The **Network Security Port Scanner** demonstrates core network discovery, service identification, and threat surface auditing techniques. It allows security auditors to resolve hostnames, scan target IP addresses across predefined or custom port ranges, measure socket response latency in milliseconds, identify running network services (HTTP, SSH, FTP, SMTP, MySQL, Redis, etc.), and capture service banners.

---

## ✨ Key Features & Technical Capabilities

- **Target Host Resolution**: Automatic IPv4 DNS resolution and reverse DNS lookup for target hostnames.
- **Multi-Threaded Concurrent Engine**: High-speed port probing using configurable worker thread pools (`ThreadPoolExecutor`).
- **Flexible Port Presets**: 
  - **Top 20 Ports**: High-speed common service discovery.
  - **Top 100 Ports**: Standard network reconnaissance profile.
  - **Custom Range**: Custom port ranges (e.g., `80,443,8000-8080`).
- **Service Banner Grabbing**: Connects to open ports to capture service banners (HTTP headers, SSH version strings, FTP greetings).
- **Latency Measurement**: Precise per-port socket connection round-trip timing in milliseconds (`ms`).
- **Report Exporting**: Export scan findings into structured JSON or CSV format.
- **Dual Interface Support**: Interactive modern dark-mode Web UI dashboard and interactive terminal CLI interface.

---

## 📁 Repository Directory Structure

```text
Network-Security-Port-Scanner/
├── frontend/
│   └── index.html          # Interactive dark-themed web UI dashboard
├── backend/
│   ├── app.py              # FastAPI REST API server
│   ├── scanner.py          # Core multi-threaded port scanner engine
│   └── cli.py              # Interactive terminal CLI port scanner
├── static/
│   └── index.html          # Static Web UI assets
├── .gitignore              # Excludes node_modules, .env, and temp files
├── package.json            # Node/Project metadata script definitions
├── requirements.txt        # Python dependencies
└── README.md               # Complete project documentation

## 🚀 Quick Start

### 1. Web UI Dashboard & REST API
```bash
python app.py
```
Open `http://127.0.0.1:8002` in your browser.

### 2. Interactive CLI Tool
```bash
python cli.py
```

---

## ⚠️ Legal & Ethical Notice
Only run port scans against systems you own or have explicit authorization to audit.
