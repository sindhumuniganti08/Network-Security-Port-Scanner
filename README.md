# Project 2: Network Security Port Scanner

A high-performance network security port scanner written in Python using concurrent socket connections.

## Features
- **Target Input Resolution**: Resolves hostnames to IPv4 and performs reverse DNS lookups.
- **Port Range Selection**: Presets (Top 20, Top 100) or custom port ranges (e.g. `80,443,8000-8080`).
- **Concurrent Scanning Engine**: Configurable thread pool execution for high-speed scanning.
- **Banner Grabbing**: Grabs service banners for HTTP, SSH, FTP, SMTP, MySQL, etc.
- **Open / Closed / Filtered Identification**: Measures response latency in milliseconds.
- **Exporting**: Export scan results as JSON or CSV reports.
- **Dual Interfaces**: Web UI dashboard & interactive CLI.

---

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
