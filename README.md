# Wolfsniff

> Advanced Hybrid Network Intrusion Detection & Threat Analytics Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?logo=windows)](https://github.com/tshivaneshk/Wolfsniff)
[![ML](https://img.shields.io/badge/ML-Random%20Forest-orange?logo=scikit-learn)](https://scikit-learn.org)
[![GUI](https://img.shields.io/badge/GUI-PySide6%20Qt6-41CD52?logo=qt)](https://doc.qt.io/qtforpython/)

Wolfsniff is a high-performance hybrid intrusion detection and network telemetry platform engineered for modern cyber defense operations. It combines native packet capture pipelines with machine learning–driven behavioral analysis to deliver real-time detection of anomalous traffic, suspicious flow activity, and advanced network threats — all without any cloud dependency.

[Features](#-features) · [Architecture](#-architecture) · [Getting Started](#-getting-started) · [Production Build](#-production-build-windows) · [Roadmap](#-roadmap) · [Contributing](#-contributing)

---

## 🔍 Overview

Traditional signature-based IDS platforms struggle to keep pace with evolving behavioral attacks and zero-day traffic deviations. Wolfsniff addresses this through a **hybrid detection architecture** that integrates:

- Native C++ packet acquisition via `libpcap` / `Npcap`
- High-throughput traffic inspection with minimal packet loss
- Machine learning inference pipelines (Random Forest, UNSW-NB15 trained)
- Adaptive anomaly thresholding with configurable sensitivity profiles
- Fully offline forensic analysis and SQLite-backed evidence storage

> Designed for cybersecurity researchers, blue-team environments, lab infrastructures, educational security operations, and private network monitoring deployments.

---

## ✨ Features

### 🛡️ Real-Time Packet Intelligence
- Native `libpcap` / `Npcap` integration via `ctypes`
- High-speed packet ingestion with minimal packet loss
- Continuous network flow analysis and telemetry extraction

### 🤖 Machine Learning Detection Engine
- Random Forest–based threat classification
- Evaluates **42+ network flow characteristics**
- Behavioral anomaly identification trained on the **UNSW-NB15** dataset

### ⚙️ Adaptive Threat Scoring

Dynamic threshold evaluation profiles to reduce noise and false-positive escalation:

| Profile | Description |
| :--- | :--- |
| `Strict` | Highest sensitivity — flags more potential threats |
| `Balanced` | Recommended default for most environments |
| `Conservative` | Reduced sensitivity — best for noisy networks |

### 📂 Offline PCAP Forensics
- Rapid ingestion of historical PCAP captures
- Threat reconstruction and retrospective analysis workflows
- Local forensic event generation and session review

### 🔒 Localized Security Architecture
- Fully offline-capable operation — **no internet required**
- SQLite-based local evidence storage
- No external telemetry, cloud sync, or remote dependency

---

## 🧰 Technology Stack

| Layer | Technology |
| :--- | :--- |
| Core Engine | Python 3.11 |
| Packet Processing | Scapy + Native libpcap / Npcap |
| Machine Learning | Scikit-Learn |
| Data Processing | Pandas |
| Desktop Interface | PySide6 (Qt6) |
| Local Database | SQLite |
| Native Integration | ctypes + WinPcap / Npcap API |

---

## 🏗️ Architecture

```
┌─────────────────────────┐
│    Network Interface    │
└───────────┬─────────────┘
            │  Raw Frames
            ▼
┌─────────────────────────┐
│   Native Packet Layer   │
│    (Npcap / libpcap)    │
└───────────┬─────────────┘
            │  Packet Stream
            ▼
┌─────────────────────────┐
│    Flow Extraction      │
│    + Feature Engine     │
│   (42+ flow features)   │
└───────────┬─────────────┘
            │  Feature Vectors
            ▼
┌─────────────────────────┐
│    ML Detection Core    │
│   Random Forest IDS     │
│  (UNSW-NB15 trained)    │
└───────────┬─────────────┘
            │  Threat Score
            ▼
┌─────────────────────────┐
│   Alert & Forensics     │
│   SQLite Event Store    │
└─────────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites

- Python **3.11+**
- Windows OS (for Npcap support)
- [Npcap](https://npcap.com/#download) driver installed

### 1. Clone the Repository

```bash
git clone https://github.com/tshivaneshk/Wolfsniff.git
cd Wolfsniff
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Install Npcap Driver

Download and install the official Npcap driver from [npcap.com](https://npcap.com/#download).

> ⚠️ **Important:** During installation, enable the option:
> **"Install Npcap in WinPcap API-compatible Mode"**

### 4. Launch Wolfsniff

```bash
python main.py
```

---

## 📦 Production Build (Windows)

Wolfsniff supports standalone Windows deployment using **PyInstaller** and **Inno Setup**.

### Build Executable

```bash
pyinstaller -y --noconsole --onedir --icon="icon.ico" ^
  --add-data "icon.ico;." ^
  --add-data "Logo.png;." ^
  --add-data "ml/rf_model.joblib;ml" ^
  --add-data "ml/encoders.joblib;ml" ^
  --add-data "ml/thresholds.json;ml" ^
  --name Wolfsniff_v1.0 main.py
```

### Build Installer

Compile `wolfsniff_installer.iss` using the [Inno Setup Compiler](https://jrsoftware.org/isinfo.php).

---

## 📁 Repository Structure

```
Wolfsniff/
├── capture/          # Native packet acquisition
├── core/             # Detection and analysis engine
├── dataset/          # ML training datasets
├── gui/              # PySide6 desktop interface
├── ml/               # Trained ML model artifacts
├── assets/           # UI resources and branding
├── main.py           # Application entry point
├── requirements.txt
└── README.md
```

---

## 🔐 Security & Privacy

Wolfsniff is designed with **localized operational privacy** as a core principle:

- No cloud synchronization
- No external API dependency
- No remote telemetry collection
- All forensic data stored entirely on-device

> This project is intended for **authorized network monitoring**, cybersecurity research, educational environments, and defensive security analysis only.

---

## 🗺️ Roadmap

- [ ] Advanced protocol fingerprinting
- [ ] Multi-model anomaly correlation
- [ ] Threat intelligence rule integration
- [ ] Real-time dashboard metrics
- [ ] Distributed sensor support
- [ ] SIEM export pipelines
- [ ] GPU-assisted inference acceleration

---

## 🤝 Contributing

Contributions are welcome! Areas of particular interest:

- Detection engineering
- Packet analysis & protocol parsing
- Machine learning pipelines
- UI/UX improvements
- Performance optimization

Please open an issue or submit a pull request.

---

## 📄 License

Released under the [MIT License](LICENSE).

---

*Built for defenders. Designed for clarity. Engineered for precision.*
