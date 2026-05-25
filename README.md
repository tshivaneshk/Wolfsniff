# Wolfsniff

**The Hybrid Network Intrusion Detection System**

Wolfsniff is an advanced, standalone network intrusion detection and forensics platform engineered for enterprise security operations. It integrates the high-throughput packet ingestion of native C++ libpcap with a robust Random Forest Machine Learning core to detect anomalies, behavioral threats, and zero-day deviations that traditional signature-based platforms miss.

## Core Capabilities

*   **Real-Time Analytics:** Bypasses the Python Global Interpreter Lock (GIL) via `ctypes` bindings to `wpcap.dll`, enabling volumetric flow capture without dropped packets.
*   **Machine Learning Inference:** Evaluates 42 distinct network flow features against a localized Scikit-Learn Random Forest model trained on the UNSW-NB15 dataset.
*   **Adaptive Thresholds:** Dynamically filters ambient network noise using Strict, Balanced, and Conservative mathematical threshold policies.
*   **Offline Forensics:** Processes historical PCAP files via a rapid-ingestion pipeline for immediate threat intelligence generation.
*   **Data Sovereignty:** Operates 100% offline. Threat alerts and forensic exports are stored locally in SQLite databases within isolated AppData boundaries.

## Architecture

*   **Backend Engine:** Python 3.11, Scapy, Scikit-Learn, Pandas.
*   **Frontend Interface:** PySide6 (Qt6) with a custom Slate styling matrix.
*   **Packet Driver:** Npcap / WinPcap API-Compatible Mode.

## Development Setup

To compile and run Wolfsniff from the source code, ensure you have Python 3.11 installed. 

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Install Network Drivers
Download and install the [Npcap Driver](https://npcap.com/). During installation, you must check the box labeled **"Install Npcap in WinPcap API-compatible Mode"** for the C++ bindings to function correctly.

### 3. Run Development Server
```bash
python main.py
```

## Compiling for Production (Windows)

Wolfsniff is designed to be compiled into a rapid-booting directory utilizing PyInstaller and Inno Setup.

1. Ensure the `icon.ico`, `Logo.png`, and the `ml/` directory (containing `.joblib` and `.json` artifacts) are present in the root directory.
2. Execute the PyInstaller build:
```bash
pyinstaller -y --noconsole --onedir --icon="icon.ico" --add-data "icon.ico;." --add-data "Logo.png;." --add-data "ml/rf_model.joblib;ml" --add-data "ml/encoders.joblib;ml" --add-data "ml/thresholds.json;ml" --name Wolfsniff_v1.0 main.py
```
3. Open `wolfsniff_installer.iss` in the Inno Setup Compiler and build the final `Setup.exe`.

## License

This software is released under the MIT License. Contributions to the detection engine, feature extraction matrix, and C++ bindings are welcome.
