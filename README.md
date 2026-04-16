# Chakshu

**Chakshu** is an advanced, AI-driven Managed Detection and Response (MDR) pipeline and multi-layered SIEM framework. It acts as an intelligent assistant to Security Operations Center (SOC) analysts, automatically ingesting heterogeneous logs, detecting Zero-Day anomalies, and reconstructing multi-stage attack narratives using Explainable AI (XAI).

Instead of relying on a monolithic system or rigid regex rules, Chakshu deploys a localized fleet of Machine Learning "Specialists" tailored to specific infrastructure layers, orchestrated by a central Fusion Engine.

---

## Architecture & Repo Structure

Chakshu is divided into a four-phase operational pipeline. The following structure represents the core logic of the framework:

```text
Chakshu/
├── ai_engine/               # Specialist Inference scripts (Unit Testing)
│   ├── linux_inference.py
│   ├── network_inference.py
│   ├── webapp_inference.py
│   └── windows_inference.py
├── models/
│   └── fusion/
│       └── master_engine.py # The Central Fusion & Correlation Brain
├── scripts/                 # Ingestion & Model Training Suite
│   ├── init_parsers.py      # Normalizes heterogeneous logs to JSON schema
│   ├── train_auth_linux.py
│   ├── train_auth_windows.py
│   ├── train_host_linux.py
│   ├── train_host_windows.py
│   ├── train_network_flow.py
│   └── train_webapp_specialist.py
├── ingest_test.py           # Master forensic reconstruction script
├── requirements.txt         # Project dependencies
├── setup.sh                 # Linux/Mac environment setup
└── setup.ps1                # Windows environment setup
```

### 1. Data Normalization (`init_parsers.py`)
Standardizes raw telemetry into a unified JSON schema: `{ "ts", "src_ip", "payload", "act" }`. It includes dynamic extraction for IPv4 addresses hidden within complex syslog or HTTP error payloads.

### 2. The Specialist Fleet (Detection Layer)
Routes normalized logs to specialized ML models based on OS autodetection.

| Specialist | Algorithm | Feature Engineering | Target Threats | XAI Tool |
|------------|-----------|---------------------|----------------|----------|
| **Network (L3/L4)** | Isolation Forest | Numerical (`dst_pt`, bytes) | DDoS, Port Scans | SHAP |
| **Web App (L7)** | One-Class SVM | Char N-Grams (TF-IDF) | SQLi, XSS, Path Traversal | LIME |
| **Auth Gateway** | One-Class SVM | Char N-Grams (TF-IDF) | SSH/RDP Brute Force, AD Anomalies | LIME |
| **OS Execution** | One-Class SVM | Char N-Grams (TF-IDF) | Reverse Shells, Obfuscated PS1 | LIME |

### 3. The Fusion Engine (`master_engine.py`)
The orchestrator that applies a **60-second temporal sliding window** to correlate events across layers. It handles **"Structural Anomalies"** where payloads are mathematically too alien for LIME to isolate a single word.

---

## Setup & Installation

### Prerequisites
- Python 3.10+
- Git

### Linux / Mac
```bash
chmod +x setup.sh
./setup.sh
```

### Windows Powershell

First, allow script execution if not already enabled:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUse
```

Then run:

```powershell
.\setup.ps1
```
---

## Usage Workflow

**1. Parse the Raw Data**
Converts raw CSV and streaming BZ2 files into Chakshu's unified JSON schema.
```bash
python scripts/init_parsers.py
```

**2. Train the Specialists**
Train the localized ML models to establish benign baselines.
```bash
python scripts/train_auth_linux.py
python scripts/train_auth_windows.py
```

**3. Run Forensic Reconstruction**
Feed the unified JSON stream into the Fusion Engine for cross-layer correlation.
```bash
python ingest_test.py
```

## Datasets

| Dataset | Domain | Source | Location |
|---------|--------|--------|----------|
| [Loghub](https://github.com/logpai/loghub) | Multi-source (Linux, Windows, Apache, SSH, Android, and more) | Git submodule | `data/raw/loghub/` |
| [LANL Unified Host and Network](https://csr.lanl.gov/data/2017/) | Network flows + Windows host/auth events | Manual download | `data/raw/lanl/` |
| [CICIDS 2017](https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset) | Network intrusion (labelled, 80+ features) | Kaggle CLI (auto) | `data/raw/cicids/` |

### LANL manual download

LANL requires a browser-based download. The setup script will open the download page automatically. Once downloaded, place files as follows:

```
data/raw/lanl/netflow/   ← netflow_day-XX.bz2 files
data/raw/lanl/wls/       ← wls_day-XX.bz2 files
```

Files can be left compressed — parsers stream directly from `.bz2`.

---

## License

Copyright 2026 Meehir Prabhakar, Soumil Sengupta, and Shivshankar Patil

Licensed under the [Apache License 2.0](LICENSE).
