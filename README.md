# Chakshu

Chakshu is an AI-driven forensic framework for automated ingestion, correlation, and analysis of diverse log data. It acts as an intelligent assistant to investigators, converting raw logs from heterogeneous sources into a unified, tamper-proof timeline of events.

Modern IT environments generate logs at a scale and velocity that makes manual review impossible. Logs exist across fragmented formats — network flows, OS events, authentication records — each requiring specialist knowledge to interpret. Chakshu addresses this by normalising all log types into a common schema, running specialist AI models per log domain, and correlating findings across domains to surface attack chains that no single model would detect alone.

---

## Architecture

Chakshu uses a four-model hybrid architecture:

- **Network specialist** — analyses network flow data (src/dst IPs, ports, bytes, protocol) for traffic anomalies and C2 patterns
- **Host specialist** — analyses OS-level process and file events for suspicious execution chains
- **Auth specialist** — analyses authentication events for brute force, lateral movement, and privilege escalation
- **Fusion model** — receives scored outputs from all three specialists and correlates cross-domain attack chains, mapped to MITRE ATT&CK techniques

All logs are normalised into a common JSON schema before reaching any model, ensuring a clean contract between the ingestion layer and the analysis engine.

---

## Repo Structure

```
Chakshu/
├── data/
│   ├── raw/
│   │   ├── loghub/          # git submodule — 16+ log types (Linux, Windows, Apache, SSH, etc.)
│   │   ├── lanl/
│   │   │   ├── netflow/     # LANL network flow logs (.bz2)
│   │   │   └── wls/         # LANL Windows host + auth logs (.bz2)
│   │   └── cicids/          # CICIDS 2017 network intrusion dataset (CSV)
│   ├── processed/           # logs normalised into JSON schema (gitignored)
│   └── synthetic/           # generated attack scenarios for augmentation (gitignored)
│
├── schema/
│   └── log_schema.json      # unified JSON schema — the contract for the entire system
│
├── models/
│   ├── network/             # network specialist model
│   ├── host/                # host / OS specialist model
│   ├── auth/                # auth specialist model
│   └── fusion/              # cross-domain correlation model
│
├── parsers/                 # raw dataset → JSON schema mappers
│   ├── loghub_parser.py
│   ├── lanl_parser.py
│   └── cicids_parser.py
│
├── training/                # training scripts per model
│   ├── train_network.py
│   ├── train_host.py
│   ├── train_auth.py
│   └── train_fusion.py
│
├── evaluation/              # metrics, benchmarks, confusion matrices
├── notebooks/               # exploratory data analysis
├── tests/
├── setup.sh                 # setup script — Linux / Mac
├── setup.ps1                # setup script — Windows
└── requirements.txt
```

---

## Setup

### Prerequisites

- Python 3.14+
- Git

### Linux / Mac

```bash
chmod +x setup.sh
./setup.sh
```

### Windows (PowerShell)

First, allow script execution if not already enabled:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then run:

```powershell
.\setup.ps1
```

---

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
