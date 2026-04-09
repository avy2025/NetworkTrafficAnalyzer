# 📡 Advanced Network Traffic Analyzer

A professional, real-time, multi-threaded network security dashboard and packet analyzer engineered in Python. 

Built using **Streamlit**, **Scapy**, and **psutil**, this tool is designed to actively monitor bandwidth frequency, trace heavily-used IP destinations, map protocol extraction ratios, and autonomously identify irregular bandwidth spiking utilizing custom statistical anomaly heuristics.

---

## 🌟 Key Features

*   **Real-Time Bandwidth Monitoring:** Track global upload/download frequencies live utilizing local Network Interface Cards.
*   **Deep Packet Inspection (DPI):** Utilize background `scapy` daemons isolated in separate memory threads to sniff packets globally targeting TCP, UDP, DNS, and HTTP requests without overflowing RAM constraints (utilizing `store=False`).
*   **Process I/O Mapping:** Cross-reference active connection bindings via `psutil` to isolate the Top 10 target processes dominating system network I/O operations instantly.
*   **Intelligent Anomaly Engine:** Internally manages a trailing 10-second historical traffic baseline. Any polling interval bursting past a **3x multiplier** compared to the safe historical network volume actively trips GUI threat-alert configurations.
*   **Thread-Safe Persistence Logs:** Telemetry logs and system threats are securely buffered in a queue and efficiently flushed to `.csv` formats (rotating bounds to protect disk health against I/O exhaustion).
*   **One-Click Interactivity UI:** Toggle scanning environments natively via checkboxes, while downloading `network_logs` and `anomaly_logs` natively directly via the web portal sidebar interface.

## 🛠️ Technology Stack

*   **Base Language:** `Python 3`
*   **Interface Engine:** `Streamlit` (Powered via `@st.cache_resource` for true background Thread-Survival processing)
*   **Data Restructuring:** `pandas`
*   **Hardware Interfacing:** `psutil`
*   **Network Packet Traversal:** `scapy`

## ⚙️ Installation & Requirements

Because the analyzer heavily leverages Network Driver interception logic to analyze protocols, **System Administrator Rights** are strictly required whenever running the program locally.

**Windows Users** require foundational low-level drivers natively installed to support `scapy`:
- Download & Install [Npcap](https://npcap.com/). Ensure standard interface installation checkboxes are enabled.

### 1. Clone the Database
```bash
git clone https://github.com/avy2025/NetworkTrafficAnalyzer.git
cd NetworkTrafficAnalyzer
```

### 2. Configure Dependencies
```bash
pip install streamlit pandas psutil scapy
```

## 🚀 Execution Guide

1. Open your native terminal app (PowerShell or Command Prompt).
2. Start it **As Administrator**.
3. Point your terminal toward the downloaded project directory. 
4. Kick off the application daemon via the Streamlit hook:

```bash
streamlit run ui.py
```

The system will natively spin up local deployment port servers and populate directly into your default web-browser (`http://localhost:8501`)!

---

## 🏗️ Project Module Architecture

| Software Module | Responsibility Outline |
| :--- | :--- |
| **`ui.py`** | The Streamlit frontend renderer. Completely refactored off structural `st.rerun()` tick-loops generating robust widget interactivity without blocking asynchronous system components. |
| **`analyzer.py`** | The Middle-man machine-learning engine. Aggregates data blocks out of Queue pipes, executes statistical threshold comparisons catching anomaly spikes, and maps objects to the GUI. |
| **`sniffer.py`** | The isolated Network Daemon. Hooks straight into raw driver layers capturing targeted packets inside `threading.Thread` boundaries to prevent interface lock-on blockages. |
| **`monitor.py`** | Foundational Hardware interface passing NIC interval updates extracting high-level generic computer host speed variables. |
| **`utils.py`** | Structurally rigid IO Engine enforcing pure `threading.Lock()` methodologies mechanically streaming metric results flawlessly over to `logs/network_log.csv` and `logs/anomalies.csv`. |

## 🛡️ End Statement
Designed specifically inside development iterations for educational learning logic & administrative network troubleshooting. Completely open-source architectures.
