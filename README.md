

# DINDGA – Dynamic Network Intrusion Detection Graph Analyzer

## Project Structure

```
.
├── src/                          # Core Python modules
│   ├── detection_engine.py       # Phase 3: ML anomaly detection
│   ├── graph_builder.py          # Phase 2: Graph construction
│   ├── intrusion_detection_engine.py # Phase 4: Threat scoring engine
│   └── process_csv.py            # Data processing utility
├── data/                         # Input datasets
│   └── network_traffic_data.csv
├── tests/                        # Test suites
│   ├── test_detection.py         # Detection engine tests
│   ├── test_graph.py             # Graph builder tests
│   └── test_intrusion_detection_engine.py
├── output/                       # Generated results (git-ignored)
│   ├── detection_results.csv
│   ├── threat_alerts.csv
│   └── network_graph.gexf
├── streamlit_app/                # Streamlit web interface
│   ├── app.py
│   └── style.css
├── venv/                         # Virtual environment
├── README.md
└── .gitignore

```

---

## Project Setup

### 1. Installation

Create and activate a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate     # On Linux/Mac
# venv\Scripts\activate     # On Windows
```

Install the required dependencies:

```bash
pip install pandas networkx scikit-learn streamlit pyvis plotly
```

---

## Project Overview

DINDGA is a network intrusion detection system that uses graph analysis and machine learning to identify suspicious activity in network traffic.

It takes network connection data, builds a graph where:

* **Nodes** represent IP addresses
* **Edges** represent network connections

The system analyzes the graph structure and detects potential attacks such as:

* Port scanning
* DDoS
* Data exfiltration

---

## Completed Phases

### Phase 1 – Data Foundation

* Created and cleaned a fixed dataset
* Added **Timestamp** column for temporal (dynamic) analysis
* Built a data parser with basic cleaning and feature engineering

---

### Phase 2 – Graph Construction

* Built `src/graph_builder.py` to convert connection data into a NetworkX graph
* Nodes represent IP addresses
* Edges include attributes:

  * Duration
  * Packet count
  * Byte count
  * Protocol
  * Ports
  * Label
  * Timestamp
* Added graph statistics and export functionality (**GEXF format**)

---

### Phase 3 – Core Algorithms and ML Detection

* Extracted meaningful features per IP:

  * Degree
  * Total bytes
  * Packets
  * Unique ports
  * Packets/sec
* Implemented **Isolation Forest** for anomaly detection
* Added time-window analysis to detect traffic spikes
* Combined multiple signals into initial threat scoring

---

### Phase 4 – Intrusion Detection Engine

* Created `src/intrusion_detection_engine.py`
* Calculates final threat scores using:
  * Graph features
  * ML anomaly scores
* Generates human-readable alerts with reasoning
* Ranks suspicious IPs by danger level
* Saves results to `output/threat_alerts.csv`

---

## Current Status

Phases 1 to 4 are complete.
The core detection logic (**graph analysis + machine learning + threat scoring**) is fully functional.

**Phase 5 (Streamlit Web Interface)** is available in `streamlit_app/`.

---

## Quick Start

### Run Tests

```bash
./venv/bin/python tests/test_detection.py
```

### Run the Detection Engine

```bash
./venv/bin/python -c "from src.intrusion_detection_engine import run_intrusion_detection; run_intrusion_detection()"
```

Or directly:

```bash
cd src && ../venv/bin/python intrusion_detection_engine.py
```

This will:

* Display the top suspicious IPs
* Generate the alerts file in `output/threat_alerts.csv`

### Run the Streamlit Web App

```bash
cd streamlit_app
../../venv/bin/streamlit run app.py
```

The app will be available at `http://localhost:8501`

---
