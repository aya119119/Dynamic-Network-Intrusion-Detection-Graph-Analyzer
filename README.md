

# DINDGA – Dynamic Network Intrusion Detection Graph Analyzer

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

### 2. Project Files

Make sure you have the following files in your project folder:

* `dindga_fixed_data_with_time.csv` (main dataset)
* `graph_builder.py`
* `detection_engine.py`
* `intrusion_detection_engine.py`
* `app.py` *(coming in Phase 5)*

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

* Created and cleaned a fixed dataset (`dindga_fixed_data_with_time.csv`)
* Added **Timestamp** column for temporal (dynamic) analysis
* Built a data parser with basic cleaning and feature engineering

---

### Phase 2 – Graph Construction

* Built `graph_builder.py` to convert connection data into a NetworkX graph
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

* Created `intrusion_detection_engine.py`
* Calculates final threat scores using:

  * Graph features
  * ML anomaly scores
* Generates human-readable alerts with reasoning
* Ranks suspicious IPs by danger level
* Saves results to `threat_alerts.csv`

---

## Current Status

Phases 1 to 4 are complete.
The core detection logic (**graph analysis + machine learning + threat scoring**) is fully functional.

**Phase 5 (Streamlit Web Interface)** is not yet implemented.

---

## Run the Detection Engine

```bash
python intrusion_detection_engine.py
```

This will:

* Display the top suspicious IPs
* Generate the alerts file (`threat_alerts.csv`)

---
