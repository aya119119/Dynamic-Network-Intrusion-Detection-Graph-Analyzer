# DINDGA Phase 2 - Graph Construction - DONE

## Overview
Phase 2 builds a network graph from network traffic data. Nodes are IP addresses, edges are connections between them with traffic attributes.

## Quick Start

### 1. Pull Latest Changes
```bash
git pull
```

### 2. Run the Module Directly
```bash
python graph_builder.py
```




Phase 1 Completion (Data Foundation) – Finish These First
Finalize the Data Parser
Create data_parser.py with a function that loads your fixed CSV, adds basic cleaning, and creates useful derived features (PacketsPerSecond, BytesPerSecond, AvgPacketSize).
Test it and make sure it prints the number of rows, time span, and Label distribution.
Document Your Dataset (for report)
Write a short paragraph:  Size of dataset (number of rows)  
Time period (from first to last timestamp)  
Number of Normal vs Attack records  
Note that Timestamp was added for dynamic analysis

Phase 2: Graph Construction (Next Major Step)
Create Graph Builder Module
Build a function that takes the DataFrame and creates a NetworkX graph:  Nodes = unique IPs (SourceIP + DestinationIP)  
Edges = every connection with attributes (Duration, PacketCount, ByteCount, Protocol, DestinationPort, Label, Timestamp)

Add Basic Graph Statistics
Calculate and print:  Total nodes and edges  
Top 10 IPs with highest degree (most connections)  
Average degree

Test Graph Visualization
Create a small interactive graph visualization using Pyvis or Plotly (start with max 100–200 edges so it doesn't lag).
Save or display the graph image/HTML.

Phase 3: Core Analysis & ML Detection
Implement Graph Algorithms  Degree Centrality  
Betweenness Centrality (optional at first)  
Community Detection (Louvain if possible)  
Find highly connected nodes or unusual communities

Feature Engineering for ML
Create features such as:  Per-IP statistics (total bytes, total packets, unique ports contacted, average degree)  
Time-window based features (connections per 5-min window)  
Anomaly-friendly features (PacketsPerSecond, BytesPerSecond, etc.)

Build Anomaly Detection Model  Use Isolation Forest or Local Outlier Factor (LOF) on the features  
Train on "Normal" connections or use unsupervised mode  
Generate anomaly scores for each connection or each IP

Phase 4: Intrusion Detection Engine
Create Threat Scoring System
Combine graph features + ML anomaly score into a single threat score per IP or per edge.
Generate Alerts
Flag top suspicious IPs and connections with reasoning (e.g., “High degree + high PacketCount + many different ports = likely port scan”).

Phase 5: Streamlit Dashboard (UI)
Set Up Streamlit App
Create app.py with pages/tabs: Data Overview, Graph View, Analysis, Detection Results, Alerts.
Add Interactive Features  Upload your fixed CSV (or load default)  
Interactive graph visualization  
Filters by Label or threat score  
Timeline slider for dynamic view

Export Functionality
Allow exporting detected threats as CSV or simple report.
