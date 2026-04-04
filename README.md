# DINDGA – Dynamic Network Intrusion Detection Graph Analyzer

## Phase 2 - Graph Construction ✅

### 1. Pull Latest Changes
```bash
git pull
```

### 2. Install Dependencies
```bash
pip install networkx pandas
```

### 3. Run the Module Directly
```bash
python graph_builder.py
```

**What it does:**
- Loads `network_traffic_data.csv`
- Builds an undirected NetworkX graph (255 nodes, ~1900 edges)
- Prints graph statistics (nodes, edges, average degree, top 10 IPs, connected components)
- Shows a sample edge with all its attributes (duration, packet count, bytes, protocol, ports, label, timestamp)
- Exports the graph to `network_graph.gexf` for visualization in tools like Gephi

### 4. Run the Test Script
```bash
python test_graph.py
```

**What it does:**
- Same as above but cleaner – imports the module functions and uses them
- Good for testing that the module works correctly
- You can modify this to test different functions or datasets

---

## Phase 3 - Core Algorithms and ML Detection ✅

### 1. Pull Latest Changes
```bash
git pull
```

### 2. Install Dependencies
```bash
pip install scikit-learn numpy
```

> `networkx` and `pandas` are already installed from Phase 2.

### 3. Run the Detection Engine
```bash
python detection_engine.py
```

**What it does:**
- Loads `network_traffic_data.csv` and builds the graph (via `graph_builder.py`)
- Extracts 7 per-IP features: degree, total bytes, total packets, unique destination ports, avg duration, packets/sec, bytes/sec
- Runs **Isolation Forest** anomaly detection (~10% contamination rate)
- Analyses traffic in **10-minute time windows** and flags connection-count spikes
- Combines signals into a weighted **threat score** per IP
- Prints the **top 10 most suspicious IPs** with their scores and reasons
- Saves full results to `detection_results.csv`

### 4. Run the Test Script
```bash
python test_detection.py
```

**What it does:**
- Runs 4 isolated unit tests: feature extraction, anomaly detection, time-window analysis, and the full pipeline
- Verifies that all output columns are present and `detection_results.csv` is created
- Prints a pass/fail summary for each test

### Generated Files

When you run either script, these files are created:

- **`detection_results.csv`** – Full per-IP results table with:
  - All extracted features
  - `anomaly_score` and `is_anomaly` from Isolation Forest
  - `threat_score` (weighted combination of all signals)
  - `reasons` (human-readable tags explaining why an IP is suspicious)

---

## Generated Files (Phase 2)

When you run the Phase 2 scripts, these files are created:

- **`network_graph.gexf`** – Graph in GEXF format (use with Gephi for visualization)
  - Contains all nodes (IPs) and edges with their attributes
  - Best for network visualization

Optional other formats (if you call `save_graph()` with different filenames):
- **`network_graph.graphml`** – GraphML format (universal graph format)
- **`network_graph.gml`** – GML format (lighter file size)
- **`network_graph.json`** – JSON node-link format (for web/custom tools)

---

## Module Reference

### `graph_builder.py`
| Function | Description |
|---|---|
| `build_graph(df)` | Takes a DataFrame, creates nodes from unique IPs, adds edges per row, skips self-loops |
| `get_graph_statistics(G)` | Returns dict with: num_nodes, num_edges, avg_degree, top_10_nodes, num_connected_components |
| `save_graph(G, filename)` | Exports graph to file (.gexf, .graphml, .gml, or .json) |

### `detection_engine.py`
| Function | Description |
|---|---|
| `extract_node_features(df, G)` | Builds a per-IP feature table (7 features) |
| `detect_anomalies(node_features_df)` | Runs Isolation Forest, adds anomaly_score and is_anomaly columns |
| `analyze_time_windows(df, window_minutes)` | Detects connection-count spikes in rolling time windows |
| `run_detection(csv_path, output_path, window_minutes)` | Full end-to-end pipeline, saves detection_results.csv |

---

## Notes
- No self-loops (same source & destination IPs are skipped)
- Undirected graph (connections work both ways)
- Efficient for datasets under 5000 rows
- `detection_engine.py` imports from `graph_builder.py` – both files must be in the same directory

---

## Roadmap

### Phase 1 – Data Foundation ✅
- Fixed CSV with Timestamp, BytesSent, BytesReceived, Label
- Basic data parser and cleaning

### Phase 2 – Graph Construction ✅
- NetworkX graph builder
- Graph statistics and GEXF export

### Phase 3 – Core Algorithms & ML Detection ✅
- Per-IP feature extraction
- Isolation Forest anomaly detection
- Time-window spike detection
- Weighted threat scoring

### Phase 4 – Intrusion Detection Engine
- Combine graph features + ML score into a unified threat score per IP/edge
- Generate alerts with reasoning (e.g. "High degree + high PacketCount + many ports = likely port scan")

### Phase 5 – Dashboard (UI)
- `app.py` with tabs: Data Overview, Graph View, Analysis, Detection Results, Alerts
- Interactive graph visualization
- Filters by Label or threat score
- Timeline slider for dynamic view
- Export detected threats as CSV or report