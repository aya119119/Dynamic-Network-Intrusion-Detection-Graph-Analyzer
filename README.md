#Phase 2 - Graph Construction


### 1. Pull Latest Changes
```bash
git pull
```

### 2. Run the Module Directly
```bash
python graph_builder.py
```

**What it does:**
- Loads `network_traffic_data.csv`
- Builds an undirected NetworkX graph (255 nodes, ~1900 edges)
- Prints graph statistics (nodes, edges, average degree, top 10 IPs, connected components)
- Shows a sample edge with all its attributes (duration, packet count, bytes, protocol, ports, label, timestamp)
- Exports the graph to `network_graph.gexf` for visualization in tools like Gephi

### 3. Run the Test Script
```bash
python test_graph.py
```

**What it does:**
- Same as above but cleaner - imports the module functions and uses them
- Good for testing that the module works correctly
- You can modify this to test different functions or datasets

## Generated Files

When you run either script, these files are created:

- **`network_graph.gexf`** - Graph in GEXF format (use with Gephi for visualization)
  - Contains all nodes (IPs) and edges with their attributes
  - Best for network visualization

Optional other formats (if you call `save_graph()` with different filenames):
- **`network_graph.graphml`** - GraphML format (universal graph format)
- **`network_graph.gml`** - GML format (lighter file size)
- **`network_graph.json`** - JSON node-link format (for web/custom tools)

## Module Functions

### `build_graph(df)`
Takes a DataFrame, creates nodes from unique IPs, adds edges per row, skips self-loops.

### `get_graph_statistics(G)`
Returns dict with: num_nodes, num_edges, avg_degree, top_10_nodes, num_connected_components

### `save_graph(G, filename)`
Exports graph to file (.gexf, .graphml, .gml, or .json)

## Notes
- No self-loops (same source & destination IPs are skipped)
- Undirected graph (connections work both ways)
- Efficient for datasets under 5000 rows
