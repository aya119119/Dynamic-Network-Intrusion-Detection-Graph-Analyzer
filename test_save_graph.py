"""Test script for save_graph function"""

import pandas as pd
from graph_builder import build_graph, save_graph

# Load and build graph
df = pd.read_csv('network_traffic_data.csv')
G = build_graph(df)

# Test different formats
print("Testing different export formats...")
save_graph(G, 'test_graph.gexf')
save_graph(G, 'test_graph.graphml')
save_graph(G, 'test_graph.gml')
save_graph(G, 'test_graph.json')

print('\n✓ All formats exported successfully!')
