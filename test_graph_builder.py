"""Test script for graph_builder module"""

import pandas as pd
from graph_builder import build_graph, get_graph_statistics

# Load data
df = pd.read_csv('network_traffic_data.csv')
print(f'✓ Loaded CSV: {len(df)} rows')

# Build graph
G = build_graph(df)
print(f'✓ Graph built successfully')

# Get statistics
stats = get_graph_statistics(G)
print(f'✓ Statistics calculated')
print(f'\n--- Graph Statistics ---')
print(f'Nodes: {stats["num_nodes"]}')
print(f'Edges: {stats["num_edges"]}')
print(f'Avg Degree: {stats["avg_degree"]:.3f}')
print(f'Connected Components: {stats["num_connected_components"]}')
print(f'\nTop 10 nodes by degree:')
for ip, degree in stats['top_10_nodes']:
    print(f'  {ip}: {degree}')
