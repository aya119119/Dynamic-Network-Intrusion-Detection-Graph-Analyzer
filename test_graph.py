"""
Test script for graph_builder module
"""

import pandas as pd
from graph_builder import build_graph, get_graph_statistics, save_graph


def main():
    # Load data
    df = pd.read_csv('network_traffic_data.csv')
    print(f"Loaded {len(df)} records from CSV\n")
    
    # Build graph
    G = build_graph(df)
    print(f"Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges\n")
    
    # Get statistics
    stats = get_graph_statistics(G)
    print("=== Graph Statistics ===")
    print(f"Nodes: {stats['num_nodes']}")
    print(f"Edges: {stats['num_edges']}")
    print(f"Average Degree: {stats['avg_degree']:.3f}")
    print(f"Connected Components: {stats['num_connected_components']}")
    print(f"\nTop 10 Nodes by Degree:")
    for ip, degree in stats['top_10_nodes']:
        print(f"  {ip}: {degree}")
    
    # Show example edge data
    print(f"\n=== Sample Edge Data ===")
    sample_edge = list(G.edges(data=True))[0]
    print(f"Edge: {sample_edge[0]} <-> {sample_edge[1]}")
    print(f"Attributes: {sample_edge[2]}")
    
    # Export graph
    save_graph(G, "network_graph.gexf")


if __name__ == "__main__":
    main()
