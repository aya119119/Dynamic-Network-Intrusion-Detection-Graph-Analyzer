"""
Graph Construction Module for Dynamic Network Intrusion Detection Graph Analyzer (DINDGA)
Builds network graphs from traffic data for analysis and visualization.
"""

import networkx as nx
import pandas as pd


def build_graph(df: pd.DataFrame) -> nx.Graph:
    """
    Build an undirected network graph from network traffic data.
    
    Parameters
    ----------
    df : pd.DataFrame
        DataFrame with columns: Timestamp, Duration, Protocol, SourceIP, DestinationIP,
        SourcePort, DestinationPort, PacketCount, BytesSent, BytesReceived, Label
    
    Returns
    -------
    nx.Graph
        Undirected graph with IP addresses as nodes and edges with attributes.
    """
    G = nx.Graph()
    
    # Add all unique IP addresses as nodes
    all_ips = pd.concat([df['SourceIP'], df['DestinationIP']]).unique()
    G.add_nodes_from(all_ips)
    
    # Add edges with attributes (skip self-loops)
    for _, row in df.iterrows():
        source_ip = row['SourceIP']
        dest_ip = row['DestinationIP']
        
        # Skip self-loops
        if source_ip == dest_ip:
            continue
        
        byte_count = row['BytesSent'] + row['BytesReceived']
        
        edge_attrs = {
            'duration': row['Duration'],
            'packet_count': row['PacketCount'],
            'byte_count': byte_count,
            'protocol': row['Protocol'],
            'source_port': row['SourcePort'],
            'destination_port': row['DestinationPort'],
            'label': row['Label'],
            'timestamp': row['Timestamp']
        }
        
        G.add_edge(source_ip, dest_ip, **edge_attrs)
    
    return G


def get_graph_statistics(G: nx.Graph) -> dict:
    """
    Calculate graph statistics.
    
    Parameters
    ----------
    G : nx.Graph
        The network graph
    
    Returns
    -------
    dict
        Dictionary with keys: num_nodes, num_edges, avg_degree, 
        top_10_nodes, num_connected_components
    """
    num_nodes = G.number_of_nodes()
    num_edges = G.number_of_edges()
    
    avg_degree = (2 * num_edges / num_nodes) if num_nodes > 0 else 0.0
    
    degree_sequence = sorted(G.degree(), key=lambda x: x[1], reverse=True)
    top_10_nodes = degree_sequence[:10]
    
    num_connected_components = nx.number_connected_components(G)
    
    return {
        'num_nodes': num_nodes,
        'num_edges': num_edges,
        'avg_degree': avg_degree,
        'top_10_nodes': top_10_nodes,
        'num_connected_components': num_connected_components
    }


def save_graph(G: nx.Graph, filename: str = "network_graph.gexf") -> None:
    """
    Export the graph to a file for visualization tools.
    
    Parameters
    ----------
    G : nx.Graph
        The network graph
    filename : str
        Output filename (.gexf, .graphml, .gml, or .json)
    
    Raises
    ------
    ValueError
        If the file format is not supported.
    """
    if filename.endswith('.gexf'):
        nx.write_gexf(G, filename)
    elif filename.endswith('.graphml'):
        nx.write_graphml(G, filename)
    elif filename.endswith('.gml'):
        nx.write_gml(G, filename)
    elif filename.endswith('.json'):
        import json
        data = nx.node_link_data(G)
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    else:
        raise ValueError(f"Unsupported format. Use .gexf, .graphml, .gml, or .json")
    
    print(f"✓ Graph saved to {filename}")


if __name__ == "__main__":
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
