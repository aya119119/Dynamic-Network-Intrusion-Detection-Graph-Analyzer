"""
Graph Construction Module for Dynamic Network Intrusion Detection Graph Analyzer (DINDGA)

This module provides functionality to build network graphs from network traffic data.
"""

import networkx as nx
import pandas as pd


def build_graph(df: pd.DataFrame) -> nx.Graph:
    """
    Build an undirected network graph from network traffic data.
    
    Parameters
    ----------
    df : pd.DataFrame
        DataFrame containing network traffic data with the following columns:
        - Timestamp: datetime of the traffic event
        - Duration: float value representing connection duration
        - Protocol: string (TCP, UDP, etc.)
        - SourceIP: string IP address of source
        - DestinationIP: string IP address of destination
        - SourcePort: integer port number
        - DestinationPort: integer port number
        - PacketCount: integer number of packets
        - BytesSent: integer bytes sent
        - BytesReceived: integer bytes received
        - Label: string (Normal, Attack, or specific attack type)
    
    Returns
    -------
    nx.Graph
        An undirected NetworkX graph where:
        - Nodes: unique IP addresses (from SourceIP and DestinationIP)
        - Edges: one edge per row between SourceIP and DestinationIP
        - Edge attributes: duration, packet_count, byte_count, protocol,
                          source_port, destination_port, label, timestamp
    
    Examples
    --------
    >>> df = pd.read_csv('dindga_fixed_data_with_time.csv')
    >>> G = build_graph(df)
    >>> print(f"Nodes: {G.number_of_nodes()}, Edges: {G.number_of_edges()}")
    """
    
    # Create an empty undirected graph
    G = nx.Graph()
    
    # Add nodes: all unique IP addresses
    all_ips = pd.concat([df['SourceIP'], df['DestinationIP']]).unique()
    G.add_nodes_from(all_ips)
    
    # Add edges with attributes from each row
    for _, row in df.iterrows():
        source_ip = row['SourceIP']
        dest_ip = row['DestinationIP']
        
        # Calculate total byte count
        byte_count = row['BytesSent'] + row['BytesReceived']
        
        # Edge attributes
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
        
        # Add edge (undirected, so order doesn't matter)
        G.add_edge(source_ip, dest_ip, **edge_attrs)
    
    return G


def get_graph_statistics(G: nx.Graph) -> dict:
    """
    Calculate and return comprehensive statistics about the network graph.
    
    Parameters
    ----------
    G : nx.Graph
        The network graph to analyze.
    
    Returns
    -------
    dict
        A dictionary containing the following statistics:
        - 'num_nodes': int, total number of nodes (IP addresses)
        - 'num_edges': int, total number of edges (connections)
        - 'avg_degree': float, average degree of all nodes
        - 'top_10_nodes': list of tuples, top 10 nodes by degree (IP, degree)
        - 'num_connected_components': int, number of connected components
    
    Examples
    --------
    >>> stats = get_graph_statistics(G)
    >>> print(f"Nodes: {stats['num_nodes']}")
    >>> print(f"Top nodes: {stats['top_10_nodes']}")
    """
    
    num_nodes = G.number_of_nodes()
    num_edges = G.number_of_edges()
    
    # Calculate average degree
    if num_nodes > 0:
        avg_degree = 2 * num_edges / num_nodes
    else:
        avg_degree = 0.0
    
    # Get top 10 nodes by degree
    degree_sequence = sorted(G.degree(), key=lambda x: x[1], reverse=True)
    top_10_nodes = degree_sequence[:10]
    
    # Count connected components
    num_connected_components = nx.number_connected_components(G)
    
    # Compile statistics
    statistics = {
        'num_nodes': num_nodes,
        'num_edges': num_edges,
        'avg_degree': avg_degree,
        'top_10_nodes': top_10_nodes,
        'num_connected_components': num_connected_components
    }
    
    return statistics
