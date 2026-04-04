"""
Detection Engine for Dynamic Network Intrusion Detection Graph Analyzer (DINDGA)
Phase 3: Core Algorithms and Machine Learning Detection

This module:
  - Extracts per-IP features from the traffic DataFrame and NetworkX graph
  - Runs Isolation Forest anomaly detection on those features
  - Analyses traffic in sliding time windows to catch connection-count spikes
  - Combines everything into a single threat score per IP
  - Saves and prints the top-10 most suspicious IPs
"""

# ── Standard library ─────────────────────────────────────────────────────────
import warnings
warnings.filterwarnings("ignore")   # keep the console output tidy

# ── Third-party ───────────────────────────────────────────────────────────────
import numpy as np
import pandas as pd
import networkx as nx
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

# ── Local project ─────────────────────────────────────────────────────────────
from graph_builder import build_graph, get_graph_statistics


# ─────────────────────────────────────────────────────────────────────────────
# 1. FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def extract_node_feature(df: pd.DataFrame, G: nx.Graph) -> pd.DataFrame:
    """
    Build a feature table with one row per unique IP address.

    Features computed
    -----------------
    degree               : number of distinct neighbours in the graph
    total_byte_count     : sum of BytesSent + BytesReceived across all rows
    total_packet_count   : sum of PacketCount
    unique_dst_ports     : how many different destination ports this IP talked to
    avg_duration         : mean session Duration (seconds)
    packets_per_second   : total_packet_count / total_duration  (activity rate)
    bytes_per_second     : total_byte_count   / total_duration

    Parameters
    ----------
    df : pd.DataFrame
        Raw traffic data (must include the columns shown in the CSV header).
    G  : nx.Graph
        Graph already built by build_graph(df).

    Returns
    -------
    pd.DataFrame  – one row per IP, columns = [ip] + feature names
    """

    # ── Derive a combined byte column if only the split columns exist ─────────
    if 'ByteCount' not in df.columns:
        df = df.copy()
        df['ByteCount'] = df['BytesSent'] + df['BytesReceived']

    records = []   # we'll append one dict per IP, then build the DataFrame

    # Collect every unique IP that appears as source OR destination
    all_ips = pd.concat([df['SourceIP'], df['DestinationIP']]).unique()

    for ip in all_ips:

        # Rows where this IP is the SOURCE
        as_source = df[df['SourceIP'] == ip]
        # Rows where this IP is the DESTINATION
        as_dest   = df[df['DestinationIP'] == ip]
        # All rows that involve this IP in either role
        involved  = pd.concat([as_source, as_dest])

        # ── Degree from the NetworkX graph ────────────────────────────────────
        # G.degree(ip) returns the number of edges connected to this node.
        degree = G.degree(ip) if ip in G else 0

        # ── Volume features ───────────────────────────────────────────────────
        total_bytes   = involved['ByteCount'].sum()
        total_packets = involved['PacketCount'].sum()

        # ── Port diversity ────────────────────────────────────────────────────
        # Only count destination ports from rows where this IP is the source,
        # because that reflects scanning / connection behaviour.
        unique_dst_ports = as_source['DestinationPort'].nunique() if len(as_source) > 0 else 0

        # ── Duration-based rate features ─────────────────────────────────────
        avg_dur      = involved['Duration'].mean() if len(involved) > 0 else 0.0
        total_dur    = involved['Duration'].sum()

        # Guard against division by zero for very short / missing durations
        if total_dur > 0:
            pps = total_packets / total_dur   # packets per second
            bps = total_bytes   / total_dur   # bytes per second
        else:
            pps = 0.0
            bps = 0.0

        records.append({
            'ip'               : ip,
            'degree'           : degree,
            'total_byte_count' : total_bytes,
            'total_packet_count': total_packets,
            'unique_dst_ports' : unique_dst_ports,
            'avg_duration'     : avg_dur,
            'packets_per_second': pps,
            'bytes_per_second' : bps,
        })

    features_df = pd.DataFrame(records)
    features_df.set_index('ip', inplace=True)

    print(f"[extract_node_features] Built feature table: "
          f"{len(features_df)} IPs × {len(features_df.columns)} features")
    return features_df





 
# ─────────────────────────────────────────────────────────────────────────────
# 2. ANOMALY DETECTION  (Isolation Forest)
# ─────────────────────────────────────────────────────────────────────────────
 
def detect_anomalies(node_features_df: pd.DataFrame,
                     contamination: float = 0.1) -> pd.DataFrame:
    """
    Run Isolation Forest on the node feature table and mark anomalous IPs.
 
    Isolation Forest works by randomly partitioning the feature space.
    Points that are easy to isolate (short average path length) are anomalies.
    contamination=0.1 means we expect ~10% of IPs to be anomalous.
 
    Adds two columns to the returned DataFrame
    ------------------------------------------
    anomaly_score : float  – raw IF decision score; more negative = more anomalous
    is_anomaly    : bool   – True if the IF classifies the IP as an outlier
 
    Parameters
    ----------
    node_features_df : pd.DataFrame  (index = ip, columns = numeric features)
    contamination    : float          fraction of expected anomalies (0 < x < 0.5)
 
    Returns
    -------
    pd.DataFrame  – original df with two new columns appended
    """
 
    result_df = node_features_df.copy()
 
    # Pull out the numeric feature matrix (all columns are already numeric)
    X = result_df.values
 
    # ── Train Isolation Forest ────────────────────────────────────────────────
    # random_state=42 makes results reproducible
    iso_forest = IsolationForest(
        n_estimators=100,       # number of isolation trees
        contamination=contamination,
        random_state=42
    )
    iso_forest.fit(X)
 
    # decision_function returns a score: negative = more anomalous
    raw_scores = iso_forest.decision_function(X)    # shape (n_ips,)
    predictions = iso_forest.predict(X)             # +1 = normal, -1 = anomaly
 
    result_df['anomaly_score'] = raw_scores
    result_df['is_anomaly']    = predictions == -1  # convert to True/False
 
    n_anomalies = result_df['is_anomaly'].sum()
    print(f"[detect_anomalies] Isolation Forest found {n_anomalies} anomalous IPs "
          f"({n_anomalies / len(result_df) * 100:.1f}%)")
 
    return result_df
 