"""
Detection Engine for Dynamic Network Intrusion Detection Graph Analyzer (DINDGA)
Phase 3: Core Algorithms and Machine Learning Detection

This module:
  - Extracts per-IP features from the traffic DataFrame and NetworkX graph
  - Runs Isolation Forest anomaly detection on those features
  - Analyses traffic in sliding time windows to catch connection-count spikes
  - Saves the base results for Phase 4
"""

import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import networkx as nx
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

from graph_builder import build_graph, get_graph_statistics

def extract_node_features(df: pd.DataFrame, G: nx.Graph) -> pd.DataFrame:
    if 'ByteCount' not in df.columns:
        df = df.copy()
        df['ByteCount'] = df['BytesSent'] + df['BytesReceived']

    records = []
    all_ips = pd.concat([df['SourceIP'], df['DestinationIP']]).unique()

    for ip in all_ips:
        as_source = df[df['SourceIP'] == ip]
        as_dest   = df[df['DestinationIP'] == ip]
        involved  = pd.concat([as_source, as_dest])

        degree = G.degree(ip) if ip in G else 0
        total_bytes   = involved['ByteCount'].sum()
        total_packets = involved['PacketCount'].sum()
        
        # Unique ports and entropy
        unique_dst_ports = as_source['DestinationPort'].nunique() if len(as_source) > 0 else 0
        if unique_dst_ports > 0:
            port_counts = as_source['DestinationPort'].value_counts()
            probs = port_counts / len(as_source)
            port_entropy = - (probs * np.log2(probs)).sum()
        else:
            port_entropy = 0.0

        avg_dur      = involved['Duration'].mean() if len(involved) > 0 else 0.0
        total_dur    = involved['Duration'].sum()

        if total_dur > 0:
            pps = total_packets / total_dur
            bps = total_bytes   / total_dur
        else:
            pps = 0.0
            bps = 0.0

        # Connection density (connections per second if total_dur > 0)
        conn_density = len(involved) / total_dur if total_dur > 0 else 0.0

        records.append({
            'ip'               : ip,
            'degree'           : degree,
            'total_byte_count' : total_bytes,
            'total_packet_count': total_packets,
            'unique_dst_ports' : unique_dst_ports,
            'port_entropy'     : port_entropy,
            'avg_duration'     : avg_dur,
            'packets_per_second': pps,
            'bytes_per_second' : bps,
            'connection_density': conn_density
        })

    features_df = pd.DataFrame(records)
    features_df.set_index('ip', inplace=True)

    print(f"[extract_node_features] Built feature table: "
          f"{len(features_df)} IPs x {len(features_df.columns)} features")
    return features_df


def detect_anomalies(node_features_df: pd.DataFrame,
                     contamination: float = 0.1) -> pd.DataFrame:
    result_df = node_features_df.copy()
    X = result_df.values

    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42
    )
    iso_forest.fit(X)

    raw_scores = iso_forest.decision_function(X)
    predictions = iso_forest.predict(X)

    result_df['anomaly_score'] = raw_scores
    result_df['is_anomaly']    = predictions == -1

    n_anomalies = result_df['is_anomaly'].sum()
    print(f"[detect_anomalies] Isolation Forest found {n_anomalies} anomalous IPs "
          f"({n_anomalies / len(result_df) * 100:.1f}%)")

    return result_df


def analyze_time_windows(df: pd.DataFrame, window_minutes: int = 5) -> tuple[pd.DataFrame, int, int]:
    df = df.copy()
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])

    # 1. Group data into time windows
    t_start = df['Timestamp'].min()
    t_end   = df['Timestamp'].max()
    freq    = f"{window_minutes}min"

    bins = pd.date_range(start=t_start, end=t_end + pd.Timedelta(minutes=window_minutes), freq=freq)
    
    df['window'] = pd.cut(df['Timestamp'], bins=bins, labels=bins[:-1], right=False).astype(str)

    # 2. Count number of connections per window for each IP
    sources = df[['window', 'SourceIP']].rename(columns={'SourceIP': 'ip'})
    destinations = df[['window', 'DestinationIP']].rename(columns={'DestinationIP': 'ip'})
    involved = pd.concat([sources, destinations])
    
    window_counts = involved.groupby(['window', 'ip']).size().reset_index(name='count')
    spike_df = window_counts[window_counts['count'] > 0].copy()

    if spike_df.empty:
        print("[analyze_time_windows] No data to analyse.")
        return pd.DataFrame(), 0, 0

    # 3. Compute mean and standard deviation of connections per window
    ip_stats = (
        spike_df
        .groupby('ip')['count']
        .agg(mean='mean', std='std')
        .reset_index()
    )

    spike_df = spike_df.merge(ip_stats, on='ip', how='left')

    # 4. Detect spikes with fallback
    # count > mean + 2 * std
    # If std is 0 or NaN, use fallback: count > 3 * mean
    condition_standard = spike_df['count'] > (spike_df['mean'] + 2 * spike_df['std'])
    condition_fallback = spike_df['count'] > (3 * spike_df['mean'])
    
    # Apply conditions based on whether std is missing or zero
    std_is_invalid = spike_df['std'].isna() | (spike_df['std'] == 0)
    
    # 5. Mark each row with a new column `is_spike`
    spike_df['is_spike'] = np.where(std_is_invalid, condition_fallback, condition_standard)

    # 6. Return: Updated dataframe, Number of spike events, Number of affected IPs
    n_spikes = spike_df['is_spike'].sum()
    n_ips    = spike_df[spike_df['is_spike']]['ip'].nunique()
    print(f"[analyze_time_windows] Detected {n_spikes} spike events across {n_ips} unique IPs")

    return spike_df, n_spikes, n_ips


def run_detection(csv_path: str = "network_traffic_data.csv",
                  output_path: str = "detection_results.csv",
                  window_minutes: int = 5) -> pd.DataFrame:
    print("=" * 60)
    print("  DINDGA - Phase 3 Detection Engine")
    print("=" * 60)

    print(f"\n[1/5] Loading data from '{csv_path}' ...")
    df = pd.read_csv(csv_path)
    if 'ByteCount' not in df.columns:
        df['ByteCount'] = df['BytesSent'] + df['BytesReceived']
    print(f"      {len(df):,} rows loaded.")

    print("\n[2/5] Building network graph ...")
    G = build_graph(df)
    stats = get_graph_statistics(G)
    print(f"      {stats['num_nodes']} nodes, {stats['num_edges']} edges, "
          f"{stats['num_connected_components']} component(s)")

    print("\n[3/5] Extracting node features ...")
    features_df = extract_node_features(df, G)

    print("\n[4/5] Running Isolation Forest anomaly detection ...")
    anomaly_df = detect_anomalies(features_df)

    print(f"\n[5/5] Analysing time windows ({window_minutes}-min buckets) ...")
    spike_df, n_spikes, n_ips = analyze_time_windows(df, window_minutes=window_minutes)

    spike_ips: set = set()
    if not spike_df.empty:
        spike_ips = set(spike_df[spike_df['is_spike']]['ip'].unique())

    results = anomaly_df.copy()
    results['is_spike'] = results.index.map(lambda ip: True if ip in spike_ips else False)

    save_cols = ['degree', 'total_byte_count', 'total_packet_count',
                 'unique_dst_ports', 'avg_duration', 'packets_per_second',
                 'bytes_per_second', 'anomaly_score', 'is_anomaly', 'is_spike']
 
    results[save_cols].to_csv(output_path)
    print(f"\n[OK] Full base results saved to '{output_path}'")
    print("=" * 60)
 
    return results

if __name__ == "__main__":
    results = run_detection()
