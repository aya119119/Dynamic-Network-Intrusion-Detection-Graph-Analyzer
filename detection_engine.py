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




# ─────────────────────────────────────────────────────────────────────────────
# 3. TIME-WINDOW SPIKE DETECTION
# ─────────────────────────────────────────────────────────────────────────────
 
def analyze_time_windows(df: pd.DataFrame,
                         window_minutes: int = 10) -> pd.DataFrame:
    """
    Divide the traffic into fixed time windows and track per-IP connection counts.
    A 'spike' is flagged when an IP's degree in a window exceeds
    (mean + 2 × std) across all windows for that IP.
 
    Parameters
    ----------
    df             : pd.DataFrame  – raw traffic data with a 'Timestamp' column
    window_minutes : int           – width of each time slice in minutes
 
    Returns
    -------
    pd.DataFrame with columns:
        ip, window_start, window_degree, mean_degree, std_degree, is_spike
    """
 
    # ── Parse timestamps ──────────────────────────────────────────────────────
    df = df.copy()
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
 
    # ── Define window boundaries ──────────────────────────────────────────────
    t_start = df['Timestamp'].min()
    t_end   = df['Timestamp'].max()
    freq    = f"{window_minutes}min"
 
    # pd.date_range creates evenly-spaced cut points
    bins = pd.date_range(start=t_start, end=t_end + pd.Timedelta(minutes=window_minutes),
                         freq=freq)
 
    # Assign each row to a bin (window)
    df['window'] = pd.cut(df['Timestamp'], bins=bins, labels=bins[:-1], right=False)
    df['window'] = df['window'].astype(str)   # make it hashable for groupby
 
    spike_records = []
 
    # Iterate over every time window that has at least one row
    for window_start, window_df in df.groupby('window'):
        # Build a mini graph for this window only
        G_window = nx.Graph()
        for _, row in window_df.iterrows():
            src, dst = row['SourceIP'], row['DestinationIP']
            if src != dst:
                G_window.add_edge(src, dst)
 
        # Record the degree of each IP in this window
        for ip, deg in G_window.degree():
            spike_records.append({
                'ip'           : ip,
                'window_start' : window_start,
                'window_degree': deg,
            })
 
    if not spike_records:
        print("[analyze_time_windows] No data to analyse.")
        return pd.DataFrame()
 
    spike_df = pd.DataFrame(spike_records)
 
    # ── Compute per-IP statistics across all windows ──────────────────────────
    ip_stats = (spike_df
                .groupby('ip')['window_degree']
                .agg(mean_degree='mean', std_degree='std')
                .fillna(0)
                .reset_index())
 
    spike_df = spike_df.merge(ip_stats, on='ip', how='left')
 
    # Flag a window as a spike if degree > mean + 2*std
    threshold = spike_df['mean_degree'] + 2 * spike_df['std_degree']
    spike_df['is_spike'] = spike_df['window_degree'] > threshold
 
    n_spikes = spike_df['is_spike'].sum()
    n_ips    = spike_df[spike_df['is_spike']]['ip'].nunique()
    print(f"[analyze_time_windows] Detected {n_spikes} spike events across {n_ips} unique IPs")
 
    return spike_df



 
# ─────────────────────────────────────────────────────────────────────────────
# 4. HELPER – REASON TAGS
# ─────────────────────────────────────────────────────────────────────────────
 
def _build_reason(row: pd.Series,
                  spike_ips: set,
                  feature_medians: pd.Series) -> str:
    """
    Build a short human-readable reason string for why an IP is suspicious.
    This is purely for display purposes.
    """
    reasons = []
 
    if row.get('is_anomaly', False):
        reasons.append("IF-anomaly")           # flagged by Isolation Forest
 
    if row.name in spike_ips:
        reasons.append("connection-spike")     # sudden degree spike in time window
 
    # High-degree node (above median)
    if row.get('degree', 0) > feature_medians.get('degree', 0):
        reasons.append("high-degree")
 
    # Unusually many distinct destination ports → possible port scan
    if row.get('unique_dst_ports', 0) > feature_medians.get('unique_dst_ports', 0):
        reasons.append("port-scan-hint")
 
    # Very high byte throughput
    if row.get('bytes_per_second', 0) > feature_medians.get('bytes_per_second', 0):
        reasons.append("high-bandwidth")
 
    return ", ".join(reasons) if reasons else "none"
 
 
# ─────────────────────────────────────────────────────────────────────────────
# 5. MAIN DETECTION PIPELINE
# ─────────────────────────────────────────────────────────────────────────────
 
def run_detection(csv_path: str = "network_traffic_data.csv",
                  output_path: str = "detection_results.csv",
                  window_minutes: int = 10) -> pd.DataFrame:
    """
    End-to-end detection pipeline.
 
    Steps
    -----
    1. Load CSV
    2. Build graph (from graph_builder)
    3. Extract per-IP node features
    4. Run Isolation Forest anomaly detection
    5. Analyse time-window spikes
    6. Compute final threat score (weighted sum of normalised sub-scores)
    7. Print top-10 suspicious IPs
    8. Save results to CSV
 
    Parameters
    ----------
    csv_path      : str  – path to the raw traffic CSV
    output_path   : str  – where to write the results CSV
    window_minutes: int  – time-window size for spike detection
 
    Returns
    -------
    pd.DataFrame  – full results table (one row per IP, sorted by threat_score desc)
    """
 
    print("=" * 60)
    print("  DINDGA – Phase 3 Detection Engine")
    print("=" * 60)
 
    # ── Step 1: Load data ─────────────────────────────────────────────────────
    print(f"\n[1/5] Loading data from '{csv_path}' …")
    df = pd.read_csv(csv_path)
    # Ensure combined byte column exists
    if 'ByteCount' not in df.columns:
        df['ByteCount'] = df['BytesSent'] + df['BytesReceived']
    print(f"      {len(df):,} rows loaded.")
 
    # ── Step 2: Build graph ───────────────────────────────────────────────────
    print("\n[2/5] Building network graph …")
    G = build_graph(df)
    stats = get_graph_statistics(G)
    print(f"      {stats['num_nodes']} nodes, {stats['num_edges']} edges, "
          f"{stats['num_connected_components']} component(s)")
 
    # ── Step 3: Extract features ──────────────────────────────────────────────
    print("\n[3/5] Extracting node features …")
    features_df = extract_node_features(df, G)
 
    # ── Step 4: Anomaly detection ─────────────────────────────────────────────
    print("\n[4/5] Running Isolation Forest anomaly detection …")
    anomaly_df = detect_anomalies(features_df)
 
    # ── Step 5: Time-window spike analysis ────────────────────────────────────
    print(f"\n[5/5] Analysing time windows ({window_minutes}-min buckets) …")
    spike_df = analyze_time_windows(df, window_minutes=window_minutes)
 
    # Collect IPs that had at least one spike window
    spike_ips: set = set()
    if not spike_df.empty:
        spike_ips = set(spike_df[spike_df['is_spike']]['ip'].unique())
 
    # ── Build combined threat score ───────────────────────────────────────────
    # We normalise each sub-signal to [0, 1] and then take a weighted sum.
 
    results = anomaly_df.copy()   # index = ip
 
    # Sub-signal A: Isolation Forest score
    #   anomaly_score is negative-is-bad; invert so higher = worse
    inv_if_score = -results['anomaly_score']
    scaler = MinMaxScaler()
    results['if_score_norm'] = scaler.fit_transform(inv_if_score.values.reshape(-1, 1)).flatten()
 
    # Sub-signal B: Connection spike flag (binary)
    results['spike_score'] = results.index.map(lambda ip: 1.0 if ip in spike_ips else 0.0)
 
    # Sub-signal C: Degree (normalised)
    results['degree_norm'] = scaler.fit_transform(
        results['degree'].values.reshape(-1, 1)).flatten()
 
    # Sub-signal D: Port diversity (normalised)
    results['port_norm'] = scaler.fit_transform(
        results['unique_dst_ports'].values.reshape(-1, 1)).flatten()
 
    # Weighted final score  (weights should sum to 1 for interpretability)
    W_IF     = 0.40   # Isolation Forest is the primary signal
    W_SPIKE  = 0.25   # temporal spike is a strong behavioural indicator
    W_DEGREE = 0.20   # high connectivity is suspicious
    W_PORT   = 0.15   # port scan hint
 
    results['threat_score'] = (
        W_IF     * results['if_score_norm'] +
        W_SPIKE  * results['spike_score']   +
        W_DEGREE * results['degree_norm']   +
        W_PORT   * results['port_norm']
    )
 
    # ── Add human-readable reasons ────────────────────────────────────────────
    feature_cols   = ['degree', 'unique_dst_ports', 'bytes_per_second']
    feature_medians = results[feature_cols].median()
 
    results['reasons'] = results.apply(
        lambda row: _build_reason(row, spike_ips, feature_medians), axis=1
    )
 
    # Sort descending by threat score
    results.sort_values('threat_score', ascending=False, inplace=True)
 
    # ── Print top 10 ──────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  TOP 10 MOST SUSPICIOUS IPs")
    print("=" * 60)
 
    display_cols = ['threat_score', 'is_anomaly', 'degree',
                    'unique_dst_ports', 'bytes_per_second', 'reasons']
 
    top10 = results.head(10)[display_cols].copy()
    top10['threat_score']    = top10['threat_score'].map('{:.4f}'.format)
    top10['bytes_per_second']= top10['bytes_per_second'].map('{:,.0f}'.format)
 
    print(top10.to_string())
 
    # ── Save results ──────────────────────────────────────────────────────────
    # Drop the intermediate normalised columns to keep the CSV clean
    save_cols = ['degree', 'total_byte_count', 'total_packet_count',
                 'unique_dst_ports', 'avg_duration', 'packets_per_second',
                 'bytes_per_second', 'anomaly_score', 'is_anomaly',
                 'threat_score', 'reasons']
 
    results[save_cols].to_csv(output_path)
    print(f"\n✓ Full results saved to '{output_path}'")
    print("=" * 60)
 
    return results
 
if __name__ == "__main__":
    results = run_detection(
        csv_path      = "network_traffic_data.csv",
        output_path   = "detection_results.csv",
        window_minutes= 10
    )