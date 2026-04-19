"""
Phase 4: Intrusion Detection Engine for DINDGA

This module ties together graph construction, feature extraction,
anomaly detection, temporal analysis, and final threat scoring.
"""

import pandas as pd

from graph_builder import build_graph, get_graph_statistics
from detection_engine import (
    analyze_time_windows,
    detect_anomalies,
    extract_node_features,
)


def _normalize_series(series: pd.Series) -> pd.Series:
    """Normalize a pandas Series to the range [0, 1]."""
    min_val = series.min()
    max_val = series.max()

    if pd.isna(min_val) or pd.isna(max_val) or min_val == max_val:
        return pd.Series(0.0, index=series.index)

    return (series - min_val) / (max_val - min_val)


def _assign_threat_level(score: float) -> str:
    """Convert a threat score into a human-readable threat level."""
    if score >= 0.7:
        return "High"
    if score >= 0.4:
        return "Medium"
    return "Low"


def _build_reason(row: pd.Series) -> str:
    """Build a short explanation for the alert reason."""
    reasons = []

    if row.get("degree_score", 0.0) >= 0.7:
        reasons.append("high degree")
    if row.get("port_scan_score", 0.0) >= 0.7:
        reasons.append("many unique ports")
    if row.get("anomaly_score_norm", 0.0) >= 0.6:
        reasons.append("high anomaly score")
    if row.get("temporal_score", 0.0) >= 0.5:
        reasons.append("temporal spike")

    if not reasons:
        return "Elevated risk due to combined suspicious signals"

    reason_text = " + ".join(reasons)
    if "many unique ports" in reasons:
        return f"{reason_text} = Possible port scanning"

    return f"{reason_text} = Suspicious activity"


def calculate_threat_score(node_features_df: pd.DataFrame) -> pd.DataFrame:
    """Calculate the final threat score and threat level for each IP.

    Parameters
    ----------
    node_features_df : pd.DataFrame
        Detection engine output with at least: degree, unique_dst_ports,
        anomaly_score. Can optionally include temporal_score.

    Returns
    -------
    pd.DataFrame
        Copy of the input table with added columns:
        degree_score, anomaly_score_norm, port_scan_score,
        temporal_score, threat_score, threat_level.
    """
    required_columns = ["degree", "unique_dst_ports", "anomaly_score"]
    for col in required_columns:
        if col not in node_features_df.columns:
            raise ValueError(f"Input DataFrame must contain '{col}' column")

    results = node_features_df.copy()

    # Ensure we always have a temporal score column for the formula.
    if "temporal_score" not in results.columns:
        results["temporal_score"] = 0.0

    # Normalize the raw signals into [0, 1] ranges.
    results["degree_score"] = _normalize_series(results["degree"])
    results["port_scan_score"] = _normalize_series(results["unique_dst_ports"])
    results["anomaly_score_norm"] = _normalize_series(-results["anomaly_score"])
    results["temporal_score"] = _normalize_series(results["temporal_score"])

    # Weighted final threat score.
    results["threat_score"] = (
        0.35 * results["degree_score"] +
        0.25 * results["anomaly_score_norm"] +
        0.20 * results["port_scan_score"] +
        0.20 * results["temporal_score"]
    )

    results["threat_level"] = results["threat_score"].apply(_assign_threat_level)

    return results


def generate_alerts(results_df: pd.DataFrame) -> pd.DataFrame:
    """Generate a concise alert table for suspicious IPs.

    Parameters
    ----------
    results_df : pd.DataFrame
        DataFrame with threat_score and threat_level already computed.

    Returns
    -------
    pd.DataFrame
        A summary table of alerts for IPs with threat_score > 0.6.
    """
    if "threat_score" not in results_df.columns:
        raise ValueError("Input DataFrame must contain 'threat_score' column")

    alerts = results_df.copy()
    alerts = alerts[alerts["threat_score"] > 0.6].copy()

    if alerts.empty:
        return pd.DataFrame(
            columns=["ip", "threat_score", "threat_level", "reason"]
        )

    alerts["reason"] = alerts.apply(_build_reason, axis=1)

    summary = alerts.reset_index()[
        ["ip", "threat_score", "threat_level", "reason"]
    ].copy()

    summary["threat_score"] = summary["threat_score"].round(4)

    return summary


def run_intrusion_detection(
    csv_path: str = "network_traffic_data.csv",
    output_path: str = "threat_alerts.csv",
    window_minutes: int = 10,
):
    """Execute the Phase 4 intrusion detection workflow.

    This function:
      1. Loads raw traffic data
      2. Builds the network graph
      3. Extracts node features
      4. Detects anomalies
      5. Computes temporal spike scores
      6. Calculates the final threat score
      7. Generates and saves alerts
    """
    print("\n=== DINDGA Phase 4: Intrusion Detection Engine ===")
    print(f"Loading data from: {csv_path}")

    df = pd.read_csv(csv_path)
    if "ByteCount" not in df.columns:
        df["ByteCount"] = df["BytesSent"] + df["BytesReceived"]

    print(f"Loaded {len(df):,} traffic records")

    print("\nBuilding the network graph...")
    G = build_graph(df)
    stats = get_graph_statistics(G)
    print(f"Graph: {stats['num_nodes']} nodes, {stats['num_edges']} edges, "
          f"{stats['num_connected_components']} components")

    print("\nExtracting node features...")
    features_df = extract_node_features(df, G)

    print("\nRunning anomaly detection...")
    anomaly_df = detect_anomalies(features_df)

    print("\nAnalysing temporal spike behaviour...")
    spike_df = analyze_time_windows(df, window_minutes=window_minutes)
    if spike_df.empty:
        temporal_scores = pd.Series(0.0, index=anomaly_df.index)
    else:
        spike_counts = (
            spike_df[spike_df["is_spike"]]
            .groupby("ip")
            .size()
            .reindex(anomaly_df.index, fill_value=0)
        )
        temporal_scores = _normalize_series(spike_counts)

    anomaly_df["temporal_score"] = temporal_scores

    print("\nCalculating final threat scores...")
    final_df = calculate_threat_score(anomaly_df)
    final_df.sort_values("threat_score", ascending=False, inplace=True)

    print("\nGenerating alerts for high-risk IPs...")
    alerts_df = generate_alerts(final_df)
    alerts_df.to_csv(output_path, index=False)

    print(f"Saved alerts to: {output_path}")
    print("\nTop 10 most dangerous IPs:")

    top10 = final_df.head(10).copy()
    display_cols = [
        "threat_score", "threat_level", "degree",
        "unique_dst_ports", "anomaly_score", "temporal_score"
    ]
    print(top10[display_cols].round(4).to_string())

    return final_df, alerts_df


if __name__ == "__main__":
    run_intrusion_detection()
