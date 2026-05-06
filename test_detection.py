"""
PHASE 3
Quick test script for detection_engine.py 

"""

import pandas as pd
from detection_engine import (
    extract_node_features,
    detect_anomalies,
    analyze_time_windows,
    run_detection,
)
from graph_builder import build_graph


def test_feature_extraction():
    """Check that feature extraction returns the right shape and no NaN columns."""
    print("\n── Test: extract_node_features ──")
    df = pd.read_csv("network_traffic_data.csv")
    if 'ByteCount' not in df.columns:
        df['ByteCount'] = df['BytesSent'] + df['BytesReceived']
    G = build_graph(df)

    features = extract_node_features(df, G)

    assert not features.empty, "Feature table should not be empty"
    expected_cols = ['degree', 'total_byte_count', 'total_packet_count',
                     'unique_dst_ports', 'avg_duration',
                     'packets_per_second', 'bytes_per_second']
    for col in expected_cols:
        assert col in features.columns, f"Missing column: {col}"

    print(f"  ✓ Shape: {features.shape[0]} IPs × {features.shape[1]} features")
    print(f"  ✓ All expected columns present")
    print(f"  Sample (first 3 rows):\n{features.head(3)}\n")


def test_anomaly_detection():
    """Ensure Isolation Forest adds the two required output columns."""
    print("── Test: detect_anomalies ──")
    df = pd.read_csv("network_traffic_data.csv")
    if 'ByteCount' not in df.columns:
        df['ByteCount'] = df['BytesSent'] + df['BytesReceived']
    G = build_graph(df)

    features = extract_node_features(df, G)
    result   = detect_anomalies(features)

    assert 'anomaly_score' in result.columns, "Missing anomaly_score column"
    assert 'is_anomaly'    in result.columns, "Missing is_anomaly column"
    assert result['is_anomaly'].dtype == bool, "is_anomaly should be boolean"

    n_flagged = result['is_anomaly'].sum()
    print(f"  ✓ anomaly_score and is_anomaly columns present")
    print(f"  ✓ {n_flagged} IPs flagged as anomalies\n")


def test_time_windows():
    """Check that time-window analysis returns spike data."""
    print("── Test: analyze_time_windows ──")
    df  = pd.read_csv("network_traffic_data.csv")
    out = analyze_time_windows(df, window_minutes=10)

    assert not out.empty, "Spike DataFrame should not be empty"
    assert 'is_spike' in out.columns, "Missing is_spike column"

    spikes = out[out['is_spike']]
    print(f"  ✓ {len(out)} window-IP combinations analysed")
    print(f"  ✓ {len(spikes)} spike events detected\n")


def test_full_pipeline():
    """Run the complete pipeline and verify the output CSV exists."""
    import os
    print("── Test: run_detection (full pipeline) ──")

    results = run_detection(
        csv_path      = "network_traffic_data.csv",
        output_path   = "detection_results.csv",
        window_minutes= 10,
    )

    assert not results.empty, "Results DataFrame should not be empty"
    assert 'threat_score' in results.columns, "Missing threat_score column"
    assert os.path.exists("detection_results.csv"), "Output CSV not created"

    print("\n  ✓ detection_results.csv written successfully")
    print(f"  ✓ {len(results)} IPs scored")
    print(f"\n  Top 5 threat scores:")
    print(results['threat_score'].head(5).to_string())


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_feature_extraction()
    test_anomaly_detection()
    test_time_windows()
    test_full_pipeline()
    print("\n✓ All tests passed.")