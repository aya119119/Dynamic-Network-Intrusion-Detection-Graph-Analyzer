#!/usr/bin/env python
"""Quick test script for the report generator"""

import sys
sys.path.insert(0, '/home/ayadr/algo/Dynamic-Network-Intrusion-Detection-Graph-Analyzer/report')

from report_analysis import (
    load_detection_results, load_threat_alerts, load_network_data,
    prepare_threat_score_top_ips, prepare_port_scanning_indicators,
    prepare_traffic_metrics_scatter
)
import os

BASE_DIR = '/home/ayadr/algo/Dynamic-Network-Intrusion-Detection-Graph-Analyzer/report'
DATA_DIR = os.path.join(BASE_DIR, '..', 'data')
OUTPUT_DIR = os.path.join(BASE_DIR, '..', 'output')

NETWORK_DATA_PATH = os.path.join(DATA_DIR, 'network_traffic_data.csv')
THREAT_ALERTS_PATH = os.path.join(OUTPUT_DIR, 'threat_alerts.csv')
DETECTION_RESULTS_PATH = os.path.join(OUTPUT_DIR, 'detection_results.csv')

print("Testing data loading and threat level generation...")
print()

# Test network data
network_data = load_network_data(NETWORK_DATA_PATH)
if network_data is not None:
    print(f"✓ Network data: {network_data.shape}")

# Test threat alerts
threat_alerts = load_threat_alerts(THREAT_ALERTS_PATH)
if threat_alerts is not None:
    print(f"✓ Threat alerts: {threat_alerts.shape}")

# Test detection results
detection_results = load_detection_results(DETECTION_RESULTS_PATH)
if detection_results is not None:
    print(f"✓ Detection results: {detection_results.shape}")
    print(f"  Columns: {list(detection_results.columns)}")

print()
print("Testing threat level generation from threat_score...")
print()

# Test threat score preparation
print("Test 1: prepare_threat_score_top_ips")
try:
    top_ips = prepare_threat_score_top_ips(detection_results, top_n=5)
    if top_ips is not None:
        print(f"✓ Top IPs created: {top_ips.shape}")
        print(f"  Columns: {list(top_ips.columns)}")
        print(top_ips)
    else:
        print("✗ Failed to create top IPs")
except Exception as e:
    print(f"✗ Error: {e}")

print()
print("Test 2: prepare_port_scanning_indicators")
try:
    port_scan = prepare_port_scanning_indicators(detection_results, top_n=5)
    if port_scan is not None:
        print(f"✓ Port scan indicators created: {port_scan.shape}")
        print(f"  Columns: {list(port_scan.columns)}")
        print(port_scan)
    else:
        print("✗ Failed to create port scan data")
except Exception as e:
    print(f"✗ Error: {e}")

print()
print("Test 3: prepare_traffic_metrics_scatter")
try:
    scatter_data = prepare_traffic_metrics_scatter(detection_results)
    if scatter_data is not None:
        print(f"✓ Scatter data created")
        print(f"  Has 'threat_level': {'threat_level' in scatter_data}")
        print(f"  Threat levels: {set(scatter_data['threat_level'])}")
    else:
        print("✗ Failed to create scatter data")
except Exception as e:
    print(f"✗ Error: {e}")

print()
print("All tests completed!")
