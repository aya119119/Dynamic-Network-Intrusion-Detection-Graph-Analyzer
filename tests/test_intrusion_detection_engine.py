"""Short test runner for the new Phase 4 intrusion detection engine."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.intrusion_detection_engine import run_intrusion_detection


if __name__ == "__main__":
    print("Running intrusion detection engine test...\n")
    results, alerts = run_intrusion_detection(
        csv_path="data/network_traffic_data.csv",
        output_path="output/threat_alerts.csv"
    )

    print("\n=== Summary ===")
    print(f"Total IPs scored: {len(results)}")
    print(f"Total alerts generated: {len(alerts)}")

    if not alerts.empty:
        print("\nTop alerts:")
        print(alerts.head(10).to_string(index=False))
    else:
        print("No alerts generated.")
