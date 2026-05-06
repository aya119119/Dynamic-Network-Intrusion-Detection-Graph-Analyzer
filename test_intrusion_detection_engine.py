"""
Short test runner for the new Phase 4 intrusion detection engine.
"""

from intrusion_detection_engine import run_intrusion_detection


if __name__ == "__main__":
    print("Running intrusion detection engine test...\n")
    results, alerts = run_intrusion_detection()

    print("\n=== Summary ===")
    print(f"Total IPs scored: {len(results)}")
    print(f"Total alerts generated: {len(alerts)}")

    if not alerts.empty:
        print("\nTop alerts:")
        print(alerts.head(10).to_string(index=False))
    else:
        print("No alerts generated.")
