#!/usr/bin/env python
"""
Simple wrapper script to run the DINDGA report generation
Can be executed from any directory
"""

import subprocess
import sys
import os

def main():
    """Run the report generation"""
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Change to report directory
    os.chdir(script_dir)
    
    print("=" * 80)
    print("DINDGA Report Generator - Starting")
    print("=" * 80)
    print(f"Working directory: {os.getcwd()}")
    print()
    
    # Run the main generator
    try:
        import generate_report_plots
        generate_report_plots.main()
        print("\n✓ Report generation completed successfully!")
        return 0
    except Exception as e:
        print(f"\n✗ Error during report generation: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
