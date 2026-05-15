# DINDGA Report Generation

This folder contains the automated report generation system for the **Dynamic Network Intrusion Detection Graph Analyzer (DINDGA)** project.

## Files Overview

### Main Scripts

- **`generate_report_plots.py`** - Main plotting and visualization script
  - Generates all 9 professional plots
  - Creates summary statistics
  - Automatically creates `plots/` subdirectory
  - Saves all outputs with high DPI (300)

- **`report_analysis.py`** - Helper functions and utilities
  - Data loading functions
  - Data preparation utilities
  - Statistical analysis helpers
  - Plot saving and formatting utilities

- **`report_structure.tex`** - LaTeX template for final report
  - Professional academic report structure
  - Sections for methodology, results, and analysis
  - Placeholders for all generated plots with \includegraphics
  - Ready to use in Overleaf

## Quick Start

### 1. Run Report Generation

```bash
python generate_report_plots.py
```

This will:
- Load data from `../data/` and `../output/`
- Generate 9 high-quality PNG plots
- Create `plots/` directory automatically
- Generate `summary_statistics.csv`
- Print summary statistics to console

### 2. Generated Outputs

After running the script, you'll have:

```
report/
├── plots/
│   ├── 01_label_distribution.png
│   ├── 02_degree_distribution.png
│   ├── 03_top_threat_ips.png
│   ├── 04_threat_level_distribution.png
│   ├── 05_traffic_volume_over_time.png
│   ├── 06_anomaly_score_distribution.png
│   ├── 07_port_scanning_indicators.png
│   ├── 08_traffic_metrics_scatter.png
│   └── 09_spike_detection_summary.png
├── summary_statistics.csv
├── generate_report_plots.py
├── report_analysis.py
├── report_structure.tex
└── README.md
```

### 3. Create LaTeX Report

Copy the plots to your Overleaf project:

1. Open `report_structure.tex` in Overleaf (or locally with pdflatex)
2. Ensure the `plots/` folder with all PNG files is in your LaTeX project
3. Build the PDF

Or use locally:

```bash
pdflatex report_structure.tex
```

## Generated Plots

### 1. Label Distribution (01_label_distribution.png)
- Pie chart showing traffic class proportions
- Bar chart showing absolute counts
- Helps understand dataset balance

### 2. IP Degree Distribution (02_degree_distribution.png)
- Histogram of node degrees in network graph
- Mean and standard deviation markers
- Statistical summary box
- Identifies highly connected IPs

### 3. Top Threat IPs (03_top_threat_ips.png)
- Top 15 IPs ranked by threat score
- Color-coded by threat level (High/Medium/Low)
- Horizontal bar chart for easy reading
- Threat scores displayed on bars

### 4. Threat Level Distribution (04_threat_level_distribution.png)
- Pie chart of threat alert distribution
- Separate count statistics box
- Shows severity breakdown
- Color-coded by threat level

### 5. Traffic Volume Over Time (05_traffic_volume_over_time.png)
- Packet count trend line
- Data volume (bytes) trend line
- Temporal anomaly identification
- Helps correlate attacks with time

### 6. Anomaly Score Distribution (06_anomaly_score_distribution.png)
- Histogram with kernel density estimation
- Box plot analysis
- Statistical summary (mean, std, min, max, median)
- Identifies outlier IPs

### 7. Port Scanning Indicators (07_port_scanning_indicators.png)
- Top 15 IPs by unique destination ports
- Color-coded by threat level
- Port count displayed on bars
- Identifies port scanners

### 8. Traffic Metrics Scatter (08_traffic_metrics_scatter.png)
- Packets/sec vs Bytes/sec scatter plot
- Logarithmic scales for better visualization
- Color-coded by threat level
- Different threat signatures visible

### 9. Spike Detection Summary (09_spike_detection_summary.png)
- Anomalous spikes per time window
- Gradient-colored bars
- Average spike count line
- Identifies high-activity periods

## Summary Statistics (summary_statistics.csv)

Contains:
- Network data metrics (record count, unique IPs, protocols)
- Detection results (analyzed IPs, degree stats, anomaly scores)
- Threat level breakdown (High/Medium/Low counts)

## Requirements

Ensure these Python packages are installed:

```bash
pip install pandas numpy matplotlib seaborn scikit-learn scipy
```

Or install from the main project requirements:

```bash
pip install -r ../requirements.txt
```

## Customization

### Modify Plot Appearance

Edit `generate_report_plots.py`:

- **Colors**: Change `THREAT_COLORS` dictionary (lines ~50-57)
- **Figure Size**: Modify `figsize` parameters in plot functions
- **DPI**: Change `DPI = 300` (line ~43)
- **Style**: Change `plt.style.use()` (line ~48)

### Adjust Data Paths

If your data is in different locations, modify these at the top of `generate_report_plots.py`:

```python
NETWORK_DATA_PATH = os.path.join(DATA_DIR, 'your_network_data.csv')
THREAT_ALERTS_PATH = os.path.join(OUTPUT_DIR, 'your_threat_alerts.csv')
DETECTION_RESULTS_PATH = os.path.join(OUTPUT_DIR, 'your_detection_results.csv')
```

### Add More Plots

1. Create a new function in `generate_report_plots.py` following the pattern
2. Add it to the `main()` function
3. Update this README

## LaTeX Report Usage

### Online (Overleaf)

1. Create new Overleaf project
2. Upload `report_structure.tex` as main file
3. Create `plots` folder in Overleaf
4. Upload all PNG files from `plots/`
5. Click Recompile

### Local Compilation

```bash
# Basic compilation
pdflatex report_structure.tex

# With references (if added)
pdflatex report_structure.tex
bibtex report_structure
pdflatex report_structure.tex
pdflatex report_structure.tex

# View result
open report_structure.pdf  # macOS
xdg-open report_structure.pdf  # Linux
start report_structure.pdf  # Windows
```

## Tips for Your Report

1. **Update Summary**: Replace `[INSERT ...]` placeholders in LaTeX with actual findings
2. **Add Observations**: Include your interpretations in each section
3. **Customize Sections**: Adapt the structure to match your project requirements
4. **Include References**: Add academic sources to the References appendix
5. **Review Figures**: Verify all plots are properly included before submission

## Data Format Requirements

### network_traffic_data.csv
Required columns: `Protocol`, `SourceIP`, `DestinationIP`, `SourcePort`, `DestinationPort`, `PacketCount`, `ByteCount`, `Label` (Optional: `Timestamp`)

### threat_alerts.csv
Required columns: `ip`, `threat_score`, `threat_level`, `reason`

### detection_results.csv
Required columns: `ip`, `degree`, `unique_dst_ports`, `anomaly_score`, `threat_level`, plus traffic metrics

## Troubleshooting

### Missing Data Files
- Verify data files exist in `../data/` and `../output/`
- Check CSV headers match expected format
- Run DINDGA detection engine first to generate `detection_results.csv`

### Plot Generation Errors
- Ensure all required libraries are installed
- Check that data is not corrupted
- Verify sufficient disk space for plots
- Try running with `python -v` for verbose output

### LaTeX Compilation Issues
- Ensure all PNG files are in the correct `plots/` directory
- Check file paths in LaTeX relative to `.tex` file location
- Verify PNG files are valid and not corrupted

## Project Structure

```
Dynamic-Network-Intrusion-Detection-Graph-Analyzer/
├── data/
│   └── network_traffic_data.csv
├── output/
│   ├── detection_results.csv
│   ├── threat_alerts.csv
│   └── ...
├── report/
│   ├── plots/
│   ├── generate_report_plots.py
│   ├── report_analysis.py
│   ├── report_structure.tex
│   └── summary_statistics.csv
└── ...
```

## Notes

- All plots are saved at 300 DPI for publication quality
- Color schemes are designed for printed reports
- Timestamps are automatically handled if present or synthesized
- The LaTeX template is fully compatible with Overleaf

## Support

For issues with:
- **Plot generation**: Check `generate_report_plots.py` comments
- **Data loading**: Verify CSV format with `report_analysis.py`
- **LaTeX compilation**: Refer to Overleaf or local LaTeX documentation

---

**Report Generated by**: DINDGA Report Generation System  
**Last Updated**: 2026  
**Version**: 1.0
