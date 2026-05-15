# DINDGA Report Generation - Quick Start Guide

## Overview

This guide will help you generate professional plots and a complete LaTeX report for your DINDGA project.

## What You Get

### Automated Visualizations (9 plots)

1. **Label Distribution** - Traffic classification overview
2. **Degree Distribution** - Network connectivity analysis
3. **Top Threat IPs** - Ranked threat assessment
4. **Threat Level Distribution** - Alert severity breakdown
5. **Traffic Over Time** - Temporal analysis
6. **Anomaly Scores** - Statistical anomaly distribution
7. **Port Scanning Indicators** - Port diversity analysis
8. **Traffic Metrics Scatter** - Multi-dimensional patterns
9. **Spike Detection** - Time-window anomaly frequency

### Summary Statistics
- CSV file with key metrics
- Printed console output

### LaTeX Report Template
- Professional academic structure
- All 9 plots embedded with captions
- Methodology and analysis sections
- Customizable for your findings

## Installation

### Prerequisites

```bash
# Ensure you're in your project directory
cd Dynamic-Network-Intrusion-Detection-Graph-Analyzer

# Install dependencies (if not already done)
pip install -r requirements.txt
```

Key packages needed:
- pandas
- numpy
- matplotlib
- seaborn
- scikit-learn
- scipy

### Verify Setup

```bash
cd report
python -c "import report_analysis; print('✓ Setup OK')"
```

## Running the Report Generator

### Method 1: Direct Python

```bash
cd report
python generate_report_plots.py
```

### Method 2: Using the Runner Script

```bash
cd report
python run_report.py
```

### Method 3: From Any Directory

```bash
python /path/to/report/generate_report_plots.py
```

## Output Structure

After running, you'll have:

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
│   ├── 09_spike_detection_summary.png
│   └── .gitkeep
├── summary_statistics.csv
├── generate_report_plots.py
├── report_analysis.py
├── report_structure.tex
├── run_report.py
├── README.md
└── USAGE.md (this file)
```

## Creating Your Report

### Option A: Using Overleaf (Recommended for University)

1. **Create Project**
   - Go to [Overleaf.com](https://www.overleaf.com)
   - Create new project → "Upload"

2. **Upload LaTeX File**
   - Upload `report_structure.tex` as main file

3. **Upload Plots**
   - Create folder `plots` in Overleaf
   - Upload all PNG files from `report/plots/`

4. **Compile**
   - Click "Recompile"
   - Download PDF

5. **Edit**
   - Replace `[INSERT ...]` placeholders
   - Add your analysis and observations
   - Update references

### Option B: Local LaTeX Compilation

1. **Setup LaTeX**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install texlive-latex-full
   
   # macOS
   brew install basictex
   
   # Windows
   # Download from http://www.tug.org/texlive/acquire-netinstall.html
   ```

2. **Navigate to Report Folder**
   ```bash
   cd report
   ```

3. **Compile PDF**
   ```bash
   pdflatex report_structure.tex
   ```

4. **View Result**
   ```bash
   # Linux
   xdg-open report_structure.pdf
   
   # macOS
   open report_structure.pdf
   
   # Windows
   start report_structure.pdf
   ```

## Customizing Your Report

### Edit in LaTeX

Open `report_structure.tex` and:

1. **Replace Placeholders**
   ```latex
   % Find and replace all [INSERT ...] sections with your findings
   ```

2. **Update Title Section**
   ```latex
   \title{Your Full Title}
   \author{Your Name}
   \date{\today}
   ```

3. **Add Your Analysis**
   - Write observations for each plot
   - Add security recommendations
   - Include your conclusions

4. **Update References**
   - Add citations in Appendix

### Modify Plot Appearance

Edit `generate_report_plots.py`:

**Change Colors:**
```python
THREAT_COLORS = {
    'High': '#your_color',
    'Medium': '#your_color',
    'Low': '#your_color',
    'Normal': '#your_color',
    'Attack': '#your_color'
}
```

**Change Figure Size:**
```python
# In each plot function, modify figsize
fig, ax = plt.subplots(figsize=(new_width, new_height))
```

**Change DPI (Resolution):**
```python
DPI = 300  # Change to desired DPI
```

**Change Style:**
```python
plt.style.use('seaborn-v0_8-darkgrid')  # Try other styles
```

## Understanding the Plots

### Plot 1: Label Distribution

**What it shows:** Balance of normal vs attack traffic

**How to interpret:**
- High normal percentage → Good baseline
- High attack percentage → Dataset focuses on threats
- Use for dataset bias discussion

**In your report:** "As shown in Figure 1, [X]% of traffic was classified as attack traffic..."

### Plot 2: Degree Distribution

**What it shows:** How many connections each IP has

**How to interpret:**
- Right-skewed → Few highly connected IPs (suspicious servers?)
- Normal distribution → Typical network behavior
- Outliers → Important network nodes

**In your report:** "The degree distribution reveals that most IPs have [X] connections, with outliers reaching [Y]..."

### Plot 3: Top Threat IPs

**What it shows:** Most suspicious IPs ranked by threat score

**How to interpret:**
- Red IPs → Immediate security concern
- High scores → Multiple suspicious indicators
- Compare threat level with threat score

**In your report:** "The top threat IP [X.X.X.X] with score [Y] shows signs of [specific behavior]..."

### Plot 4: Threat Level Distribution

**What it shows:** How many High/Medium/Low threats detected

**How to interpret:**
- Many high threats → Network is under attack
- Few high threats → Good detection specificity
- Distribution shape indicates alert quality

**In your report:** "Of the [N] alerts, [X]% were classified as high-threat..."

### Plot 5: Traffic Over Time

**What it shows:** Traffic volume patterns and anomalies

**How to interpret:**
- Peaks → Busy periods or attacks
- Sudden drops → Potential network issues
- Correlation with threats → Targeted attacks

**In your report:** "Traffic volume peaks at time windows [X-Y], correlating with [N] threat alerts..."

### Plot 6: Anomaly Scores

**What it shows:** Statistical distribution of anomaly metrics

**How to interpret:**
- Outliers (box plot) → Anomalous IPs
- KDE curve shape → Patterns in data
- Mean/Std markers → Baseline behavior

**In your report:** "Anomaly scores range from [X] to [Y], with [N] significant outliers..."

### Plot 7: Port Scanning Indicators

**What it shows:** IPs accessing many different ports (scanning behavior)

**How to interpret:**
- High bars → Strong port scanning signals
- Red/Orange bars → Confirmed threats
- Blue bars → Monitor but lower priority

**In your report:** "IP [X.X.X.X] accessed [N] unique ports, indicating possible port scanning..."

### Plot 8: Traffic Metrics Scatter

**What it shows:** Packets/sec vs Bytes/sec with threat coloring

**How to interpret:**
- Upper right → High rate traffic
- Red dots → High threat with high rate
- Clustering patterns → Similar attack signatures

**In your report:** "High-threat IPs cluster in the upper range of the scatter plot, showing elevated traffic rates..."

### Plot 9: Spike Detection

**What it shows:** When anomalous spikes occur

**How to interpret:**
- High bars → Periods of high anomaly
- Average line → Baseline activity
- Time windows → When to focus investigation
