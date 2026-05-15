"""
DINDGA Report Plot Generator
Generates professional visualizations for network intrusion detection analysis report

Usage:
    python generate_report_plots.py
"""

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from scipy import stats

# Import helper functions
from report_analysis import (
    load_network_data, load_threat_alerts, load_detection_results,
    prepare_label_distribution, prepare_ip_degree_distribution,
    prepare_threat_score_top_ips, prepare_threat_level_distribution,
    prepare_anomaly_scores, prepare_port_scanning_indicators,
    prepare_traffic_metrics_scatter, prepare_summary_statistics,
    create_plots_directory, save_plot, create_summary_table, print_summary_table
)


# ============================================================================
# CONFIGURATION
# ============================================================================

# Set paths (relative to this script)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, '..', 'data')
OUTPUT_DIR = os.path.join(BASE_DIR, '..', 'output')

# Data file paths
NETWORK_DATA_PATH = os.path.join(DATA_DIR, 'network_traffic_data.csv')
THREAT_ALERTS_PATH = os.path.join(OUTPUT_DIR, 'threat_alerts.csv')
DETECTION_RESULTS_PATH = os.path.join(OUTPUT_DIR, 'detection_results.csv')

# Try alternative path for enhanced data
ENHANCED_DATA_PATH = os.path.join(BASE_DIR, '..', 'dindga_fixed_data_with_time.csv')

# DPI for saved images
DPI = 300

# ============================================================================
# MATPLOTLIB SETUP
# ============================================================================

# Set professional style
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

# Define color palettes
THREAT_COLORS = {
    'High': '#d62728',      # Red
    'Medium': '#ff7f0e',    # Orange
    'Low': '#2ca02c',       # Green
    'Normal': '#1f77b4',    # Blue
    'Attack': '#d62728'     # Red
}


# ============================================================================
# PLOTTING FUNCTIONS
# ============================================================================

def plot_label_distribution(network_data, plots_dir):
    """
    Plot 1: Label Distribution (Normal vs Attack) - Pie + Bar chart
    """
    print("\n[1/9] Generating Label Distribution plot...")
    
    if network_data is None or 'Label' not in network_data.columns:
        print("  ✗ Label column not found in network data")
        return
    
    label_counts = network_data['Label'].value_counts()
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle('Label Distribution: Normal vs Attack Traffic', fontsize=16, fontweight='bold', y=1.00)
    
    # Pie chart
    colors_pie = [THREAT_COLORS.get(label, '#1f77b4') for label in label_counts.index]
    axes[0].pie(label_counts.values, labels=label_counts.index, autopct='%1.1f%%',
                colors=colors_pie, startangle=90, textprops={'fontsize': 11, 'weight': 'bold'})
    axes[0].set_title('Proportion', fontsize=12, fontweight='bold', pad=10)
    
    # Bar chart
    axes[1].bar(label_counts.index, label_counts.values, color=colors_pie, edgecolor='black', linewidth=1.5)
    axes[1].set_title('Count', fontsize=12, fontweight='bold', pad=10)
    axes[1].set_ylabel('Number of Records', fontsize=11)
    axes[1].set_xlabel('Label', fontsize=11)
    axes[1].grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for i, v in enumerate(label_counts.values):
        axes[1].text(i, v + 100, str(v), ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    save_plot(fig, '01_label_distribution.png', plots_dir, DPI)
    plt.close()


def plot_degree_distribution(detection_results, plots_dir):
    """
    Plot 2: Degree Distribution of all IPs (Histogram)
    """
    print("[2/9] Generating IP Degree Distribution plot...")
    
    if detection_results is None or 'degree' not in detection_results.columns:
        print("  ✗ Degree column not found in detection results")
        return
    
    degrees = detection_results['degree'].values
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Histogram with KDE
    n, bins, patches = ax.hist(degrees, bins=20, color='#1f77b4', alpha=0.7, edgecolor='black', linewidth=1.2)
    
    # Color gradient for bars
    cm = plt.cm.Blues
    for i, patch in enumerate(patches):
        patch.set_facecolor(cm(0.3 + 0.7 * i / len(patches)))
    
    # Add statistics
    mean_degree = np.mean(degrees)
    std_degree = np.std(degrees)
    
    ax.axvline(mean_degree, color='red', linestyle='--', linewidth=2, label=f'Mean: {mean_degree:.2f}')
    ax.axvline(mean_degree - std_degree, color='orange', linestyle=':', linewidth=2, label=f'±1 Std Dev: {std_degree:.2f}')
    ax.axvline(mean_degree + std_degree, color='orange', linestyle=':', linewidth=2)
    
    ax.set_xlabel('Degree (Number of Connections)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Frequency', fontsize=12, fontweight='bold')
    ax.set_title('Distribution of IP Degrees in Network', fontsize=14, fontweight='bold', pad=15)
    ax.legend(fontsize=11, loc='upper right')
    ax.grid(axis='y', alpha=0.3)
    
    # Add statistics box
    stats_text = f'Count: {len(degrees)}\nMin: {np.min(degrees)}\nMax: {np.max(degrees)}\nMedian: {np.median(degrees):.1f}'
    ax.text(0.02, 0.98, stats_text, transform=ax.transAxes, fontsize=10,
            verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    plt.tight_layout()
    save_plot(fig, '02_degree_distribution.png', plots_dir, DPI)
    plt.close()


def plot_top_threat_ips(detection_results, plots_dir, top_n=15):
    """
    Plot 3: Top 15 IPs by Threat Score (Horizontal Bar Chart)
    """
    print("[3/9] Generating Top Threat IPs plot...")
    
    top_ips = prepare_threat_score_top_ips(detection_results, top_n)
    
    if top_ips is None:
        print("  ✗ Could not prepare threat score data")
        return
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Create color map based on threat level
    colors = [THREAT_COLORS.get(level, '#1f77b4') for level in top_ips['threat_level']]
    
    # Horizontal bar chart
    bars = ax.barh(range(len(top_ips)), top_ips['threat_score'].values, color=colors, edgecolor='black', linewidth=1.2)
    
    # Customize
    ax.set_yticks(range(len(top_ips)))
    ax.set_yticklabels(top_ips['ip'].values, fontsize=10)
    ax.set_xlabel('Threat Score', fontsize=12, fontweight='bold')
    ax.set_title(f'Top {top_n} IPs by Threat Score', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlim(0, 1.0)
    ax.grid(axis='x', alpha=0.3)
    
    # Add value labels
    for i, (bar, score) in enumerate(zip(bars, top_ips['threat_score'].values)):
        ax.text(score + 0.02, i, f'{score:.3f}', va='center', fontweight='bold', fontsize=9)
    
    # Add legend
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=THREAT_COLORS[level], edgecolor='black', label=level)
                       for level in ['High', 'Medium', 'Low']]
    ax.legend(handles=legend_elements, loc='lower right', fontsize=10)
    
    plt.tight_layout()
    save_plot(fig, '03_top_threat_ips.png', plots_dir, DPI)
    plt.close()


def plot_threat_level_distribution(threat_alerts, plots_dir):
    """
    Plot 4: Threat Level Distribution (Pie Chart)
    """
    print("[4/9] Generating Threat Level Distribution plot...")
    
    if threat_alerts is None or 'threat_level' not in threat_alerts.columns:
        print("  ✗ Threat level column not found")
        return
    
    threat_dist = threat_alerts['threat_level'].value_counts()
    
    fig, ax = plt.subplots(figsize=(10, 7))
    
    # Create colors in order
    threat_order = ['High', 'Medium', 'Low']
    threat_dist = threat_dist.reindex([t for t in threat_order if t in threat_dist.index])
    colors = [THREAT_COLORS[level] for level in threat_dist.index]
    
    # Pie chart with enhanced styling
    wedges, texts, autotexts = ax.pie(
        threat_dist.values,
        labels=threat_dist.index,
        autopct='%1.1f%%',
        colors=colors,
        startangle=90,
        explode=[0.05 if i == 0 else 0 for i in range(len(threat_dist))],
        textprops={'fontsize': 12, 'weight': 'bold'},
        shadow=True
    )
    
    # Enhance autotext
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontsize(11)
        autotext.set_weight('bold')
    
    ax.set_title('Distribution of Threat Alert Levels', fontsize=14, fontweight='bold', pad=15)
    
    # Add count annotations
    total = threat_dist.sum()
    counts_text = '\n'.join([f'{level}: {count} ({count/total*100:.1f}%)' 
                             for level, count in threat_dist.items()])
    ax.text(1.3, 0.5, counts_text, transform=ax.transAxes, fontsize=11,
            verticalalignment='center', bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.8))
    
    plt.tight_layout()
    save_plot(fig, '04_threat_level_distribution.png', plots_dir, DPI)
    plt.close()


def plot_traffic_volume_over_time(network_data, plots_dir):
    """
    Plot 5: Traffic Volume Over Time (Line Chart)
    Note: Creates synthetic time-series if timestamp not available
    """
    print("[5/9] Generating Traffic Volume Over Time plot...")
    
    if network_data is None:
        print("  ✗ Network data not available")
        return
    
    fig, axes = plt.subplots(2, 1, figsize=(14, 10))
    fig.suptitle('Network Traffic Volume Analysis Over Time', fontsize=14, fontweight='bold', y=0.995)
    
    # Create time window aggregation
    if 'Timestamp' in network_data.columns:
        network_data['Timestamp'] = pd.to_datetime(network_data['Timestamp'])
        time_data = network_data.set_index('Timestamp').resample('1T').agg({
            'ByteCount': 'sum',
            'PacketCount': 'sum'
        })
    else:
        # Create synthetic time windows
        n_windows = min(50, len(network_data) // 10)
        window_size = len(network_data) // n_windows
        
        packet_by_window = []
        byte_by_window = []
        
        for i in range(n_windows):
            start = i * window_size
            end = (i + 1) * window_size if i < n_windows - 1 else len(network_data)
            packet_by_window.append(network_data.iloc[start:end]['PacketCount'].sum())
            byte_by_window.append(network_data.iloc[start:end]['ByteCount'].sum())
        
        time_windows = np.arange(len(packet_by_window))
        time_data = pd.DataFrame({
            'PacketCount': packet_by_window,
            'ByteCount': byte_by_window
        }, index=time_windows)
    
    # Plot 1: Packet Count over time
    axes[0].plot(time_data.index, time_data['PacketCount'], color='#1f77b4', linewidth=2, marker='o', markersize=4)
    axes[0].fill_between(time_data.index, time_data['PacketCount'], alpha=0.3, color='#1f77b4')
    axes[0].set_ylabel('Total Packets', fontsize=11, fontweight='bold')
    axes[0].set_title('Packet Count Over Time', fontsize=12, fontweight='bold')
    axes[0].grid(True, alpha=0.3)
    
    # Plot 2: Byte Count over time
    axes[1].plot(time_data.index, time_data['ByteCount'], color='#ff7f0e', linewidth=2, marker='s', markersize=4)
    axes[1].fill_between(time_data.index, time_data['ByteCount'], alpha=0.3, color='#ff7f0e')
    axes[1].set_ylabel('Total Bytes', fontsize=11, fontweight='bold')
    axes[1].set_xlabel('Time Window', fontsize=11, fontweight='bold')
    axes[1].set_title('Byte Count Over Time', fontsize=12, fontweight='bold')
    axes[1].grid(True, alpha=0.3)
    
    plt.tight_layout()
    save_plot(fig, '05_traffic_volume_over_time.png', plots_dir, DPI)
    plt.close()


def plot_anomaly_score_distribution(detection_results, plots_dir):
    """
    Plot 6: Anomaly Score Distribution (Histogram + KDE)
    """
    print("[6/9] Generating Anomaly Score Distribution plot...")
    
    if detection_results is None or 'anomaly_score' not in detection_results.columns:
        print("  ✗ Anomaly score column not found")
        return
    
    anomaly_scores = detection_results['anomaly_score'].values
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle('Anomaly Score Distribution Analysis', fontsize=14, fontweight='bold', y=1.00)
    
    # Plot 1: Histogram with KDE
    axes[0].hist(anomaly_scores, bins=30, color='#2ca02c', alpha=0.7, edgecolor='black', linewidth=1.2, density=True)
    
    # Add KDE
    from scipy.stats import gaussian_kde
    kde = gaussian_kde(anomaly_scores)
    x_range = np.linspace(anomaly_scores.min(), anomaly_scores.max(), 100)
    axes[0].plot(x_range, kde(x_range), color='red', linewidth=2, label='KDE')
    
    axes[0].set_xlabel('Anomaly Score', fontsize=11, fontweight='bold')
    axes[0].set_ylabel('Density', fontsize=11, fontweight='bold')
    axes[0].set_title('Distribution with KDE', fontsize=12, fontweight='bold')
    axes[0].legend(fontsize=10)
    axes[0].grid(axis='y', alpha=0.3)
    
    # Plot 2: Box plot and statistics
    box_data = [anomaly_scores]
    bp = axes[1].boxplot(box_data, vert=True, patch_artist=True, labels=['Anomaly Score'])
    
    for patch in bp['boxes']:
        patch.set_facecolor('#2ca02c')
        patch.set_alpha(0.7)
    
    axes[1].set_ylabel('Anomaly Score', fontsize=11, fontweight='bold')
    axes[1].set_title('Box Plot Analysis', fontsize=12, fontweight='bold')
    axes[1].grid(axis='y', alpha=0.3)
    
    # Add statistics
    stats_text = f'Mean: {np.mean(anomaly_scores):.4f}\nStd: {np.std(anomaly_scores):.4f}\nMin: {np.min(anomaly_scores):.4f}\nMax: {np.max(anomaly_scores):.4f}\nMedian: {np.median(anomaly_scores):.4f}'
    axes[1].text(0.5, 0.02, stats_text, transform=axes[1].transAxes, fontsize=10,
                verticalalignment='bottom', horizontalalignment='center',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    plt.tight_layout()
    save_plot(fig, '06_anomaly_score_distribution.png', plots_dir, DPI)
    plt.close()


def plot_port_scanning_indicators(detection_results, plots_dir, top_n=15):
    """
    Plot 7: Top IPs by Unique Destination Ports (Port Scanning Indicator)
    """
    print("[7/9] Generating Port Scanning Indicators plot...")
    
    port_scan = prepare_port_scanning_indicators(detection_results, top_n)
    
    if port_scan is None:
        print("  ✗ Could not prepare port scanning data")
        return
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Create color map
    colors = [THREAT_COLORS.get(level, '#1f77b4') for level in port_scan['threat_level']]
    
    # Horizontal bar chart
    bars = ax.barh(range(len(port_scan)), port_scan['unique_dst_ports'].values, color=colors, edgecolor='black', linewidth=1.2)
    
    ax.set_yticks(range(len(port_scan)))
    ax.set_yticklabels(port_scan['ip'].values, fontsize=10)
    ax.set_xlabel('Number of Unique Destination Ports', fontsize=12, fontweight='bold')
    ax.set_title(f'Top {top_n} IPs by Unique Destination Ports (Port Scanning Indicators)', fontsize=14, fontweight='bold', pad=15)
    ax.grid(axis='x', alpha=0.3)
    
    # Add value labels
    for i, (bar, count) in enumerate(zip(bars, port_scan['unique_dst_ports'].values)):
        ax.text(count + 0.2, i, str(int(count)), va='center', fontweight='bold', fontsize=9)
    
    # Add legend
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=THREAT_COLORS[level], edgecolor='black', label=level)
                       for level in ['High', 'Medium', 'Low']]
    ax.legend(handles=legend_elements, loc='lower right', fontsize=10)
    
    plt.tight_layout()
    save_plot(fig, '07_port_scanning_indicators.png', plots_dir, DPI)
    plt.close()


def plot_traffic_metrics_scatter(detection_results, plots_dir):
    """
    Plot 8: Packets per Second vs Bytes per Second scatter plot (colored by threat level)
    """
    print("[8/9] Generating Traffic Metrics Scatter Plot...")
    
    scatter_data = prepare_traffic_metrics_scatter(detection_results)
    
    if scatter_data is None:
        print("  ✗ Could not prepare scatter plot data")
        return
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Create scatter plot with color mapping
    threat_levels = np.array(scatter_data['threat_level'])
    unique_levels = np.unique(threat_levels)
    
    for level in unique_levels:
        mask = threat_levels == level
        ax.scatter(scatter_data['pps'][mask], scatter_data['bps'][mask], 
                  label=level, s=100, alpha=0.7, color=THREAT_COLORS.get(level, '#1f77b4'),
                  edgecolor='black', linewidth=1)
    
    # Add log scale for better visualization
    ax.set_xlabel('Packets per Second (log scale)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Bytes per Second (log scale)', fontsize=12, fontweight='bold')
    ax.set_title('Network Traffic Metrics: Packets/sec vs Bytes/sec', fontsize=14, fontweight='bold', pad=15)
    
    # Use log scale with offset to handle potential zero values
    ax.set_xscale('symlog')
    ax.set_yscale('symlog')
    
    ax.legend(title='Threat Level', fontsize=11, title_fontsize=12, loc='best')
    ax.grid(True, alpha=0.3, which='both')
    
    plt.tight_layout()
    save_plot(fig, '08_traffic_metrics_scatter.png', plots_dir, DPI)
    plt.close()


def plot_spike_detection_summary(detection_results, plots_dir):
    """
    Plot 9: Number of Spikes Detected per Time Window
    Note: Creates synthetic spike detection data based on anomaly scores
    """
    print("[9/9] Generating Spike Detection Summary plot...")
    
    if detection_results is None or 'anomaly_score' not in detection_results.columns:
        print("  ✗ Could not prepare spike detection data")
        return
    
    # Create synthetic time windows based on anomaly scores
    n_windows = 12  # e.g., 12 time windows
    window_size = len(detection_results) // n_windows
    
    spike_counts = []
    window_labels = []
    
    anomaly_threshold = np.percentile(detection_results['anomaly_score'], 25)  # Lower quartile indicates anomaly
    
    for i in range(n_windows):
        start = i * window_size
        end = (i + 1) * window_size if i < n_windows - 1 else len(detection_results)
        window_anomalies = detection_results.iloc[start:end]
        spike_count = len(window_anomalies[window_anomalies['anomaly_score'] < anomaly_threshold])
        spike_counts.append(spike_count)
        window_labels.append(f'W{i+1}')
    
    fig, ax = plt.subplots(figsize=(13, 6))
    
    # Create bar chart with gradient colors
    colors_gradient = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(spike_counts)))
    bars = ax.bar(window_labels, spike_counts, color=colors_gradient, edgecolor='black', linewidth=1.5)
    
    # Customize
    ax.set_ylabel('Number of Spike Events', fontsize=12, fontweight='bold')
    ax.set_xlabel('Time Window', fontsize=12, fontweight='bold')
    ax.set_title('Number of Anomalous Spikes Detected per Time Window', fontsize=14, fontweight='bold', pad=15)
    ax.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for bar, count in zip(bars, spike_counts):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
               f'{int(count)}', ha='center', va='bottom', fontweight='bold', fontsize=10)
    
    # Add average line
    avg_spikes = np.mean(spike_counts)
    ax.axhline(y=avg_spikes, color='red', linestyle='--', linewidth=2, label=f'Average: {avg_spikes:.1f}')
    ax.legend(fontsize=11, loc='upper right')
    
    plt.tight_layout()
    save_plot(fig, '09_spike_detection_summary.png', plots_dir, DPI)
    plt.close()


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """
    Main execution function
    """
    print("\n" + "="*80)
    print("DINDGA REPORT PLOT GENERATOR")
    print("="*80)
    
    # Create plots directory
    plots_dir = create_plots_directory(BASE_DIR)
    
    # Load data
    print("\n[DATA LOADING]")
    network_data = load_network_data(NETWORK_DATA_PATH)
    threat_alerts = load_threat_alerts(THREAT_ALERTS_PATH)
    detection_results = load_detection_results(DETECTION_RESULTS_PATH)
    
    # Generate plots
    print("\n[PLOTTING]")
    plot_label_distribution(network_data, plots_dir)
    plot_degree_distribution(detection_results, plots_dir)
    plot_top_threat_ips(detection_results, plots_dir)
    plot_threat_level_distribution(threat_alerts, plots_dir)
    plot_traffic_volume_over_time(network_data, plots_dir)
    plot_anomaly_score_distribution(detection_results, plots_dir)
    plot_port_scanning_indicators(detection_results, plots_dir)
    plot_traffic_metrics_scatter(detection_results, plots_dir)
    plot_spike_detection_summary(detection_results, plots_dir)
    
    # Generate summary statistics
    print("\n[SUMMARY STATISTICS]")
    summary_stats = prepare_summary_statistics(network_data, detection_results, threat_alerts)
    df_summary = create_summary_table(summary_stats)
    print_summary_table(df_summary)
    
    # Save summary table
    summary_path = os.path.join(BASE_DIR, 'summary_statistics.csv')
    df_summary.to_csv(summary_path, index=False)
    print(f"✓ Summary table saved: summary_statistics.csv")
    
    print("\n" + "="*80)
    print("REPORT GENERATION COMPLETE!")
    print(f"All plots saved in: {plots_dir}")
    print("="*80 + "\n")


if __name__ == '__main__':
    main()
