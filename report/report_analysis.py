"""
Helper functions for DINDGA Report Generation
Provides utilities for data loading, processing, and analysis
"""

import pandas as pd
import numpy as np
import os
from pathlib import Path


def load_network_data(data_path):
    """
    Load network traffic data from CSV file.
    
    Args:
        data_path (str): Path to the network traffic CSV file
        
    Returns:
        pd.DataFrame: Loaded network traffic data
    """
    try:
        df = pd.read_csv(data_path)
        print(f"✓ Loaded network data from {data_path}")
        print(f"  Shape: {df.shape[0]} rows, {df.shape[1]} columns")
        return df
    except FileNotFoundError:
        print(f"✗ Network data file not found: {data_path}")
        return None
    except Exception as e:
        print(f"✗ Error loading network data: {e}")
        return None


def load_threat_alerts(alert_path):
    """
    Load threat alerts from CSV file.
    
    Args:
        alert_path (str): Path to threat alerts CSV file
        
    Returns:
        pd.DataFrame: Loaded threat alerts data
    """
    try:
        df = pd.read_csv(alert_path)
        print(f"✓ Loaded threat alerts from {alert_path}")
        print(f"  Shape: {df.shape[0]} rows, {df.shape[1]} columns")
        return df
    except FileNotFoundError:
        print(f"✗ Threat alerts file not found: {alert_path}")
        return None
    except Exception as e:
        print(f"✗ Error loading threat alerts: {e}")
        return None


def load_detection_results(results_path):
    """
    Load detection results from CSV file.
    
    Args:
        results_path (str): Path to detection results CSV file
        
    Returns:
        pd.DataFrame: Loaded detection results
    """
    try:
        df = pd.read_csv(results_path)
        print(f"✓ Loaded detection results from {results_path}")
        print(f"  Shape: {df.shape[0]} rows, {df.shape[1]} columns")
        return df
    except FileNotFoundError:
        print(f"✗ Detection results file not found: {results_path}")
        return None
    except Exception as e:
        print(f"✗ Error loading detection results: {e}")
        return None


def prepare_label_distribution(network_data):
    """
    Prepare label distribution statistics.
    
    Args:
        network_data (pd.DataFrame): Network traffic data
        
    Returns:
        dict: Label distribution statistics
    """
    if network_data is None or 'Label' not in network_data.columns:
        return None
    
    label_counts = network_data['Label'].value_counts()
    label_dist = {
        'counts': label_counts.to_dict(),
        'percentages': (label_counts / len(network_data) * 100).to_dict(),
        'total': len(network_data)
    }
    return label_dist


def prepare_ip_degree_distribution(detection_results):
    """
    Prepare IP degree distribution from detection results.
    
    Args:
        detection_results (pd.DataFrame): Detection results with degree info
        
    Returns:
        dict: Degree statistics
    """
    if detection_results is None or 'degree' not in detection_results.columns:
        return None
    
    degrees = detection_results['degree'].values
    degree_stats = {
        'data': degrees,
        'mean': np.mean(degrees),
        'std': np.std(degrees),
        'min': np.min(degrees),
        'max': np.max(degrees)
    }
    return degree_stats


def prepare_threat_score_top_ips(detection_results, top_n=15):
    """
    Prepare top IPs by threat score.
    
    Args:
        detection_results (pd.DataFrame): Detection results
        top_n (int): Number of top IPs to return
        
    Returns:
        pd.DataFrame: Top IPs by threat score
    """
    if detection_results is None or 'threat_score' not in detection_results.columns:
        return None
    
    top_ips_data = detection_results.nlargest(top_n, 'threat_score')[['ip', 'threat_score']].copy()
    
    # Create threat_level based on threat_score thresholds
    def get_threat_level(score):
        if score >= 0.7:
            return 'High'
        elif score >= 0.4:
            return 'Medium'
        else:
            return 'Low'
    
    top_ips_data['threat_level'] = top_ips_data['threat_score'].apply(get_threat_level)
    return top_ips_data


def prepare_threat_level_distribution(threat_alerts):
    """
    Prepare threat level distribution from alerts.
    
    Args:
        threat_alerts (pd.DataFrame): Threat alerts data
        
    Returns:
        dict: Threat level distribution
    """
    if threat_alerts is None or 'threat_level' not in threat_alerts.columns:
        return None
    
    threat_dist = threat_alerts['threat_level'].value_counts()
    distribution = {
        'counts': threat_dist.to_dict(),
        'percentages': (threat_dist / len(threat_alerts) * 100).to_dict(),
        'total': len(threat_alerts)
    }
    return distribution


def prepare_anomaly_scores(detection_results):
    """
    Prepare anomaly score data.
    
    Args:
        detection_results (pd.DataFrame): Detection results
        
    Returns:
        np.ndarray: Anomaly scores
    """
    if detection_results is None or 'anomaly_score' not in detection_results.columns:
        return None
    
    return detection_results['anomaly_score'].values


def prepare_port_scanning_indicators(detection_results, top_n=15):
    """
    Prepare port scanning indicators (top IPs by unique destination ports).
    
    Args:
        detection_results (pd.DataFrame): Detection results
        top_n (int): Number of top IPs to return
        
    Returns:
        pd.DataFrame: Top IPs by unique destination ports
    """
    if detection_results is None or 'unique_dst_ports' not in detection_results.columns:
        return None
    
    port_scan = detection_results.nlargest(top_n, 'unique_dst_ports')[['ip', 'unique_dst_ports', 'threat_score']].copy()
    
    # Create threat_level based on threat_score thresholds
    def get_threat_level(score):
        if score >= 0.7:
            return 'High'
        elif score >= 0.4:
            return 'Medium'
        else:
            return 'Low'
    
    port_scan['threat_level'] = port_scan['threat_score'].apply(get_threat_level)
    return port_scan


def prepare_traffic_metrics_scatter(detection_results):
    """
    Prepare data for packets per second vs bytes per second scatter plot.
    
    Args:
        detection_results (pd.DataFrame): Detection results
        
    Returns:
        dict: Scatter plot data
    """
    if detection_results is None:
        return None
    
    required_cols = ['packets_per_second', 'bytes_per_second', 'threat_score', 'ip']
    if not all(col in detection_results.columns for col in required_cols):
        return None
    
    # Create threat_level based on threat_score thresholds
    def get_threat_level(score):
        if score >= 0.7:
            return 'High'
        elif score >= 0.4:
            return 'Medium'
        else:
            return 'Low'
    
    threat_levels = detection_results['threat_score'].apply(get_threat_level).values
    
    scatter_data = {
        'pps': detection_results['packets_per_second'].values,
        'bps': detection_results['bytes_per_second'].values,
        'threat_level': threat_levels,
        'ip': detection_results['ip'].values
    }
    return scatter_data


def prepare_summary_statistics(network_data, detection_results, threat_alerts):
    """
    Prepare comprehensive summary statistics.
    
    Args:
        network_data (pd.DataFrame): Network traffic data
        detection_results (pd.DataFrame): Detection results
        threat_alerts (pd.DataFrame): Threat alerts
        
    Returns:
        dict: Summary statistics
    """
    summary = {
        'Network Data': {
            'Total Records': len(network_data) if network_data is not None else 0,
            'Protocols': network_data['Protocol'].nunique() if network_data is not None and 'Protocol' in network_data.columns else 0,
            'Unique Source IPs': network_data['SourceIP'].nunique() if network_data is not None and 'SourceIP' in network_data.columns else 0,
            'Unique Destination IPs': network_data['DestinationIP'].nunique() if network_data is not None and 'DestinationIP' in network_data.columns else 0,
        },
        'Detection Results': {
            'Total IPs Analyzed': len(detection_results) if detection_results is not None else 0,
            'Average Degree': detection_results['degree'].mean() if detection_results is not None and 'degree' in detection_results.columns else 0,
            'Average Anomaly Score': detection_results['anomaly_score'].mean() if detection_results is not None and 'anomaly_score' in detection_results.columns else 0,
            'High Threat IPs': len(detection_results[detection_results['threat_score'] >= 0.7]) if detection_results is not None and 'threat_score' in detection_results.columns else 0,
            'Medium Threat IPs': len(detection_results[(detection_results['threat_score'] >= 0.4) & (detection_results['threat_score'] < 0.7)]) if detection_results is not None and 'threat_score' in detection_results.columns else 0,
            'Low Threat IPs': len(detection_results[detection_results['threat_score'] < 0.4]) if detection_results is not None and 'threat_score' in detection_results.columns else 0,
        },
        'Threat Alerts': {
            'Total Alerts': len(threat_alerts) if threat_alerts is not None else 0,
            'High Alerts': len(threat_alerts[threat_alerts['threat_level'] == 'High']) if threat_alerts is not None and 'threat_level' in threat_alerts.columns else 0,
            'Medium Alerts': len(threat_alerts[threat_alerts['threat_level'] == 'Medium']) if threat_alerts is not None and 'threat_level' in threat_alerts.columns else 0,
            'Low Alerts': len(threat_alerts[threat_alerts['threat_level'] == 'Low']) if threat_alerts is not None and 'threat_level' in threat_alerts.columns else 0,
        }
    }
    return summary


def create_plots_directory(base_path):
    """
    Create plots directory if it doesn't exist.
    
    Args:
        base_path (str): Base path where to create plots folder
        
    Returns:
        str: Path to plots folder
    """
    plots_dir = os.path.join(base_path, 'plots')
    Path(plots_dir).mkdir(parents=True, exist_ok=True)
    print(f"✓ Plots directory ready: {plots_dir}")
    return plots_dir


def save_plot(fig, filename, plots_dir, dpi=300):
    """
    Save a matplotlib figure to file.
    
    Args:
        fig: Matplotlib figure object
        filename (str): Name of the file to save
        plots_dir (str): Directory to save to
        dpi (int): DPI for the saved image
    """
    filepath = os.path.join(plots_dir, filename)
    fig.savefig(filepath, dpi=dpi, bbox_inches='tight', facecolor='white')
    print(f"  ✓ Saved: {filename}")


def create_summary_table(summary_stats):
    """
    Create a formatted summary statistics table.
    
    Args:
        summary_stats (dict): Summary statistics dictionary
        
    Returns:
        pd.DataFrame: Formatted summary table
    """
    data = []
    for category, metrics in summary_stats.items():
        for metric, value in metrics.items():
            data.append({
                'Category': category,
                'Metric': metric,
                'Value': value
            })
    
    return pd.DataFrame(data)


def print_summary_table(df_summary):
    """
    Print a formatted summary table.
    
    Args:
        df_summary (pd.DataFrame): Summary table data frame
    """
    print("\n" + "="*80)
    print("REPORT SUMMARY STATISTICS")
    print("="*80)
    
    for category in df_summary['Category'].unique():
        print(f"\n{category}:")
        print("-" * 60)
        category_data = df_summary[df_summary['Category'] == category]
        for _, row in category_data.iterrows():
            print(f"  {row['Metric']:<40} {row['Value']:>15}")
    
    print("\n" + "="*80 + "\n")
