import pandas as pd
import numpy as np
from datetime import timedelta

# Load your current data
csv_file = "network_traffic_data.csv"
df = pd.read_csv(csv_file)
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# === Create Spikes (Attacks) ===
np.random.seed(42)

# Get IPs with the most traffic to use for spikes, to ensure we have enough data to burst
top_ips = df['SourceIP'].value_counts().head(5).index.tolist()
spike_ips = np.random.choice(top_ips, 3, replace=False)
print(f"Creating artificial spikes for IPs: {spike_ips}")

for ip in spike_ips:
    # Find rows belonging to this IP
    mask = df['SourceIP'] == ip
    if mask.sum() > 0:
        # Make 60% of their connections happen in a very short time (burst)
        burst_indices = np.random.choice(df[mask].index, size=int(mask.sum()*0.6), replace=False)
        
        # Base time from the first of these connections
        base_time = df.loc[burst_indices[0], 'Timestamp']
        
        # Add random seconds between 0 and 120 to create a tight burst
        random_offsets = pd.to_timedelta(np.random.randint(0, 120, size=len(burst_indices)), unit='s')
        df.loc[burst_indices, 'Timestamp'] = base_time + random_offsets

# Sort again by time
df = df.sort_values('Timestamp').reset_index(drop=True)

# Save as new fixed version
df.to_csv(csv_file, index=False)
print(f"✅ Spikes added! Saved new dataset to {csv_file}")
print(f"Total rows: {len(df)}")
