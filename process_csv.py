import csv
import random
from datetime import datetime, timedelta
import os

input_file = r"c:\Users\elmes\OneDrive\Bureau\S6\Advanced Algorithms\Dynamic Network Intrusion Detection Graph Analyzer\network_traffic_data.csv"
output_file = input_file + ".tmp"

with open(input_file, 'r', newline='') as f_in, open(output_file, 'w', newline='') as f_out:
    reader = csv.reader(f_in)
    writer = csv.writer(f_out)
    
    header = next(reader)
    try:
        bytecount_idx = header.index("ByteCount")
    except ValueError:
        print("ByteCount column not found.")
        exit(1)
        
    new_header = ["Timestamp"] + header[:bytecount_idx] + ["BytesSent", "BytesReceived"] + header[bytecount_idx+1:]
    writer.writerow(new_header)
    
    current_time = datetime(2023, 10, 1, 8, 0, 0)
    
    for row in reader:
        # Add between 0 and 2.5 seconds to simulate sequential real-time network traffic
        current_time += timedelta(seconds=random.uniform(0.01, 2.5))
        timestamp_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
        
        byte_count = int(row[bytecount_idx])
        # Random but realistic split (not always 50/50)
        ratio = random.uniform(0.05, 0.95)
        bytes_sent = int(byte_count * ratio)
        bytes_received = byte_count - bytes_sent
        
        new_row = [timestamp_str] + row[:bytecount_idx] + [str(bytes_sent), str(bytes_received)] + row[bytecount_idx+1:]
        writer.writerow(new_row)

os.replace(output_file, input_file)
print("Updated network_traffic_data.csv successfully.")
