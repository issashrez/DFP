import os
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame

log_to_df = LogToDataFrame()
base_path = 'E:/net_log/zeek/extracted/2025-01-15/conn/'
all_dfs = []

for log_file in os.listdir(base_path):
    if log_file.startswith('conn') and log_file.endswith('.log'):
        file_path = os.path.join(base_path, log_file)
        df = log_to_df.create_dataframe(file_path)  
        df['duration_seconds'] = df['duration'].dt.total_seconds()
        all_dfs.append(df)

combined_df = pd.concat(all_dfs, ignore_index=False)
print("Shape:", combined_df.shape)

# Basic stats
print("Conn states:", combined_df['conn_state'].value_counts(), sep='\n')
print("Protocols:", combined_df['proto'].value_counts(), sep='\n')
print("Bytes stats:", combined_df[['orig_bytes', 'resp_bytes']].describe(), sep='\n')
print("Connections sending more:", combined_df[combined_df['orig_bytes'] > combined_df['resp_bytes']].shape[0], sep='\n')
print("Duration stats:", combined_df['duration'].describe(), sep='\n')
print("Short-lived connections (<1s):", combined_df[combined_df['duration_seconds'] < 1.0].shape[0], sep='\n')

# Key entities
print("Top source IPs:", combined_df['id.orig_h'].value_counts().head(5), sep='\n')
print("Top destination IPs:", combined_df['id.resp_h'].value_counts().head(5), sep='\n')
print("Top destination ports:", combined_df['id.resp_p'].value_counts().head(5), sep='\n')

# Behavioral patterns
combined_df['bytes_per_pkt'] = combined_df['orig_bytes'] / (combined_df['orig_pkts'] + 1)
print("Bytes per packet:", combined_df['bytes_per_pkt'].describe(), sep='\n')
hourly_counts = combined_df.resample('1h').size()
print("Hourly connection counts:", hourly_counts, sep='\n')

# Anomalies (T3 focus)
heavy_senders = combined_df[combined_df['orig_bytes'] > 1e6]
print("Heavy senders:", heavy_senders[['id.orig_h', 'id.resp_h', 'orig_bytes', 'duration_seconds']], sep='\n')
broadcast_conns = combined_df[combined_df['id.resp_h'].isin(['255.255.255.255', '172.30.30.255'])]
print("Broadcast details:", broadcast_conns[['id.orig_h', 'proto', 'orig_bytes', 'duration_seconds']], sep='\n')
failed_conns = combined_df[combined_df['conn_state'].isin(['S0', 'RSTO'])]
print("Failed conn IPs:", failed_conns['id.orig_h'].value_counts(), sep='\n')

# DNS vs. non-DNS
dns_conns = combined_df[combined_df['id.resp_p'] == 53]
print("DNS durations:", dns_conns['duration_seconds'].describe(), sep='\n')
short_non_dns = combined_df[(combined_df['duration_seconds'] < 1.0) & (combined_df['id.resp_p'] != 53)]
print("Short non-DNS dest IPs:", short_non_dns['id.resp_h'].value_counts().head(5), sep='\n')

combined_df.to_csv('jan15_ctf.csv')
