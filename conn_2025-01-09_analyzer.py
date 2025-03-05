import os
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame

log_to_df = LogToDataFrame()
base_path = 'E:/net_log/zeek/extracted/2025-01-09/conn/'
all_dfs = []

for log_file in os.listdir(base_path):
    if log_file.startswith('conn') and log_file.endswith('.log'):
        df = log_to_df.create_dataframe(os.path.join(base_path, log_file))
        all_dfs.append(df)

combined_df = pd.concat(all_dfs, ignore_index=False) 
print(combined_df.columns)
combined_df['duration_seconds'] = combined_df['duration'].dt.total_seconds()

print(combined_df.shape)
print(combined_df['conn_state'].value_counts())
print(combined_df['proto'].value_counts())
print(combined_df[['orig_bytes', 'resp_bytes']].describe())
print(combined_df[combined_df['orig_bytes'] > combined_df['resp_bytes']].shape[0], "connections send more than they receive")
print(combined_df['duration'].describe())
print(combined_df[combined_df['duration_seconds'] < 1.0].shape[0], "short-lived connections (<1s)")
print("Top source IPs:", combined_df['id.orig_h'].value_counts().head(5), sep='\n')
print("Top destination IPs:", combined_df['id.resp_h'].value_counts().head(5), sep='\n')
print("Top source ports:", combined_df['id.orig_p'].value_counts().head(5), sep='\n')
print("Top destination ports:", combined_df['id.resp_p'].value_counts().head(5), sep='\n')
unique_dests = combined_df.groupby('id.orig_h')['id.resp_h'].nunique()
print(unique_dests.describe())
print(unique_dests[unique_dests > 10].index.tolist(), "IPs contacting >10 destinations")
print(combined_df['service'].value_counts(dropna=False))
print(combined_df['history'].value_counts().head(5))
print(combined_df['missed_bytes'].value_counts())
print(combined_df[combined_df['missed_bytes'] > 0].shape[0], "connections with missed bytes")
print(combined_df[['orig_pkts', 'resp_pkts']].describe())
print(combined_df[['local_orig', 'local_resp']].value_counts(dropna=False))

heavy_senders = combined_df[combined_df['orig_bytes'] > 1e6]
print("Heavy senders:", heavy_senders[['id.orig_h', 'id.resp_h', 'orig_bytes', 'resp_bytes', 'duration_seconds']], sep='\n')
short_conns = combined_df[combined_df['duration_seconds'] < 1.0]
print("Short conn protocols:", short_conns['proto'].value_counts(), sep='\n')
print("Short conn ports:", short_conns['id.resp_p'].value_counts().head(5), sep='\n')
failed_conns = combined_df[combined_df['conn_state'].isin(['S0', 'RSTO'])]
print("Failed conn IPs:", failed_conns['id.orig_h'].value_counts(), sep='\n')
print("Failed conn ports:", failed_conns['id.resp_p'].value_counts(), sep='\n')
combined_df['bytes_per_pkt'] = combined_df['orig_bytes'] / (combined_df['orig_pkts'] + 1)
print("Bytes per packet:", combined_df['bytes_per_pkt'].describe(), sep='\n')

heavy_ip = combined_df[combined_df['id.orig_h'] == '172.30.30.250']
print("172.30.30.250 details:", heavy_ip[['id.resp_h', 'proto', 'service', 'orig_bytes', 'duration_seconds', 'conn_state']], sep='\n')
dns_conns = combined_df[combined_df['id.resp_p'] == 53]
print("DNS conn states:", dns_conns['conn_state'].value_counts(), sep='\n')
print("DNS durations:", dns_conns['duration_seconds'].describe(), sep='\n')
https_conns = combined_df[combined_df['id.resp_p'] == 443]
print("HTTPS big senders:", https_conns[https_conns['orig_bytes'] > 1e6][['id.orig_h', 'orig_bytes', 'duration_seconds']], sep='\n')
print("Failed conn dests:", failed_conns['id.resp_h'].value_counts(), sep='\n')
discard_conns = combined_df[combined_df['id.resp_p'] == 9]
print("Port 9 details:", discard_conns[['id.orig_h', 'proto', 'orig_bytes', 'conn_state']], sep='\n')

broadcast_conns = combined_df[combined_df['id.resp_h'].isin(['255.255.255.255', '172.30.30.255'])]
print("Broadcast details:", broadcast_conns[['id.orig_h', 'proto', 'orig_bytes', 'duration_seconds', 'conn_state']], sep='\n')
short_non_dns = combined_df[(combined_df['duration_seconds'] < 1.0) & (combined_df['id.resp_p'] != 53)]
print("Short non-DNS:", short_non_dns[['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'duration_seconds']], sep='\n')
print("UDP bytes:", combined_df[combined_df['proto'] == 'udp'][['orig_bytes', 'resp_bytes']].describe(), sep='\n')
print("TCP bytes:", combined_df[combined_df['proto'] == 'tcp'][['orig_bytes', 'resp_bytes']].describe(), sep='\n')
ip_states = combined_df.groupby('id.orig_h')['conn_state'].value_counts().unstack(fill_value=0)
print("IP conn states:", ip_states, sep='\n')
high_bpp = combined_df[combined_df['bytes_per_pkt'] > 50]
print("High bytes/packet:", high_bpp[['id.orig_h', 'id.resp_h', 'orig_bytes', 'orig_pkts', 'bytes_per_pkt']], sep='\n')

hourly_counts = combined_df.resample('1h').size()
print("Hourly connection counts:", hourly_counts, sep='\n')

# temporal
broadcast_hourly = broadcast_conns.resample('1h').size()
print("Broadcast hourly counts:", broadcast_hourly, sep='\n')
short_non_dns_dests = short_non_dns['id.resp_h'].value_counts()
print("Short non-DNS dest IPs:", short_non_dns_dests.head(10), sep='\n')
tcp_downloads = combined_df[(combined_df['proto'] == 'tcp') & (combined_df['resp_bytes'] > 1e6)]
print("TCP big downloads:", tcp_downloads[['id.orig_h', 'id.resp_h', 'resp_bytes', 'duration_seconds']], sep='\n')
failed_hourly = failed_conns.resample('1h').size()
print("Failed conn hourly counts:", failed_hourly, sep='\n')
dns_hourly = dns_conns.resample('1h').size()
non_dns_hourly = combined_df[combined_df['id.resp_p'] != 53].resample('1h').size()
print("DNS hourly:", dns_hourly, sep='\n')
print("Non-DNS hourly:", non_dns_hourly, sep='\n')

# Add to each analyzer script (e.g., conn_2025-01-12_analyzer.py)
combined_df.to_csv('jan9_baseline.csv')  # Repeat for Jan 9/11