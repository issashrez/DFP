import os
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame

base_path = 'E:/net_log/zeek/extracted/2025-01-11/dns/'
log_to_df = LogToDataFrame()
all_dfs = []

for log_file in os.listdir(base_path):
    if log_file.startswith('dns') and log_file.endswith('.log'):
        file_path = os.path.join(base_path, log_file)
        if 'dns.12_00_00-00_00_00.log' in log_file:
            df = pd.read_csv(file_path, sep='\t', comment='#', na_values='-', nrows=50000)
            with open(file_path, 'r') as f:
                header = next(line for line in f if line.startswith('#fields'))
            fields = header.strip().split('\t')[1:]  
            df.columns = fields
            df.index = pd.to_datetime(df['ts'], unit='s')  
            if 'rtt' in df.columns:  
                df['rtt'] = pd.to_timedelta(df['rtt']).dt.total_seconds()
        else:
            df = log_to_df.create_dataframe(file_path)
            if 'rtt' in df.columns:  # Convert rtt to seconds
                df['rtt'] = df['rtt'].dt.total_seconds()
        if not df.empty:
            all_dfs.append(df)

combined_df = pd.concat(all_dfs, ignore_index=False) if all_dfs else pd.DataFrame()
print("Shape:", combined_df.shape)

# Basic stats
print("Protocols:", combined_df['proto'].value_counts(), sep='\n')
print("Response codes:", combined_df['rcode'].value_counts(), sep='\n')
print("Top source IPs:", combined_df['id.orig_h'].value_counts().head(5), sep='\n')
print("Top destination IPs:", combined_df['id.resp_h'].value_counts().head(5), sep='\n')
print("Top queries:", combined_df['query'].value_counts().head(5), sep='\n')

# Feature 1: Count of unique DNS queries per source IP per hour
unique_queries = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')])['query'].nunique()
print("Unique DNS queries per source IP per hour:", unique_queries, sep='\n')

# Feature 2: Ratio of failed DNS responses per source IP per hour
failed_responses = combined_df[combined_df['rcode'].astype(float) != 0]
failed_counts = failed_responses.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
total_counts = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
failed_ratio = failed_counts / total_counts
print("Failed DNS response ratio per source IP per hour:", failed_ratio.fillna(0), sep='\n')

# Feature 3: Average RTT per destination IP per hour (fixed)
avg_rtt = combined_df.groupby(['id.resp_h', pd.Grouper(freq='1h')])['rtt'].mean()
print("Avg RTT per destination IP per hour:", avg_rtt.fillna(0), sep='\n')

# Feature 4: Count of unusual qtype requests per source IP per hour
common_qtypes = [1, 28]  # A, AAAA
unusual_qtype_conns = combined_df[combined_df['qtype'].notna() & ~combined_df['qtype'].isin(common_qtypes)]
unusual_qtype_counts = unusual_qtype_conns.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
print("Unusual qtype counts per source IP per hour:", unusual_qtype_counts, sep='\n')

# Feature 5: Count of recursive queries per source IP per hour
recursive_conns = combined_df[combined_df['RD'] == True]
recursive_counts = recursive_conns.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
print("Recursive query counts per source IP per hour:", recursive_counts, sep='\n')

# Save outputs
combined_df.to_csv('dns_jan11.csv')
with open('dns_jan11_output.txt', 'w') as f:
    f.write(f"Shape: {combined_df.shape}\n")
    f.write("Protocols:\n" + combined_df['proto'].value_counts().to_string() + "\n")
    f.write("Response codes:\n" + combined_df['rcode'].value_counts().to_string() + "\n")
    f.write("Top source IPs:\n" + combined_df['id.orig_h'].value_counts().head(5).to_string() + "\n")
    f.write("Top destination IPs:\n" + combined_df['id.resp_h'].value_counts().head(5).to_string() + "\n")
    f.write("Top queries:\n" + combined_df['query'].value_counts().head(5).to_string() + "\n")
    f.write("Unique DNS queries per source IP per hour:\n" + unique_queries.to_string() + "\n")
    f.write("Failed DNS response ratio per source IP per hour:\n" + failed_ratio.fillna(0).to_string() + "\n")
    f.write("Avg RTT per destination IP per hour:\n" + avg_rtt.fillna(0).to_string() + "\n")
    f.write("Unusual qtype counts per source IP per hour:\n" + unusual_qtype_counts.to_string() + "\n")
    f.write("Recursive query counts per source IP per hour:\n" + recursive_counts.to_string() + "\n")
