import os
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame

base_path = 'E:/net_log/zeek/extracted/2025-01-11/weird/'
log_to_df = LogToDataFrame()
all_dfs = []

for log_file in os.listdir(base_path):
    if log_file.startswith('weird') and log_file.endswith('.log'):
        file_path = os.path.join(base_path, log_file)
        if os.path.getsize(file_path) > 1e9:  # >1 GB, sample 100K rows
            df = log_to_df.create_dataframe(file_path, nrows=100000)
        else:
            df = log_to_df.create_dataframe(file_path)
        if not df.empty:
            all_dfs.append(df)

combined_df = pd.concat(all_dfs, ignore_index=False) if all_dfs else pd.DataFrame()
print("Shape:", combined_df.shape)
print("Raw data sample:", combined_df.head(), sep='\n')

# Basic stats
print("Weird names:", combined_df['name'].value_counts(), sep='\n')
print("Notice flags:", combined_df['notice'].value_counts(), sep='\n')
print("Top source IPs:", combined_df['id.orig_h'].value_counts().head(5), sep='\n')
print("Top destination IPs:", combined_df['id.resp_h'].value_counts().head(5), sep='\n')
print("Sources:", combined_df['source'].value_counts(), sep='\n')

# Feature 1: Count of weird events per source IP per hour
weird_counts = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
print("Weird event counts per source IP per hour:", weird_counts, sep='\n')

# Feature 2: Count of unique weird names per source IP per hour
unique_weird_names = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')])['name'].nunique()
print("Unique weird names per source IP per hour:", unique_weird_names, sep='\n')

# Feature 3: Ratio of notice-flagged weird events per source IP per hour
notice_conns = combined_df[combined_df['notice'] == True]
notice_counts = notice_conns.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
total_counts = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
notice_ratio = notice_counts / total_counts
print("Notice-flagged weird ratio per source IP per hour:", notice_ratio.fillna(0), sep='\n')

# Save outputs
combined_df.to_csv('weird_jan11.csv')
with open('weird_jan11_output.txt', 'w') as f:
    f.write(f"Shape: {combined_df.shape}\n")
    f.write("Raw data sample:\n" + combined_df.head().to_string() + "\n")
    f.write("Weird names:\n" + combined_df['name'].value_counts().to_string() + "\n")
    f.write("Notice flags:\n" + combined_df['notice'].value_counts().to_string() + "\n")
    f.write("Top source IPs:\n" + combined_df['id.orig_h'].value_counts().head(5).to_string() + "\n")
    f.write("Top destination IPs:\n" + combined_df['id.resp_h'].value_counts().head(5).to_string() + "\n")
    f.write("Sources:\n" + combined_df['source'].value_counts().to_string() + "\n")
    f.write("Weird event counts per source IP per hour:\n" + weird_counts.to_string() + "\n")
    f.write("Unique weird names per source IP per hour:\n" + unique_weird_names.to_string() + "\n")
    f.write("Notice-flagged weird ratio per source IP per hour:\n" + notice_ratio.fillna(0).to_string() + "\n")