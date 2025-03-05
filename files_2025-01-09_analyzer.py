import os
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame

base_path = 'E:/net_log/zeek/extracted/2025-01-09/files/'
log_to_df = LogToDataFrame()
all_dfs = []

for log_file in os.listdir(base_path):
    if log_file.startswith('files') and log_file.endswith('.log'):
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
print("Sources:", combined_df['source'].value_counts(), sep='\n')
print("Top MIME types:", combined_df['mime_type'].value_counts().head(5), sep='\n')
print("Top source IPs:", combined_df['id.orig_h'].value_counts().head(5), sep='\n')
print("Top destination IPs:", combined_df['id.resp_h'].value_counts().head(5), sep='\n')
print("Total bytes stats:", combined_df['total_bytes'].describe(), sep='\n')

# Feature 1: Total file size transferred per source IP per hour
total_size = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')])['seen_bytes'].sum()
print("Total file size transferred per source IP per hour:", total_size, sep='\n')

# Feature 2: Count of unusual MIME types per source IP per hour
common_mime_types = ['text/plain', 'application/pdf', 'image/jpeg', 'image/png', 'text/html']
unusual_mime_conns = combined_df[combined_df['mime_type'].notna() & 
                                 ~combined_df['mime_type'].isin(common_mime_types)]
unusual_mime_counts = unusual_mime_conns.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
print("Unusual MIME type counts per source IP per hour:", unusual_mime_counts, sep='\n')

# Feature 3: Ratio of missing bytes per source IP per hour
missing_bytes_sum = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')])['missing_bytes'].sum()
total_bytes_sum = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')])['total_bytes'].sum()
missing_ratio = missing_bytes_sum / total_bytes_sum
print("Missing bytes ratio per source IP per hour:", missing_ratio.fillna(0), sep='\n')

# Save outputs
combined_df.to_csv('files_jan9.csv')
with open('files_jan9_output.txt', 'w') as f:
    f.write(f"Shape: {combined_df.shape}\n")
    f.write("Raw data sample:\n" + combined_df.head().to_string() + "\n")
    f.write("Sources:\n" + combined_df['source'].value_counts().to_string() + "\n")
    f.write("Top MIME types:\n" + combined_df['mime_type'].value_counts().head(5).to_string() + "\n")
    f.write("Top source IPs:\n" + combined_df['id.orig_h'].value_counts().head(5).to_string() + "\n")
    f.write("Top destination IPs:\n" + combined_df['id.resp_h'].value_counts().head(5).to_string() + "\n")
    f.write("Total bytes stats:\n" + combined_df['total_bytes'].describe().to_string() + "\n")
    f.write("Total file size transferred per source IP per hour:\n" + total_size.to_string() + "\n")
    f.write("Unusual MIME type counts per source IP per hour:\n" + unusual_mime_counts.to_string() + "\n")
    f.write("Missing bytes ratio per source IP per hour:\n" + missing_ratio.fillna(0).to_string() + "\n")