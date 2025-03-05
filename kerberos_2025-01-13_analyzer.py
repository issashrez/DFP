import os
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame

base_path = 'E:/net_log/zeek/extracted/2025-01-13/kerberos/'  # Update to 2025-01-15 later
log_to_df = LogToDataFrame()
all_dfs = []

for log_file in os.listdir(base_path):
    if log_file.startswith('kerberos') and log_file.endswith('.log'):
        file_path = os.path.join(base_path, log_file)
        df = log_to_df.create_dataframe(file_path)
        if not df.empty:
            all_dfs.append(df)

combined_df = pd.concat(all_dfs, ignore_index=False) if all_dfs else pd.DataFrame()
print("Shape:", combined_df.shape)
print("Raw data sample:", combined_df.head(), sep='\n')

# Basic stats
print("Request types:", combined_df['request_type'].value_counts(), sep='\n')
print("Top clients:", combined_df['client'].value_counts().head(5), sep='\n')
print("Top services:", combined_df['service'].value_counts().head(5), sep='\n')
print("Success rate:", combined_df['success'].value_counts(), sep='\n')
print("Top source IPs:", combined_df['id.orig_h'].value_counts().head(5), sep='\n')

# Feature 1: Failed authentication ratio per source IP per hour
failed_auths = combined_df[(combined_df['success'] == False) | 
                           combined_df['error_msg'].notna()]
failed_counts = failed_auths.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
total_counts = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
failed_ratio = failed_counts / total_counts
print("Failed authentication ratio per source IP per hour:", failed_ratio.fillna(0), sep='\n')

# Feature 2: Count of unique service names per source IP per hour
unique_services = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')])['service'].nunique()
print("Unique service names per source IP per hour:", unique_services, sep='\n')

# Save outputs
combined_df.to_csv('kerberos_jan13.csv')
with open('kerberos_jan13_output.txt', 'w') as f:
    f.write(f"Shape: {combined_df.shape}\n")
    f.write("Raw data sample:\n" + combined_df.head().to_string() + "\n")
    f.write("Request types:\n" + combined_df['request_type'].value_counts().to_string() + "\n")
    f.write("Top clients:\n" + combined_df['client'].value_counts().head(5).to_string() + "\n")
    f.write("Top services:\n" + combined_df['service'].value_counts().head(5).to_string() + "\n")
    f.write("Success rate:\n" + combined_df['success'].value_counts().to_string() + "\n")
    f.write("Top source IPs:\n" + combined_df['id.orig_h'].value_counts().head(5).to_string() + "\n")
    f.write("Failed authentication ratio per source IP per hour:\n" + failed_ratio.fillna(0).to_string() + "\n")
    f.write("Unique service names per source IP per hour:\n" + unique_services.to_string() + "\n")