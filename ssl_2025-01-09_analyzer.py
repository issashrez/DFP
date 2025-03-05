import os
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame

base_path = 'E:/net_log/zeek/extracted/2025-01-09/ssl/'
log_to_df = LogToDataFrame()
all_dfs = []

for log_file in os.listdir(base_path):
    if log_file.startswith('ssl') and log_file.endswith('.log'):
        file_path = os.path.join(base_path, log_file)
        if os.path.getsize(file_path) > 1e9:  
            df = log_to_df.create_dataframe(file_path, nrows=100000)
        else:
            df = log_to_df.create_dataframe(file_path)
        if not df.empty:
            all_dfs.append(df)

combined_df = pd.concat(all_dfs, ignore_index=False) if all_dfs else pd.DataFrame()
print("Shape:", combined_df.shape)
print("Raw data sample:", combined_df.head(), sep='\n')  

# Basic stats
print("TLS Versions:", combined_df['version'].value_counts(), sep='\n')
print("Top ciphers:", combined_df['cipher'].value_counts().head(5), sep='\n')
print("Top source IPs:", combined_df['id.orig_h'].value_counts().head(5), sep='\n')
print("Top destination IPs:", combined_df['id.resp_h'].value_counts().head(5), sep='\n')
print("Validation status:", combined_df['validation_status'].value_counts(), sep='\n')

# Feature 1: Ratio of invalid certificates per source IP per hour
invalid_certs = combined_df[combined_df['validation_status'].notna() & 
                            ~combined_df['validation_status'].str.contains('ok', case=False, na=False)]
invalid_counts = invalid_certs.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
total_counts = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
invalid_ratio = invalid_counts / total_counts
print("Invalid certificate ratio per source IP per hour:", invalid_ratio.fillna(0), sep='\n')

# Feature 2: Count of unusual cipher suites per source IP per hour (refined for weak ciphers)
weak_ciphers = ['TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA', 
                'TLS_RSA_WITH_DES_CBC_SHA']  # Weak/deprecated ciphers
unusual_cipher_conns = combined_df[combined_df['cipher'].notna() & 
                                   combined_df['cipher'].isin(weak_ciphers)]
unusual_cipher_counts = unusual_cipher_conns.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
print("Unusual cipher counts per source IP per hour:", unusual_cipher_counts, sep='\n')

# Feature 3: Count of non-established SSL connections per source IP per hour
non_established_conns = combined_df[combined_df['established'] == False]
non_established_counts = non_established_conns.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
print("Non-established SSL counts per source IP per hour:", non_established_counts, sep='\n')

# Save outputs
combined_df.to_csv('ssl_jan9.csv')
with open('ssl_jan9_output.txt', 'w') as f:
    f.write(f"Shape: {combined_df.shape}\n")
    f.write("Raw data sample:\n" + combined_df.head().to_string() + "\n")
    f.write("TLS Versions:\n" + combined_df['version'].value_counts().to_string() + "\n")
    f.write("Top ciphers:\n" + combined_df['cipher'].value_counts().head(5).to_string() + "\n")
    f.write("Top source IPs:\n" + combined_df['id.orig_h'].value_counts().head(5).to_string() + "\n")
    f.write("Top destination IPs:\n" + combined_df['id.resp_h'].value_counts().head(5).to_string() + "\n")
    f.write("Validation status:\n" + combined_df['validation_status'].value_counts().to_string() + "\n")
    f.write("Invalid certificate ratio per source IP per hour:\n" + invalid_ratio.fillna(0).to_string() + "\n")
    f.write("Unusual cipher counts per source IP per hour:\n" + unusual_cipher_counts.to_string() + "\n")
    f.write("Non-established SSL counts per source IP per hour:\n" + non_established_counts.to_string() + "\n")
