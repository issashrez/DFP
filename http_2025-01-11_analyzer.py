import os
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame

base_path = 'E:/net_log/zeek/extracted/2025-01-11/http/' 
log_to_df = LogToDataFrame()
all_dfs = []

for log_file in os.listdir(base_path):
    if log_file.startswith('http') and log_file.endswith('.log'):
        file_path = os.path.join(base_path, log_file)
        df = log_to_df.create_dataframe(file_path)
        if not df.empty:  
            all_dfs.append(df)

if all_dfs:  
    combined_df = pd.concat(all_dfs, ignore_index=False)
    print("Shape:", combined_df.shape)

    # Basic stats
    print("Methods:", combined_df['method'].value_counts(), sep='\n')
    print("Status codes:", combined_df['status_code'].value_counts(), sep='\n')
    print("Top source IPs:", combined_df['id.orig_h'].value_counts().head(5), sep='\n')
    print("Top destination hosts:", combined_df['host'].value_counts().head(5), sep='\n')

    # Feature 1: Count of HTTP 4xx/5xx per source IP per hour
    error_codes = combined_df[combined_df['status_code'].astype(float).between(400, 599)]
    error_counts = error_codes.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
    print("HTTP 4xx/5xx per source IP per<|control698|>:", error_counts, sep='\n')

    # Feature 2: Count of suspicious methods per source IP per hour
    suspicious_methods = ['POST', 'PUT', 'DELETE']
    suspicious_conns = combined_df[combined_df['method'].isin(suspicious_methods)]
    suspicious_counts = suspicious_conns.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
    print("Suspicious methods per source IP per hour:", suspicious_counts, sep='\n')

    # Feature 3: Average request/response size per host per hour
    avg_sizes = combined_df.groupby(['host', pd.Grouper(freq='1h')])[['request_body_len', 'response_body_len']].mean()
    print("Avg request/response size per host per hour:", avg_sizes, sep='\n')

    # Feature 4: Count of unique URIs per source IP per hour
    unique_uris = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')])['uri'].nunique()
    print("Unique URIs per source IP per hour:", unique_uris, sep='\n')

    # Feature 5: Count of unusual user agents per host per hour
    common_ua_patterns = ['Mozilla', 'Chrome', 'Safari', 'Firefox']
    unusual_ua = combined_df[~combined_df['user_agent'].str.contains('|'.join(common_ua_patterns), na=False)]
    unusual_ua_counts = unusual_ua.groupby(['host', pd.Grouper(freq='1h')]).size()
    print("Unusual user agents per host per hour:", unusual_ua_counts, sep='\n')

    # Feature 6: Ratio of proxied connections per source IP per hour
    proxied_conns = combined_df[combined_df['proxied'].notna() & (combined_df['proxied'] != '')]
    proxied_counts = proxied_conns.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
    total_counts = combined_df.groupby(['id.orig_h', pd.Grouper(freq='1h')]).size()
    proxied_ratio = proxied_counts / total_counts
    print("Proxied connection ratio per source IP per hour:", proxied_ratio.fillna(0), sep='\n')

    # Save outputs
    combined_df.to_csv('http_jan11.csv')
    with open('http_jan11_output.txt', 'w') as f:
        f.write(f"Shape: {combined_df.shape}\n")
        f.write("Methods:\n" + combined_df['method'].value_counts().to_string() + "\n")
        f.write("Status codes:\n" + combined_df['status_code'].value_counts().to_string() + "\n")
        f.write("Top source IPs:\n" + combined_df['id.orig_h'].value_counts().head(5).to_string() + "\n")
        f.write("Top destination hosts:\n" + combined_df['host'].value_counts().head(5).to_string() + "\n")
        f.write("HTTP 4xx/5xx per source IP per hour:\n" + error_counts.to_string() + "\n")
        f.write("Suspicious methods per source IP per hour:\n" + suspicious_counts.to_string() + "\n")
        f.write("Avg request/response size per host per hour:\n" + avg_sizes.to_string() + "\n")
        f.write("Unique URIs per source IP per hour:\n" + unique_uris.to_string() + "\n")
        f.write("Unusual user agents per host per hour:\n" + unusual_ua_counts.to_string() + "\n")
        f.write("Proxied connection ratio per source IP per hour:\n" + proxied_ratio.fillna(0).to_string() + "\n")
else:
    print("No HTTP logs found or all logs are empty.")
