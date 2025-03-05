from zat.log_to_dataframe import LogToDataFrame

# Create an instance of LogToDataFrame
log_to_df = LogToDataFrame()

# Replace this path with the path to your Zeek log file
df = log_to_df.create_dataframe('E:/net_log/zeek/extracted/2025-01-09/conn/conn.21_15_15-21_16_44.log')

# Display some columns as an example
print(df[['id.orig_h', 'id.resp_h', 'duration']])