from zat.log_to_dataframe import LogToDataFrame


log_to_df = LogToDataFrame()

df = log_to_df.create_dataframe('E:/net_log/zeek/extracted/2025-01-09/conn/conn.21_15_15-21_16_44.log')

print(df[['id.orig_h', 'id.resp_h', 'duration']])
