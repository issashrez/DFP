from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

base_path = "E:/net_log/zeek/extracted/2025-01-09/conn"
def validate_all_logs(base_path: str):
    log_files = list(Path(base_path).rglob("*.log"))
    
    with ProcessPoolExecutor(max_workers=8) as executor:  
        futures = []
        for log_file in log_files:
            log_type = log_file.parent.name 
            futures.append(executor.submit(validate_zeek_schema, log_file, log_type))
        
        results = [f.result() for f in futures]
        return sum(results) / len(results)  

# Usage
validation_score = validate_all_logs("extracted/")
print(f"Schema validation passed for {validation_score*100:.1f}% of files")
