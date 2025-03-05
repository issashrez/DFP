from pathlib import Path
from urllib.parse import unquote
import os
import shutil

def sanitize_filename(name):
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    name = name.rstrip('. ')
    return name

base_path = r"E:/net_log/zeek/extracted"
date_folders = ["2025-01-09", "2025-01-11", "2025-01-12", "2025-01-13", "2025-01-14", "2025-01-15"]

for date_folder in date_folders:
    folder_path = Path(base_path) / date_folder
    if not folder_path.exists():
        print(f"Warning: Folder '{folder_path}' does not exist. Skipping...")
        continue

    for file in folder_path.iterdir():
        decoded_name = unquote(file.name)
        sanitized_name = sanitize_filename(decoded_name)
        
        log_type = sanitized_name.split(".", 1)[0]  
        
        if file.is_dir():
            target_dir = folder_path / log_type
            target_dir.mkdir(exist_ok=True)
            try:
                for item in file.iterdir():
                    shutil.move(str(item), str(target_dir / item.name))
                file.rmdir()
            except Exception as e:
                print(f"Error moving directory {file}: {e}")
        else:
            target_dir = folder_path / log_type
            target_dir.mkdir(exist_ok=True)
            new_file_name = target_dir / sanitized_name
            try:
                shutil.move(str(file), str(new_file_name))
            except Exception as e:
                print(f"Error moving file {file}: {e}")