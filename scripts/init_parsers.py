import pandas as pd
import json
import os
from datetime import datetime, timedelta

def parse_cicids(file_path, out_dir):
    # skipinitialspace=True strips the annoying leading spaces in " Destination Port"
    raw_data = pd.read_csv(file_path, skipinitialspace=True, encoding='utf-8')
    
    # Map based on the EXACT headers shown in your head command
    col_map = {
        'Destination Port': 'dst_pt',
        'Total Length of Fwd Packets': 'b_out',
        'Total Length of Bwd Packets': 'b_in',
        'Label': 'act'
    }
    
    valid_cols = {k: v for k, v in col_map.items() if k in raw_data.columns}
    clean_data = raw_data[list(valid_cols.keys())].rename(columns=valid_cols)
    
    out_list = []
    base_time = datetime.now()
    
    for idx, row in clean_data.iterrows():
        out_dict = {
            # Fake a timestamp sequence since it was stripped from the CSV
            "ts": (base_time + timedelta(seconds=idx)).strftime("%Y-%m-%dT%H:%M:%SZ"), 
            "src_ip": "0.0.0.0", 
            "dst_ip": "0.0.0.0", 
            "src_pt": 0,         
            "dst_pt": int(row.get('dst_pt', 0)),
            "proto": "NA",
            "evt_id": 1000,
            "act": str(row.get('act', 'BENIGN')),
            "b_in": int(row.get('b_in', 0)),
            "b_out": int(row.get('b_out', 0))
        }
        out_list.append(out_dict)
    
    base_name = os.path.basename(file_path).replace('.csv', '.json')
    out_path = os.path.join(out_dir, base_name)
    
    with open(out_path, 'w') as out_file:
        json.dump(out_list, out_file, indent=2)

def parse_loghub(file_path, out_dir, log_tag):
    raw_data = pd.read_csv(file_path)
    out_list = []
    
    for _, row in raw_data.iterrows():
        # THE FIX: Dynamically handle split Linux/Windows timestamps vs Apache timestamps
        if 'Month' in row and 'Date' in row and 'Time' in row:
            time_val = f"{row.get('Month', '')} {row.get('Date', '')} {row.get('Time', '')}".strip()
        else:
            time_val = str(row.get('Time', "1970-01-01T00:00:00Z"))
            
        out_dict = {
            "ts": time_val,
            "src_ip": "0.0.0.0",
            "dst_ip": "0.0.0.0",
            "src_pt": 0,
            "dst_pt": 0,
            "proto": "NA",
            "evt_id": str(row.get('EventId', '0')),
            "act": log_tag,
            "b_in": 0,
            "b_out": 0,
            "payload": str(row.get('Content', '')) 
        }
        out_list.append(out_dict)
        
    base_name = os.path.basename(file_path).replace('.csv', '.json')
    out_path = os.path.join(out_dir, base_name)
    
    with open(out_path, 'w') as out_file:
        json.dump(out_list, out_file, indent=2)

def init_parsers():
    cicids_path = "data/raw/cicids/Monday-WorkingHours.pcap_ISCX.csv"
    apache_path = "data/raw/loghub/Apache/Apache_2k.log_structured.csv"
    linux_path = "data/raw/loghub/Linux/Linux_2k.log_structured.csv"
    out_dir = "data/processed"
    
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
        
    if os.path.exists(cicids_path):
        print(f"Parsing {cicids_path}...")
        parse_cicids(cicids_path, out_dir)
        
    if os.path.exists(apache_path):
        print(f"Parsing {apache_path}...")
        parse_loghub(apache_path, out_dir, "WEB_APP")
    if os.path.exists(linux_path):
        print(f"Parsing {linux_path}...")
        parse_loghub(linux_path, out_dir, "HOST_LINUX")

if __name__ == "__main__":
    init_parsers()
