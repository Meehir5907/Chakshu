import bz2
import pandas as pd
import json
import os
from datetime import datetime, timedelta

def parse_cicids(file_path, out_dir):
    raw_data = pd.read_csv(file_path, skipinitialspace=True, encoding='utf-8')
    
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
            "ts": (base_time + timedelta(seconds=idx)).strftime("%Y-%m-%dT%H:%M:%SZ"), 
            "src_ip": "0.0.0.0", 
            "dst_ip": "0.0.0.0", 
            "src_pt": 0,         
            "dst_pt": int(row.get('dst_pt', 0)),
            "proto": "NA",
            "evt_id": 1000,
            "act": "L3_L4", # Force route to the Network Specialist
            "b_in": int(row.get('b_in', 0)),
            "b_out": int(row.get('b_out', 0)),
            "payload": str(row.get('act', 'BENIGN')) # Store Kaggle label as payload
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
        if 'Month' in row and 'Date' in row and 'Time' in row:
            time_val = f"{row.get('Month', '')} {row.get('Date', '')} {row.get('Time', '')}".strip()
        elif 'Date' in row and 'Day' in row and 'Time' in row:
            time_val = f"{row.get('Date', '')} {row.get('Day', '')} {row.get('Time', '')}".strip()
        elif 'Date' in row and 'Time' in row:
            time_val = f"{row.get('Date', '')}T{row.get('Time', '')}Z"
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

def parse_lanl_wls():
    raw_path = "data/raw/lanl/wls/wls_day-01.bz2"
    out_dir = "data/processed"
    out_path = os.path.join(out_dir, "LANL_WLS_2k.json")
    
    if not os.path.exists(raw_path):
        print(f"[!] Cannot find {raw_path}")
        return

    print(f"Parsing {raw_path} (Streaming first 2000 logs)...")
    frames = []
    base_time = datetime.now()
    
    try:
        with bz2.open(raw_path, "rt", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= 2000:
                    break
                
                payload = line.strip()
                
                frames.append({
                    "ts": (base_time + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "src_ip": "0.0.0.0", 
                    "payload": payload,
                    "act": "AUTH_WINDOWS"
                })
                
    except Exception as e:
        print(f"[ERROR] Failed to read BZ2: {e}")
        return

    os.makedirs(out_dir, exist_ok=True)
    with open(out_path, 'w') as out_file:
        json.dump(frames, out_file, indent=4)
        
    print(f"[+] Processed {len(frames)} LANL WLS logs into {out_path}")

def init_parsers():
    cicids_path = "data/raw/cicids/Monday-WorkingHours.pcap_ISCX.csv"
    ddos_path = "data/raw/cicids/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    apache_path = "data/raw/loghub/Apache/Apache_2k.log_structured.csv"
    linux_path = "data/raw/loghub/Linux/Linux_2k.log_structured.csv"
    windows_path = "data/raw/loghub/Windows/Windows_2k.log_structured.csv"
    openssh_path = "data/raw/loghub/OpenSSH/OpenSSH_2k.log_structured.csv"
    wls_path = "data/raw/lanl/wls/wls_day-01.bz2"
    out_dir = "data/processed"
    
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
        
    if os.path.exists(cicids_path):
        print(f"Parsing {cicids_path}...")
        parse_cicids(cicids_path, out_dir)

    if os.path.exists(ddos_path):
        print(f"Parsing {ddos_path}...")
        parse_cicids(ddos_path, out_dir)
        
    if os.path.exists(apache_path):
        print(f"Parsing {apache_path}...")
        parse_loghub(apache_path, out_dir, "WEB_APP")
        
    if os.path.exists(linux_path):
        print(f"Parsing {linux_path}...")
        parse_loghub(linux_path, out_dir, "HOST_LINUX")
        
    if os.path.exists(windows_path):
        print(f"Parsing {windows_path}...")
        parse_loghub(windows_path, out_dir, "HOST_WINDOWS")

    if os.path.exists(openssh_path):
        print(f"Parsing {openssh_path}...")
        parse_loghub(openssh_path, out_dir, "AUTH_LINUX")

    if os.path.exists(wls_path):
        parse_lanl_wls()

if __name__ == "__main__":
    init_parsers()
