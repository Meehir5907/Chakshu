import time
import os
import json
import threading
from pathlib import Path
from datetime import datetime

# --- CONFIGURATION ---
BASE_DIR = Path(r"F:\CODING AND AI\Codings file VS code\forensics_lab")
RAW_LOG_DIR = BASE_DIR / "logs" 
OUTPUT_FILE = BASE_DIR / "logs" / "normalized_logs.json"

# Sources mapping
LOG_SOURCES = {
    "NETWORK": RAW_LOG_DIR / "network.log",
    "OS": RAW_LOG_DIR / "os.log",
    "APP": RAW_LOG_DIR / "app.log"
}

# --- PHASE 2: NORMALIZATION CLASSES ---
class JSONExporter:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def write_log(self, data):
        """Appends a single normalized log entry into the JSON file."""
        try:
            with open(self.file_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(data) + "\n")
            return True
        except Exception as e:
            print(f"[-] Write Error: {e}")
            return False

class UniversalIngestionLayer:
    def __init__(self):
        self.schemas = {
            "NETWORK": ["protocol", "local_address", "foreign_address", "state", "pid"],
            "OS": ["service_name", "status"],
            "APP": ["image_name", "pid", "session_name", "session_num", "mem_usage", "status"]
        }

    def is_garbage_line(self, line):
        garbage_indicators = ["---", "===", "Time:", "Active Connections", "Image Name", "Proto", "Status", "Name"]
        return any(indicator in line for indicator in garbage_indicators) or not line.strip()

    def normalize(self, source_tag, raw_line):
        """Converts raw tabular lines into structured dictionaries."""
        if self.is_garbage_line(raw_line):
            return None

        parts = raw_line.split()
        schema = self.schemas.get(source_tag, [])

        if len(parts) >= len(schema):
            normalized_data = {
                "timestamp": datetime.now().isoformat(),
                "source": source_tag,
                "data": {schema[i]: parts[i] for i in range(len(schema))}
            }
            # Capture extra info (like User Name or Window Title)
            if len(parts) > len(schema):
                normalized_data["data"]["extra_info"] = " ".join(parts[len(schema):])
            return normalized_data
        return None

# --- PHASE 1: REAL-TIME MONITORING ---
def setup_environment():
    RAW_LOG_DIR.mkdir(parents=True, exist_ok=True)
    for path in LOG_SOURCES.values():
        if not path.exists():
            path.touch()

def tail_file(source_name, file_path, ingestor, exporter):
    """Watches file, normalizes new lines, and exports to JSON."""
    print(f"[*] Thread started: Monitoring {source_name}")
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            
            clean_line = line.strip()
            
            # 1. Print to console for visibility
            if "--- [" in clean_line:
                print(f"\n[!] {source_name} SNAPSHOT AT: {clean_line.strip(' -[]')}")
            
            # 2. Normalize and Export
            normalized = ingestor.normalize(source_name, clean_line)
            if normalized:
                exporter.write_log(normalized)
                print(f"    [+] Logged {source_name} entry to JSON")

if __name__ == "__main__":
    setup_environment()
    
    # Initialize our components
    ingestor = UniversalIngestionLayer()
    exporter = JSONExporter(OUTPUT_FILE)

    print("="*60)
    print("LIVE FORENSIC ANALYSER: INGESTION & NORMALIZATION")
    print(f"Saving to: {OUTPUT_FILE}")
    print("="*60)
    
    try:
        threads = []
        for name, path in LOG_SOURCES.items():
            t = threading.Thread(
                target=tail_file, 
                args=(name, path, ingestor, exporter), 
                daemon=True
            )
            t.start()
            threads.append(t)
            
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[*] Analysis stopped. Data preserved in JSON.")