import json
import time
import os
from pathlib import Path

# Paths
BASE_DIR = Path(r"F:\CODING AND AI\Codings file VS code\forensics_lab")
INPUT_FILE = BASE_DIR / "logs" / "normalized_logs.json"
FILTERED_FILE = BASE_DIR / "logs" / "filtered_logs.json"

class ForensicSanitizer:
    def __init__(self):
        self.state_cache = {}
        # Step 1: Clean the file immediately on startup
        self.cleanup_existing_file()

    def generate_id(self, entry):
        """Creates a unique identity based on source and key data points."""
        source = entry.get("source", "UNKNOWN")
        data = entry.get("data", {})
        if source == "OS":
            return f"OS:{data.get('service_name')}"
        elif source == "NETWORK":
            return f"NET:{data.get('local_address')}-{data.get('pid')}"
        elif source == "APP":
            return f"APP:{data.get('image_name')}-{data.get('pid')}"
        return f"GENERIC:{hash(str(data))}"

    def cleanup_existing_file(self):
        """
        Reads the filtered file. If duplicates exist, it DELETES 
        them by rewriting only the unique lines.
        """
        if not FILTERED_FILE.exists():
            return

        print(f"[*] Checking {FILTERED_FILE.name} for existing duplicates...")
        unique_entries = []
        seen_ids = set()

        with open(FILTERED_FILE, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    uid = self.generate_id(entry)
                    # Only keep the line if we haven't seen this ID/State combo yet
                    state_id = f"{uid}:{hash(str(entry.get('data')))}"
                    
                    if state_id not in seen_ids:
                        unique_entries.append(entry)
                        seen_ids.add(state_id)
                        self.state_cache[uid] = entry.get("data")
                except json.JSONDecodeError:
                    continue

        # If we found duplicates, rewrite the file (deleting the bad lines)
        if len(unique_entries) < sum(1 for _ in open(FILTERED_FILE, "r")):
            print(f"[!] Duplicates found! Sanitizing file...")
            with open(FILTERED_FILE, "w") as f:
                for entry in unique_entries:
                    f.write(json.dumps(entry) + "\n")
            print(f"[+] File sanitized. Clean version saved.")
        else:
            print(f"[+] No existing duplicates found in filtered file.")

    def process_live_line(self, line):
        """Standard live check: prevents new duplicates from entering."""
        try:
            entry = json.loads(line)
            uid = self.generate_id(entry)
            current_data = entry.get("data")

            if uid not in self.state_cache or self.state_cache[uid] != current_data:
                self.state_cache[uid] = current_data
                return entry
            return None
        except json.JSONDecodeError:
            return None

def start_engine():
    sanitizer = ForensicSanitizer()
    
    print(f"[*] Monitoring for new logs...")
    
    with open(INPUT_FILE, "r") as f:
        # Move to end if you only want to filter data from this second forward
        # f.seek(0, os.SEEK_END) 
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            clean_entry = sanitizer.process_live_line(line)
            if clean_entry:
                with open(FILTERED_FILE, "a") as out:
                    out.write(json.dumps(clean_entry) + "\n")
                print(f"[SAVED] {clean_entry['source']} update detected.")

if __name__ == "__main__":
    try:
        start_engine()
    except KeyboardInterrupt:
        print("\n[!] Engine stopped.")