import os
import json
import time
from datetime import datetime
from models.fusion.master_engine import ChakshuFusion

def export_alerts(history, out_file):
    """Helper function to dump the current engine history to JSON."""
    export_history = []
    for alert in history:
        alert_copy = alert.copy()
        # Convert datetime objects to strings so JSON doesn't crash
        if isinstance(alert_copy["ts"], datetime):
            alert_copy["ts"] = alert_copy["ts"].isoformat()
        export_history.append(alert_copy)

    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(export_history, f, indent=4)

def run_full_pipeline():
    processed_dir = "data/processed"
    out_file = "data/processed/alerts.json"
    
    # The complete roster of datasets mapped to our specialists
    datasets = [
        "Monday-WorkingHours.pcap_ISCX.json", # Network (L3/L4)
        "Apache_2k.log_structured.json",      # Web App (WEB_APP)
        "OpenSSH_2k.log_structured.json",     # Linux Gateway (AUTH_LINUX)
        "LANL_WLS_2k.json",                   # Windows Gateway (AUTH_WINDOWS)
        "Linux_2k.log_structured.json",       # Linux OS (HOST_LIN)
        "Windows_2k.log_structured.json"      # Windows OS (HOST_WIN)
    ]
    
    # Initialize the brain once
    engine = ChakshuFusion()
    total_records = 0
    
    # --- Real-Time Push Trackers ---
    logs_processed_since_last_push = 0
    last_push_time = time.time()
    
    print("Initializing Chakshu Fusion Engine (Streaming Mode)...")

    for ds in datasets:
        target_file = os.path.join(processed_dir, ds)
        
        if not os.path.exists(target_file):
            print(f"[!] Warning: {target_file} not found. Skipping...")
            continue
            
        print(f"\n--- Ingesting {ds} ---")
        
        with open(target_file, "r") as f:
            try:
                logs = json.load(f)
            except Exception as e:
                print(f"[ERROR] Could not read {ds}: {e}")
                continue
            
        file_anomalies = 0
        
        for log in logs:
            total_records += 1
            logs_processed_since_last_push += 1
            
            alert = engine.process_frame(log)
            if alert and alert["is_anomaly"]:
                file_anomalies += 1
                # Print a clean, matrix-style scrolling output
                print(f"[{alert['tag']}] ALERT (Score: {alert['score']}) | IP/ID: {alert['src_ip']}")
                print(f" > Evidence: {alert['forensics']}")
                print(f" > Payload: {alert['payload'][:50]}...")
                print("-" * 60)
            
            # --- The Streaming Trigger Condition ---
            current_time = time.time()
            if logs_processed_since_last_push >= 30 or (current_time - last_push_time) >= 20:
                export_alerts(engine.history, out_file)
                logs_processed_since_last_push = 0
                last_push_time = current_time
                
        print(f"[+] Finished {ds} | Anomalies detected: {file_anomalies}")

    # Final push to catch any remaining alerts at the end of the run
    export_alerts(engine.history, out_file)

    print(f"\n==================================================")
    print(f"--- Recon Complete. Processed {total_records} total records. ---")
    print(f"Total Anomalies Found Across All Layers: {len(engine.history)}")
    print(f"==================================================\n")
    print(f"[*] The Streamlit Dashboard is ready for consumption.")

if __name__ == "__main__":
    run_full_pipeline()
