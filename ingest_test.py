import os
import json
from datetime import datetime
from models.fusion.master_engine import ChakshuFusion

def run_full_pipeline():
    processed_dir = "data/processed"
    
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
    
    print("Initializing Chakshu Fusion Engine (Full Spectrum Scan)...")

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
            
        total_records += len(logs)
        file_anomalies = 0
        
        for log in logs:
            alert = engine.process_frame(log)
            if alert and alert["is_anomaly"]:
                file_anomalies += 1
                # Print a clean, matrix-style scrolling output
                print(f"[{alert['tag']}] ALERT (Score: {alert['score']}) | IP/ID: {alert['src_ip']}")
                print(f" > Evidence: {alert['forensics']}")
                print(f" > Payload: {alert['payload'][:50]}...")
                print("-" * 60)
                
        print(f"[+] Finished {ds} | Anomalies detected: {file_anomalies}")

    print(f"\n==================================================")
    print(f"--- Recon Complete. Processed {total_records} total records. ---")
    print(f"Total Anomalies Found Across All Layers: {len(engine.history)}")
    print(f"==================================================\n")

    # Export the aggregated threat intelligence to JSON for Streamlit
    out_file = "data/processed/alerts.json"
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    
    export_history = []
    for alert in engine.history:
        alert_copy = alert.copy()
        # Convert datetime objects to strings so JSON doesn't crash
        alert_copy["ts"] = alert_copy["ts"].isoformat()
        export_history.append(alert_copy)

    with open(out_file, "w") as f:
        json.dump(export_history, f, indent=4)
        
    print(f"[+] Deployed {len(export_history)} cross-layer alerts to {out_file}.")
    print(f"[*] The Streamlit Dashboard is ready for consumption.")

if __name__ == "__main__":
    run_full_pipeline()
