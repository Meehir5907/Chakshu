import os
import json
import time
from datetime import datetime
from models.fusion.master_engine import ChakshuFusion

def export_alerts(threat_history, output_filepath):
    export_list = []
    for threat_alert in threat_history:
        alert_copy = threat_alert.copy()
        if isinstance(alert_copy["ts"], datetime):
            alert_copy["ts"] = alert_copy["ts"].isoformat()
        export_list.append(alert_copy)

    os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
    with open(output_filepath, "w") as out_file:
        json.dump(export_list, out_file, indent=4)

def run_full_pipeline():
    processed_directory = "data/processed"
    dashboard_filepath = "data/processed/alerts.json"
    
    dataset_files = [
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.json",
        "Apache_2k.log_structured.json",      
        "OpenSSH_2k.log_structured.json",     
        "LANL_WLS_2k.json",                   
        "Linux_2k.log_structured.json",       
        "Windows_2k.log_structured.json"      
    ]
    
    fusion_engine = ChakshuFusion()
    total_scanned_records = 0
    
    logs_since_push = 0
    last_push_timestamp = time.time()
    
    print("Initializing Chakshu Fusion Engine (Silent Streaming Mode)...")

    for dataset_name in dataset_files:
        target_filepath = os.path.join(processed_directory, dataset_name)
        
        if not os.path.exists(target_filepath):
            continue
            
        with open(target_filepath, "r") as input_file:
            try:
                log_frames = json.load(input_file)
            except Exception as error_msg:
                continue
            
        for idx, single_log_frame in enumerate(log_frames):
            # Targeted scan logic for Friday DDoS file
            if "Friday-WorkingHours-Afternoon-DDos" in dataset_name:
                if 10 <= idx < 1884:
                    continue  # Jump to block 1884
                if idx >= 1884 + 20:
                    break  # Stop scanning after 20 entries from block 1884
            
            total_scanned_records += 1
            logs_since_push += 1
            
            threat_alert = fusion_engine.process_frame(single_log_frame)
            
            if threat_alert and threat_alert["is_anomaly"]:
                print(f"[{threat_alert['tag']}] ALERT (Score: {threat_alert['score']}) | IP/ID: {threat_alert['src_ip']}")
                print(f" > Evidence: {threat_alert['forensics']}")
                print(f" > Payload: {threat_alert['payload'][:50]}...")
                print("-" * 60)
            
            current_timestamp = time.time()
            if logs_since_push >= 30 or (current_timestamp - last_push_timestamp) >= 20:
                export_alerts(fusion_engine.history, dashboard_filepath)
                logs_since_push = 0
                last_push_timestamp = current_timestamp

    export_alerts(fusion_engine.all_alerts, dashboard_filepath)

    print(f"\n==================================================")
    print(f"--- Recon Complete. Processed {total_scanned_records} total records. ---")
    print(f"Total Anomalies Found: {len(fusion_engine.all_alerts)}")
    print(f"==================================================\n")

if __name__ == "__main__":
    run_full_pipeline()
