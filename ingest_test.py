import json
import os
from models.fusion.master_engine import ChakshuFusion

def run_mass_recon():
    engine = ChakshuFusion()
    processed_dir = "data/processed"
    
    target_file = os.path.join(processed_dir, "Windows_2k.log_structured.json")
    
    if not os.path.exists(target_file):
        print(f"[!] Target file {target_file} not found.")
        return

    with open(target_file, 'r') as f:
        logs = json.load(f)

    print(f"--- Processing {len(logs)} records from {target_file} ---\n")
    
    anomalies_found = 0
    for log in logs:
        # The engine handles timestamp/OS detection automatically
        res = engine.process_frame(log)
        
        if res and res["is_anomaly"]:
            anomalies_found += 1
            print(f"[{res['tag']}] ALERT (Score: {res['score']}) | IP: {res['src_ip']}")
            print(f" > Evidence: {res['forensics']}")
            print(f" > Payload: {res['payload']}\n")

    print(f"--- Recon Complete. Found {anomalies_found} anomalies. ---")

if __name__ == "__main__":
    run_mass_recon()
