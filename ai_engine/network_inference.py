import joblib
import json
import pandas as pd
import time
import os

# Paths to your deployed artifacts and the simulated live stream
MODEL_PATH = "models/network_flow/iforest_v1.pkl"
EXPLAINER_PATH = "models/network_flow/shap_explainer_v1.pkl"
LIVE_STREAM_SIM = "data/processed/Monday-WorkingHours.pcap_ISCX.json"

def run_inference_engine():
    print("[SYSTEM] Booting AI Engine...")
    if not os.path.exists(MODEL_PATH) or not os.path.exists(EXPLAINER_PATH):
        print("[ERROR] Artifacts missing. Run scripts/train_network_flow.py first.")
        return

    # 1. Load the artifacts into memory (happens only once at boot)
    model = joblib.load(MODEL_PATH)
    explainer = joblib.load(EXPLAINER_PATH)
    print("[SYSTEM] Network Specialist and SHAP Explainer loaded successfully.\n")

    # 2. Simulate connecting to the ingestion layer stream
    print("[SYSTEM] Connecting to ingestion log stream...\n")
    with open(LIVE_STREAM_SIM, 'r') as f:
        logs = json.load(f)


    # --- INJECTION START ---
    # Create a synthetic volumetric attack (e.g., Data Exfiltration or DDoS)
    malicious_log = {
        "ts": "2026-04-16T00:38:00Z",
        "src_ip": "10.0.0.99",
        "dst_ip": "192.168.1.5",
        "src_pt": 54321,
        "dst_pt": 4444,        # Highly suspicious destination port (default Metasploit)
        "proto": "TCP",
        "evt_id": 1000,
        "act": "BENIGN",
        "b_in": 15000000,      # 15MB incoming in a single flow (Massive anomaly)
        "b_out": 0             # Zero bytes out (Asymmetric flow)
    }
    
    # Inject the poison pill into the 5th position of the stream
    logs.insert(5, malicious_log)
    # --- INJECTION END ---

    # 3. Process logs in real-time
    features = ['dst_pt', 'b_in', 'b_out']
    
    # We will just process the first 20 logs for this test
    for i, log in enumerate(logs[:20]):
        # Time delay to simulate real-time network traffic arrival
        time.sleep(0.5) 
        
        # Extract the relevant features for the network specialist
        df_current = pd.DataFrame([log])[features]
        
        # Score the log
        prediction = model.predict(df_current)[0]

        if prediction == 1:
            print(f"[{log['ts']}] [NORMAL] Flow to {log['dst_ip']}:{log['dst_pt']}")
        else:
            print(f"\n[!!!] 🚨 ANOMALY DETECTED 🚨 [!!!]")
            print(f"Timestamp: {log['ts']} | Target: {log['dst_ip']}:{log['dst_pt']}")
            
            # Instantly calculate Explainable AI metrics
            shap_vals = explainer.shap_values(df_current)
            
            print("--- Automated Forensic Context (SHAP) ---")
            for feature_name, value, shap_score in zip(features, df_current.values[0], shap_vals[0]):
                impact = "Pushed toward Normal" if shap_score > 0 else "Pushed toward Anomaly"
                print(f" > {feature_name}: {value} (Score: {shap_score:.3f} -> {impact})")
            print("-----------------------------------------\n")

if __name__ == "__main__":
    run_inference_engine()
