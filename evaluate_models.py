import os
import json
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from models.fusion.master_engine import ChakshuFusion
from models.fusion.master_engine import AssetLoader

def extract_ground_truth(log_frame, dataset_name):
    if "L3_L4" in log_frame.get("act", ""):
        payload_value = log_frame.get("payload", "").upper()
        if "BENIGN" in payload_value:
            return 0
        return 1

    if "DDos" in dataset_name or "attack" in dataset_name.lower():
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

    print("Initializing Model Evaluation...")

    for file_name in dataset_files:
        file_path = os.path.join(dataset_directory, file_name)
        if not os.path.exists(file_path):
            continue

        with open(file_path, "r") as input_file:
            log_frames = json.load(input_file)

        for log_frame in log_frames:
            true_anomaly = extract_ground_truth(log_frame, file_name)
            assigned_tag = log_frame.get("act", "L3_L4")

            if "HOST" in assigned_tag:
                detected_os = fusion_engine.check_os(log_frame.get("payload", ""))
                if detected_os: 
                    assigned_tag = detected_os

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

    print("\n--- Specialist Models Performance ---")
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
