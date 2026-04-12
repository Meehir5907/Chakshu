import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os
import shap

# Define absolute or relative paths based on project root
INPUT_JSON = "data/processed/Monday-WorkingHours.pcap_ISCX.json"
OUTPUT_MODEL = "models/network_flow/iforest_v1.pkl"
OUTPUT_EXPLAINER = "models/network_flow/shap_explainer_v1.pkl"

def train_network_model():
    if not os.path.exists(INPUT_JSON):
        print(f"Error: {INPUT_JSON} not found. Ensure you run init_parsers.py first.")
        return

    print("Loading processed network flow data...")
    df = pd.read_json(INPUT_JSON)

    # The Network Flow Specialist only cares about ports and volumetric byte data
    features = ['dst_pt', 'b_in', 'b_out']
    X = df[features]

    print(f"Matrix built. Training Isolation Forest on {len(X)} records...")
    
    # contamination=0.01 assumes 1% of the training dataset is anomalous
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X)

    # Serialize and store the trained matrix in the artifacts folder
    joblib.dump(model, OUTPUT_MODEL)
    print(f"Success! Model Artifact deployed to: {OUTPUT_MODEL}")

    print("Initializing SHAP TreeExplainer...")
    # Create the SHAP explainer tailored for this specific Isolation Forest
    explainer = shap.TreeExplainer(model)
    
    # Save the explainer so the live dashboard doesn't have to recompute baselines
    joblib.dump(explainer, OUTPUT_EXPLAINER)
    print(f"Success! XAI Explainer deployed to: {OUTPUT_EXPLAINER}")

    # Validation Test: Grab an anomaly and prove the explainer works
    print("\nValidating XAI on a detected anomaly...")
    df['anomaly'] = model.predict(X)
    anomalies = X[df['anomaly'] == -1]
    
    if not anomalies.empty:
        sample_anomaly = anomalies.iloc[[0]]
        shap_values = explainer.shap_values(sample_anomaly)
        print("--- SHAP context for sample anomaly ---")
        print(f"Feature Map: {features}")
        print(f"Raw Values:  {sample_anomaly.values[0]}")
        print(f"SHAP Scores: {shap_values[0]}")
        print("---------------------------------------")
        print("Positive SHAP scores pushed the event toward 'Anomaly'.")
        print("Negative SHAP scores pushed the event toward 'Normal'.")

if __name__ == "__main__":
    train_network_model()
