import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import joblib
import os
import shap

INPUT_JSON = "data/processed/Monday-WorkingHours.pcap_ISCX.json"
OUTPUT_MODEL = "models/network_flow/iforest_v1.pkl"
OUTPUT_SCALER = "models/network_flow/scaler_v1.pkl"
OUTPUT_EXPLAINER = "models/network_flow/shap_explainer_v1.pkl"

def train_network_model():
    if not os.path.exists(INPUT_JSON):
        print(f"Error: {INPUT_JSON} not found. Ensure you run init_parsers.py first.")
        return

    print("Loading processed network flow data...")
    df = pd.read_json(INPUT_JSON)

    features = ['dst_pt', 'b_in', 'b_out']
    X = df[features]

    print("Scaling numerical features with outlier-resistant RobustScaler...")
    # RobustScaler uses IQR, making it immune to the extreme values of DDoS attacks
    scaler = RobustScaler()
    X_scaled_array = scaler.fit_transform(X)
    X_scaled = pd.DataFrame(X_scaled_array, columns=features)

    print(f"Matrix built. Training Isolation Forest on {len(X_scaled)} records...")
    
    # We can keep contamination at 0.01 since the scaler is now handling the distribution correctly
    model = IsolationForest(n_estimators=100, contamination=0.007, random_state=42)
    model.fit(X_scaled)

    joblib.dump(scaler, OUTPUT_SCALER)
    print(f"Success! Scaler Artifact deployed to: {OUTPUT_SCALER}")
    joblib.dump(model, OUTPUT_MODEL)
    print(f"Success! Model Artifact deployed to: {OUTPUT_MODEL}")

    print("Initializing SHAP TreeExplainer...")
    explainer = shap.TreeExplainer(model)
    
    joblib.dump(explainer, OUTPUT_EXPLAINER)
    print(f"Success! XAI Explainer deployed to: {OUTPUT_EXPLAINER}")

    print("\nValidating XAI on a detected anomaly...")
    df['anomaly'] = model.predict(X_scaled)
    anomalies = X_scaled[df['anomaly'] == -1]
    
    if not anomalies.empty:
        sample_anomaly = anomalies.iloc[[0]]
        shap_values = explainer.shap_values(sample_anomaly)
        print("--- SHAP context for sample anomaly ---")
        print(f"Feature Map: {features}")
        print(f"Raw Values:  {X.iloc[sample_anomaly.index[0]].values}")
        print(f"Scaled Values: {sample_anomaly.values[0]}")
        print(f"SHAP Scores: {shap_values[0]}")
        print("---------------------------------------")
        print("Positive SHAP scores pushed the event toward 'Anomaly'.")
        print("Negative SHAP scores pushed the event toward 'Normal'.")

if __name__ == "__main__":
    train_network_model()
