import joblib
import os
import numpy as np
from lime.lime_text import LimeTextExplainer

MODEL_PATH = "models/network_app/svm_v1.pkl"
VEC_PATH = "models/network_app/tfidf_v1.pkl"

def run_webapp_inference():
    print("[SYSTEM] Booting L7 Web/App Engine...")
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VEC_PATH):
        print("[ERROR] Artifacts missing. Run train_webapp_specialist.py first.")
        return

    svm_mdl = joblib.load(MODEL_PATH)
    vec = joblib.load(VEC_PATH)
    print("[SYSTEM] Web/App Specialist and TF-IDF Vectorizer loaded successfully.\n")

    # THE FIX: Drop char_level=True. Use Regex to split by spaces.
    # This forces LIME to evaluate whole syntax chunks like "HTTP/1.1" or "1=1--"
    explainer = LimeTextExplainer(class_names=['Anomaly', 'Normal'], split_expression=r'\s+')

    def svm_predict_proba(texts):
        X_vec = vec.transform(texts)
        distances = svm_mdl.decision_function(X_vec)
        prob_normal = 1 / (1 + np.exp(-distances))
        prob_anomaly = 1 - prob_normal
        return np.vstack([prob_anomaly, prob_normal]).T

    live_stream = [
        "workerEnv.init() ok /etc/httpd/conf/workers2.properties",
        "GET /login.php?user=admin' OR 1=1-- HTTP/1.1 403",
        "GET /../../../../etc/passwd HTTP/1.1 404"
    ]

    print("[SYSTEM] Monitoring Application Layer traffic...\n")

    for payload in live_stream:
        X_single = vec.transform([payload])
        prediction = svm_mdl.predict(X_single)[0]

        if prediction == 1:
            print(f"[NORMAL] Payload: {payload}")
        else:
            print(f"\n[!!!] 🚨 L7 ATTACK DETECTED 🚨 [!!!]")
            print(f"Payload: {payload}")
            
            exp = explainer.explain_instance(
                payload, 
                svm_predict_proba, 
                num_features=4, 
                labels=[0] 
            )
            
            print("--- Forensic Context (LIME) ---")
            top_features = exp.as_list(label=0)
            for text_chunk, score in top_features:
                if score > 0:
                    print(f" > Suspicious Syntax Found: '{text_chunk}' (Weight: +{score:.3f})")
            print("---------------------------------\n")

if __name__ == "__main__":
    run_webapp_inference()
