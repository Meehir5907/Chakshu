import joblib
import os
import numpy as np
from lime.lime_text import LimeTextExplainer

MODEL_PATH = "models/host_linux_mac/svm_v1.pkl"
VEC_PATH = "models/host_linux_mac/tfidf_v1.pkl"

def run_linux_inference():
    print("[SYSTEM] Booting Linux OS Host Engine...")
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VEC_PATH):
        print("[ERROR] Artifacts missing. Run train_host_linux.py first.")
        return

    svm_mdl = joblib.load(MODEL_PATH)
    vec = joblib.load(VEC_PATH)
    print("[SYSTEM] Linux Host Specialist and TF-IDF Vectorizer loaded successfully.\n")

    # Using word-level splitting (spaces) so LIME evaluates whole commands/paths
    explainer = LimeTextExplainer(class_names=['Anomaly', 'Normal'], split_expression=r'\s+')

    def svm_predict_proba(texts):
        X_vec = vec.transform(texts)
        distances = svm_mdl.decision_function(X_vec)
        prob_normal = 1 / (1 + np.exp(-distances))
        prob_anomaly = 1 - prob_normal
        return np.vstack([prob_anomaly, prob_normal]).T

    # --- SIMULATE LIVE OS INGESTION ---
    live_stream = [
        "systemd[1]: Started Process Core Dump (PID 1234/UID 0).",
        "meehir : TTY=pts/1 ; PWD=/home/meehir/Dev/ResearchProjects/Chakshu ; USER=root ; COMMAND=/tmp/miner_v2.elf",
        "pam_unix(sudo:session): session opened for user root by meehir(uid=1000)",
        "useradd[8921]: new user: name=ghost, UID=1005, GID=1005, home=/home/ghost, shell=/bin/bash"
    ]

    print("[SYSTEM] Monitoring local OS execution states...\n")

    for payload in live_stream:
        X_single = vec.transform([payload])
        prediction = svm_mdl.predict(X_single)[0]

        if prediction == 1:
            print(f"[NORMAL] OS Event: {payload}")
        else:
            print(f"\n[!!!] 🚨 HOST COMPROMISE DETECTED 🚨 [!!!]")
            print(f"OS Event: {payload}")
            
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
                    print(f" > Suspicious Command/Path: '{text_chunk}' (Weight: +{score:.3f})")
            print("---------------------------------\n")

if __name__ == "__main__":
    run_linux_inference()
