import joblib
import os
import numpy as np
from lime.lime_text import LimeTextExplainer

MODEL_PATH = "models/host_windows/svm_v1.pkl"
VEC_PATH = "models/host_windows/tfidf_v1.pkl"

def run_windows_inference():
    print("[SYSTEM] Booting Windows OS Host Engine...")
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VEC_PATH):
        print("[ERROR] Artifacts missing. Run train_host_windows.py first.")
        return

    svm_mdl = joblib.load(MODEL_PATH)
    vec = joblib.load(VEC_PATH)
    print("[SYSTEM] Windows Host Specialist loaded successfully.\n")

    explainer = LimeTextExplainer(class_names=['Anomaly', 'Normal'], split_expression=r'\s+')

    def svm_predict_proba(texts):
        X_vec = vec.transform(texts)
        distances = svm_mdl.decision_function(X_vec)
        prob_normal = 1 / (1 + np.exp(-distances))
        prob_anomaly = 1 - prob_normal
        return np.vstack([prob_anomaly, prob_normal]).T

    live_stream = [
        "A new process has been created. Creator Process ID: 0x4a8. Process Name: C:\\Windows\\System32\\svchost.exe",
        "A new process has been created. Creator Process ID: 0x1f4. Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine: powershell.exe -nop -w hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA"
    ]

    print("[SYSTEM] Monitoring Windows Event Logs...\n")

    for payload in live_stream:
        X_single = vec.transform([payload])
        prediction = svm_mdl.predict(X_single)[0]

        if prediction == 1:
            print(f"[NORMAL] OS Event: {payload[:80]}...")
        else:
            print(f"\n[!!!] 🚨 WINDOWS ENDPOINT COMPROMISE DETECTED 🚨 [!!!]")
            print(f"OS Event: {payload[:80]}...")
            
            exp = explainer.explain_instance(payload, svm_predict_proba, num_features=4, labels=[0], num_samples=10000)
            
            print("--- Forensic Context (LIME) ---")
            for text_chunk, score in exp.as_list(label=0):
                if score > 0:
                    print(f" > Suspicious Context: '{text_chunk}' (Weight: +{score:.3f})")
            print("---------------------------------\n")

if __name__ == "__main__":
    run_windows_inference()
